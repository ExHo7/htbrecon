from __future__ import annotations

import asyncio
import json
import re
from dataclasses import dataclass

from htbrecon import llm
from htbrecon.console import logger, print_finding, print_info, print_warning
from htbrecon.executor import run
from htbrecon.models import CveInfo, ReconContext, VulnxResult

# Pure metadata/HTTP plugins — not real products to search CVEs for
_SKIP_PLUGINS = frozenset({
    "HTTPServer", "X-Powered-By", "X-Frame-Options", "Strict-Transport-Security",
    "X-Content-Type-Options", "Content-Security-Policy", "X-XSS-Protection",
    "Via-Proxy", "RedirectLocation", "IP", "Country", "Title", "Meta-Author",
    "Meta-Generator", "Email", "Script", "Frame", "Cookies", "HTML5",
    "Bootstrap", "JQuery", "jQuery", "UncommonHeaders", "Open-Graph-Protocol",
    "OpenGraph", "Facebook", "Twitter",
})

# Minimal static fallback map (used when AI is unavailable)
_VENDOR_MAP: dict[str, tuple[str, str]] = {
    "Apache": ("apache", "http_server"),
    "Nginx": ("nginx", "nginx"),
    "nginx": ("nginx", "nginx"),
    "IIS": ("microsoft", "iis"),
    "WordPress": ("wordpress", "wordpress"),
    "Joomla": ("joomla", "joomla"),
    "Drupal": ("drupal", "drupal"),
    "PHP": ("php", "php"),
    "OpenSSL": ("openssl", "openssl"),
    "OpenSSH": ("openbsd", "openssh"),
    "Tomcat": ("apache", "tomcat"),
    "Jenkins": ("jenkins", "jenkins"),
    "GitLab": ("gitlab", "gitlab"),
    "Grafana": ("grafana", "grafana"),
    "Kibana": ("elastic", "kibana"),
    "Elasticsearch": ("elastic", "elasticsearch"),
    "Spring": ("vmware", "spring_framework"),
    "Rails": ("rubyonrails", "ruby_on_rails"),
    "Django": ("djangoproject", "django"),
    "Flask": ("palletsprojects", "flask"),
    "FastAPI": ("tiangolo", "fastapi"),
    "Express": ("expressjs", "express"),
    "Laravel": ("laravel", "laravel"),
    "Symfony": ("sensiolabs", "symfony"),
    "Magento": ("magento", "magento"),
    "SharePoint": ("microsoft", "sharepoint_server"),
    "Exchange": ("microsoft", "exchange_server"),
    "OWA": ("microsoft", "exchange_server"),
    "Flowise": ("flowiseai", "flowise"),
    "FlowiseAI": ("flowiseai", "flowise"),
    "Strapi": ("strapi", "strapi"),
    "Directus": ("directus", "directus"),
    "Hasura": ("hasura", "graphql_engine"),
    "Keycloak": ("redhat", "keycloak"),
    "Vault": ("hashicorp", "vault"),
    "Consul": ("hashicorp", "consul"),
    "phpMyAdmin": ("phpmyadmin", "phpmyadmin"),
    "Webmin": ("webmin", "webmin"),
    "cPanel": ("cpanel", "cpanel"),
    "Plesk": ("plesk", "plesk"),
}

_NMAP_VERSION_RE = re.compile(r"^([\w\-]+(?:\s[\w\-]+)?)\s+(\d+[\d.]+)", re.IGNORECASE)
# Artefacts nmap à ignorer (état de port, protocoles, etc.).
# NB: "microsoft"/"generic" volontairement absents — ils bloquaient des vrais
# produits (Microsoft IIS, …). Le CPE structuré est désormais prioritaire.
_NMAP_SKIP_NAMES = frozenset({
    "syn-ack", "tcpwrapped", "filtered", "closed", "open",
})


def _cpe_to_term(cpe: str) -> SearchTerm | None:
    """Parse an nmap CPE (2.2 ``cpe:/a:...`` or 2.3 ``cpe:2.3:a:...``) into a
    SearchTerm. Returns None for non application/OS CPEs or malformed input."""
    parts = cpe.split(":")
    if cpe.startswith("cpe:2.3:"):
        # cpe:2.3:<part>:<vendor>:<product>:<version>:...
        if len(parts) < 5:
            return None
        kind, vendor, product = parts[2], parts[3], parts[4]
        version = parts[5] if len(parts) > 5 else ""
    else:
        # cpe:/<part>:<vendor>:<product>:<version>
        if len(parts) < 4:
            return None
        kind = parts[1].lstrip("/")
        vendor, product = parts[2], parts[3]
        version = parts[4] if len(parts) > 4 else ""
    if kind not in ("a", "o"):
        return None
    vendor, product = vendor.strip().lower(), product.strip().lower()
    if not vendor or not product:
        return None
    if version in ("*", "-", ""):
        version = ""
    return SearchTerm(vendor=vendor, product=product, version=version)


@dataclass
class SearchTerm:
    """A structured vendor/product search term for vulnx."""
    vendor: str
    product: str
    version: str = ""

    def __str__(self) -> str:
        if self.version:
            return f"{self.vendor}/{self.product}@{self.version}"
        return f"{self.vendor}/{self.product}"


# ── Version-range applicability ────────────────────────────────────────────────
# vulnx exposes no structured version range (no versionStart/End, no
# vulnerable_cpe). The affected range lives in free text: the CVE ``description``
# (e.g. "Apache HTTP Server 2.4.17 through 2.4.67 ...") and ``remediation``
# (e.g. "Upgrade to a version later than 2.4.67"). These helpers parse the common
# phrasings deterministically; anything unparsable is left "unknown" and handed
# to the AI fallback (_ai_version_filter) rather than guessed.

# A dotted version token: requires at least one dot to avoid matching bare
# numbers like CWE ids or "HTTP/2". An optional trailing letter/build is kept.
_VER_TOKEN = r"\d+(?:\.\d+)+[a-z]?\d*"
_VER_RE = re.compile(_VER_TOKEN, re.IGNORECASE)

# "X through Y", "from X to Y", "X up to Y" — a bounded range (needs two tokens).
_RANGE_RE = re.compile(
    rf"({_VER_TOKEN})\s*(?:through|thru|to|up to|-|–|—)\s*({_VER_TOKEN})",
    re.IGNORECASE,
)
# Exclusive upper bound: affected if detected < Y.
_BEFORE_EXCL_RE = re.compile(
    rf"(?:before|prior to|earlier than|older than|up to but not including)\s+v?({_VER_TOKEN})",
    re.IGNORECASE,
)
# Inclusive upper bound: affected if detected <= Y.
_BEFORE_INCL_RE = re.compile(
    rf"(?:up to and including|up to|through)\s+v?({_VER_TOKEN})",
    re.IGNORECASE,
)
# "Y and earlier" / "Y and below": affected if detected <= Y.
_AND_EARLIER_RE = re.compile(
    rf"({_VER_TOKEN})\s+(?:and|or)\s+(?:earlier|prior|older|below|before)",
    re.IGNORECASE,
)
# Remediation fix bound: "fixed in Y" / "upgrade to Y" → affected if detected < Y.
_FIXED_RE = re.compile(
    rf"(?:later than|after version|fixed in|patched in|resolved in|"
    rf"update to(?: version| a version(?: later than)?)?|"
    rf"upgrade to(?: version| a version(?: later than)?)?)\s+v?({_VER_TOKEN})",
    re.IGNORECASE,
)


def _version_tuple(v: str) -> tuple[int, ...]:
    """Parse a version string into a comparable int tuple ("v2.4.41" → (2,4,41)).

    Stops at the first non-numeric segment; returns () when nothing parses.
    """
    v = v.strip().lstrip("vV")
    parts: list[int] = []
    for seg in v.split("."):
        m = re.match(r"\d+", seg)
        if not m:
            break
        parts.append(int(m.group()))
    return tuple(parts)


def _cmp_version(a: str, b: str) -> int:
    """Numeric version compare. Returns -1/0/1 (a<b / a==b / a>b)."""
    ta, tb = _version_tuple(a), _version_tuple(b)
    n = max(len(ta), len(tb))
    ta += (0,) * (n - len(ta))
    tb += (0,) * (n - len(tb))
    return (ta > tb) - (ta < tb)


def _extract_range_verdict(detected: str, description: str, remediation: str = "") -> str:
    """Decide whether ``detected`` falls in a CVE's affected range.

    Returns "in" (affected), "out" (not affected), or "unknown" (no parsable
    range). High precision is preferred: only confident "out" verdicts are used
    to drop a CVE downstream, so ambiguity stays "unknown".
    """
    if not detected or not _version_tuple(detected):
        return "unknown"
    desc = description or ""

    m = _RANGE_RE.search(desc)
    if m:
        lo, hi = m.group(1), m.group(2)
        in_range = _cmp_version(detected, lo) >= 0 and _cmp_version(detected, hi) <= 0
        return "in" if in_range else "out"

    m = _BEFORE_EXCL_RE.search(desc)
    if m:
        return "in" if _cmp_version(detected, m.group(1)) < 0 else "out"

    m = _BEFORE_INCL_RE.search(desc)
    if m:
        return "in" if _cmp_version(detected, m.group(1)) <= 0 else "out"

    m = _AND_EARLIER_RE.search(desc)
    if m:
        return "in" if _cmp_version(detected, m.group(1)) <= 0 else "out"

    m = _FIXED_RE.search(remediation or "")
    if m:
        return "in" if _cmp_version(detected, m.group(1)) < 0 else "out"

    # No bound keyword: if the exact detected version is named, treat as affected
    # (covers discrete "versions X, Y, Z are affected" lists).
    for tok in _VER_RE.finditer(desc):
        if _cmp_version(tok.group(0), detected) == 0:
            return "in"

    return "unknown"


# ── AI-based tech normalisation ────────────────────────────────────────────────

_AI_SYSTEM_PROMPT = """\
You are a security tool assistant. Your job is to normalize web technology fingerprints
into structured CPE-compatible (vendor, product, version) tuples for NVD/CVE lookup.

Rules:
- Return ONLY a JSON array, no prose, no markdown fences.
- Each item: {"vendor": "...", "product": "...", "version": "..."}
- version is "" if unknown.
- Skip pure metadata: HTML5, HTTP headers, IP addresses, page titles, social meta-tags,
  Open Graph, unrecognized strings, port states (syn-ack, tcpwrapped).
- Normalize vendor/product to lowercase, use underscores for spaces.
- Use NVD CPE conventions: e.g. nginx→nginx/nginx, PHP→php/php,
  Apache httpd→apache/http_server, OpenSSH→openbsd/openssh,
  FlowiseAI→flowiseai/flowise, WordPress→wordpress/wordpress.
- If a Meta-Author or plugin name clearly identifies a known product, include it.
- nmap_service_versions entries may be CPE strings (cpe:/a:vendor:product:version
  or cpe:2.3:a:vendor:product:version). These are authoritative — extract
  vendor/product/version directly from them.
- whatweb_raw is the raw WhatWeb output. Mine it for web-application names AND
  versions that the flattened plugin list loses (e.g. Server/X-Powered-By/
  X-Generator headers, CMS version banners, login-page footers). The specific
  web-app version is often the key target — extract it when present.
- Never invent CVEs or products you don't recognise — omit them instead."""


async def _normalize_with_ai(
    raw_technologies: list[str],
    nmap_versions: list[str],
    whatweb_raws: list[str] | None = None,
) -> list[SearchTerm] | None:
    """Use the active LLM to parse and normalize detected technologies.

    Returns None if no LLM provider is available or the call/parse fails.
    """
    payload = {
        "whatweb_plugins": raw_technologies,
        "nmap_service_versions": nmap_versions,
        "whatweb_raw": whatweb_raws or [],
    }
    user_msg = (
        "Normalize these detected technologies for NVD CVE lookup.\n"
        f"Input: {json.dumps(payload, ensure_ascii=False)}"
    )

    text = await llm.complete(
        system=_AI_SYSTEM_PROMPT, user=user_msg, tier="small",
        max_tokens=1024, json_mode=True,
    )
    if text is None:
        return None

    try:
        # Strip accidental markdown fences
        text = re.sub(r"```(?:json)?\s*", "", text).strip().rstrip("`").strip()
        data = json.loads(text)
        if isinstance(data, dict):
            if "product" in data or "vendor" in data:
                data = [data]  # a single term emitted as a bare object
            else:
                # Some local models wrap the array in an object — unwrap the first list.
                data = next((v for v in data.values() if isinstance(v, list)), [])
        terms: list[SearchTerm] = []
        for item in data:
            if not isinstance(item, dict):
                continue
            vendor = str(item.get("vendor", "")).strip().lower()
            product = str(item.get("product", "")).strip().lower()
            version = str(item.get("version", "")).strip()
            if vendor and product:
                terms.append(SearchTerm(vendor=vendor, product=product, version=version))
        return terms
    except Exception as exc:
        logger.debug("AI tech normalisation parse failed: %s", exc)
        return None


_AI_VERSION_SYSTEM_PROMPT = """\
You are a security analyst deciding whether a detected software version falls within
the versions affected by a CVE.

You receive a JSON array of items: {"cve_id", "version", "description", "remediation"}.
For each, decide if the detected "version" is affected by that CVE, using only the
affected-version information stated in the description/remediation text.

Rules:
- Return ONLY a JSON object mapping cve_id -> "in" | "out" | "unknown". No prose, no fences.
- "in"  = the detected version is within the affected range.
- "out" = the detected version is explicitly NOT affected (e.g. it is at or above the fixed version).
- "unknown" = the text does not state enough to decide. When in doubt, use "unknown" — never guess.
- Compare versions numerically (2.4.9 < 2.4.41 < 2.4.67), not lexically.
- Never invent versions or CVEs."""


async def _ai_version_filter(
    items: list[tuple[str, str, str, str]],
) -> dict[str, str]:
    """Resolve version applicability for the residual "unknown" CVEs via the LLM.

    ``items`` is a list of (cve_id, detected_version, description, remediation).
    Returns a cve_id -> "in"/"out"/"unknown" map. Returns ``{}`` (leaving every
    item "unknown") when no LLM provider is available or it fails — never raises.
    """
    if not items:
        return {}

    payload = [
        {
            "cve_id": cve_id,
            "version": version,
            "description": (description or "")[:400],
            "remediation": (remediation or "")[:200],
        }
        for cve_id, version, description, remediation in items
    ]
    user_msg = (
        "Decide version applicability for each CVE below.\n"
        f"Input: {json.dumps(payload, ensure_ascii=False)}"
    )

    text = await llm.complete(
        system=_AI_VERSION_SYSTEM_PROMPT, user=user_msg, tier="small",
        max_tokens=1024, json_mode=True,
    )
    if text is None:
        return {}

    try:
        text = re.sub(r"```(?:json)?\s*", "", text).strip().rstrip("`").strip()
        data = json.loads(text)
        if not isinstance(data, dict):
            return {}
        verdicts: dict[str, str] = {}
        for cve_id, verdict in data.items():
            verdict = str(verdict).strip().lower()
            if verdict in ("in", "out", "unknown"):
                verdicts[cve_id] = verdict
        return verdicts
    except Exception as exc:
        logger.debug("AI version filter parse failed: %s", exc)
        return {}


# ── Static fallback extractors ─────────────────────────────────────────────────

def _extract_from_whatweb_static(ctx: ReconContext) -> list[SearchTerm]:
    """Static fallback: parse WhatWeb results using _VENDOR_MAP."""
    terms: list[SearchTerm] = []
    for wwresult in ctx.whatweb:
        for tech in wwresult.technologies:
            tech = tech.strip()
            # Strip multi-line artefacts: take only the part before any newline
            tech = tech.splitlines()[0].strip()

            if "[" in tech:
                plugin = tech[:tech.index("[")].strip()
                value = tech[tech.index("[") + 1:tech.rindex("]")].strip() if "]" in tech else ""
            else:
                plugin = tech
                value = ""

            if plugin in _SKIP_PLUGINS:
                continue

            if plugin in _VENDOR_MAP:
                vendor, product = _VENDOR_MAP[plugin]
            else:
                vendor = plugin.lower()
                product = plugin.lower()

            # Capture a leading dotted version, tolerating a "v" prefix and a
            # trailing build/suffix: "v1.4.0", "6.2.1-beta" → "1.4.0", "6.2.1".
            version = ""
            if value:
                vm = re.match(r"^v?(\d+(?:\.\d+)*)", value.strip())
                if vm:
                    version = vm.group(1)

            terms.append(SearchTerm(vendor=vendor, product=product, version=version))
    return terms


def _extract_from_nmap_static(ctx: ReconContext) -> list[SearchTerm]:
    """Static fallback: derive search terms from nmap data.

    Prefers the structured CPE (clean vendor/product/version); falls back to a
    regex over the version display string only when no CPE is available.
    """
    terms: list[SearchTerm] = []
    for port in ctx.open_ports:
        # Preferred: nmap CPEs already carry vendor/product/version.
        cpe_terms = [t for t in (_cpe_to_term(c) for c in port.cpe) if t]
        if cpe_terms:
            terms.extend(cpe_terms)
            continue

        if not port.version:
            continue
        m = _NMAP_VERSION_RE.match(port.version)
        if not m:
            continue
        raw_name = m.group(1).strip()
        version = m.group(2)
        name = raw_name.split()[0]
        if name.lower() in _NMAP_SKIP_NAMES:
            continue
        if name in _VENDOR_MAP:
            vendor, product = _VENDOR_MAP[name]
        else:
            vendor = name.lower()
            product = name.lower()
        terms.append(SearchTerm(vendor=vendor, product=product, version=version))
    return terms


def _collect_raw_inputs(ctx: ReconContext) -> tuple[list[str], list[str], list[str]]:
    """Collect raw technology strings from WhatWeb and nmap for AI normalisation.

    Returns ``(whatweb_plugins, nmap_service_versions, whatweb_raw)``. The raw
    WhatWeb output is included (trimmed) so the AI can recover web-app versions
    that the flattened plugin list drops — often the real HTB attack vector.
    """
    whatweb_techs: list[str] = []
    whatweb_raws: list[str] = []
    for wwresult in ctx.whatweb:
        for tech in wwresult.technologies:
            # Collapse multi-line WhatWeb artefacts before sending to AI
            tech = " ".join(tech.splitlines()).strip()
            whatweb_techs.append(tech)
        if wwresult.raw_output.strip():
            # Trim: the AI only needs the headers/version banners, not the full dump.
            whatweb_raws.append(wwresult.raw_output.strip()[:1500])

    nmap_versions: list[str] = []
    for port in ctx.open_ports:
        # Prefer the structured CPE(s) — they normalise far better than the
        # free-text service/version string. Fall back to the display string.
        if port.cpe:
            nmap_versions.extend(port.cpe)
        elif port.version:
            nmap_versions.append(f"{port.service} {port.version}".strip())

    return whatweb_techs, nmap_versions, whatweb_raws


def _deduplicate_struct(terms: list[SearchTerm]) -> list[SearchTerm]:
    """Keep unique (vendor, product) pairs, preferring entries that have a version."""
    seen: dict[tuple[str, str], SearchTerm] = {}
    for t in terms:
        key = (t.vendor, t.product)
        if key not in seen or (not seen[key].version and t.version):
            seen[key] = t
    return list(seen.values())


# ── vulnx search ──────────────────────────────────────────────────────────────

def _parse_vulnx_json(raw: str, product: str) -> list[CveInfo]:
    """Parse vulnx --json output into CveInfo list."""
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return []

    findings: list[CveInfo] = []
    for r in data.get("results", []):
        cve_id = r.get("cve_id") or r.get("doc_id", "")
        if not cve_id:
            continue
        poc_urls = [p.get("url", "") for p in r.get("pocs", []) if p.get("url")]
        findings.append(
            CveInfo(
                cve_id=cve_id,
                severity=r.get("severity", "unknown"),
                cvss_score=float(r.get("cvss_score") or 0.0),
                epss_score=float(r.get("epss_score") or 0.0),
                # Keep enough text for version-range extraction (the affected
                # range is stated in the description); the report truncates again.
                description=r.get("description", "")[:400],
                product=product,
                is_poc=bool(r.get("is_poc", False)),
                is_kev=bool(r.get("is_kev", False)),
                is_remote=bool(r.get("is_remote", False)),
                has_nuclei_template=bool(r.get("is_template", False)),
                remediation=(r.get("remediation") or "")[:300],
                poc_urls=poc_urls[:5],
            )
        )
    return findings


def _build_query(term: SearchTerm) -> str:
    """Build a vulnx search query (vendor/product only).

    The version is deliberately NOT a query constraint: vulnx exposes no
    structured version field to match against (the affected range lives only in
    free-text description/remediation), so a versioned query matches nothing.
    Version applicability is instead resolved client-side after the search via
    :func:`_extract_range_verdict` / :func:`_ai_version_filter`.
    """
    return (
        f"affected_products.vendor:{term.vendor} && "
        f"affected_products.product:{term.product}"
    )


def _base_cmd(query: str, n: int = 40) -> list[str]:
    return [
        "vulnx", "search", query,
        "--json", "--silent", "--disable-update-check",
        "--severity", "critical,high,medium",
        "--sort-desc", "cvss_score",
        "-n", str(n),
    ]


# Result-set variants unioned per term: exploit-prioritised sets plus a broad
# top-CVSS set, so the version-relevant CVE is not lost behind exploit filters.
_SEARCH_VARIANTS: tuple[list[str], ...] = (
    ["--kev", "--poc", "--remote-exploit"],
    ["--poc", "--remote-exploit"],
    ["--template"],
    [],
)


async def _search_structured(term: SearchTerm) -> list[CveInfo]:
    """Search vendor/product, union the variant result sets, then filter by the
    detected version (deterministic range parse + AI fallback on the residual).

    Only confident "out" verdicts are dropped; "in" and "unknown" are kept.
    """
    query = _build_query(term)
    cmds = [_base_cmd(query) + variant for variant in _SEARCH_VARIANTS]
    results = await asyncio.gather(
        *(run(cmd, timeout=30) for cmd in cmds), return_exceptions=True
    )

    findings: dict[str, CveInfo] = {}
    for res in results:
        if isinstance(res, BaseException):
            continue
        for f in _parse_vulnx_json(res.stdout, term.product):
            findings.setdefault(f.cve_id, f)

    if not findings:
        return []

    # Deterministic version verdict from description/remediation.
    for cve_id, f in list(findings.items()):
        verdict = _extract_range_verdict(term.version, f.description, f.remediation)
        findings[cve_id] = f.model_copy(update={"version_verdict": verdict})

    # AI fallback only for the residual "unknown" (and only when we have a
    # detected version to compare against).
    if term.version:
        residual = [
            (f.cve_id, term.version, f.description, f.remediation)
            for f in findings.values()
            if f.version_verdict == "unknown"
        ]
        ai_verdicts = await _ai_version_filter(residual)
        for cve_id, verdict in ai_verdicts.items():
            if cve_id in findings:
                findings[cve_id] = findings[cve_id].model_copy(
                    update={"version_verdict": verdict}
                )

    survivors = [f for f in findings.values() if f.version_verdict != "out"]
    logger.debug(
        "vulnx %s: %d CVE(s) kept (%d dropped out-of-range)",
        term, len(survivors), len(findings) - len(survivors),
    )
    return survivors


async def run_vulnx(ctx: ReconContext) -> None:
    """Run vulnx CVE search for all detected technologies."""
    whatweb_techs, nmap_versions, whatweb_raws = _collect_raw_inputs(ctx)

    # Try AI-based normalisation first
    ai_terms = await _normalize_with_ai(whatweb_techs, nmap_versions, whatweb_raws)

    if ai_terms is not None:
        print_info(f"vulnx: using AI-based technology normalisation ({llm.active_provider()})")
        all_terms = _deduplicate_struct(ai_terms)
    else:
        if llm.active_provider():
            print_warning("vulnx: AI normalisation unavailable — falling back to static parser")
        else:
            print_info("vulnx: no LLM provider — using static technology parser")
        struct_ww = _extract_from_whatweb_static(ctx)
        struct_nmap = _extract_from_nmap_static(ctx)
        all_terms = _deduplicate_struct(struct_ww + struct_nmap)

    if not all_terms:
        print_info("vulnx: no recognisable technologies to search")
        ctx.vulnx = VulnxResult(findings=[], searched_terms=[])
        return

    searched_labels = [str(t) for t in all_terms]
    print_info(f"vulnx: searching {len(all_terms)} tech(s): {', '.join(searched_labels)}")

    tasks = [_search_structured(t) for t in all_terms]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    all_findings: list[CveInfo] = []
    seen_ids: set[str] = set()
    for res in results:
        if isinstance(res, BaseException):
            print_warning(f"vulnx search error: {res}")
            continue
        for f in res:
            if f.cve_id not in seen_ids:
                seen_ids.add(f.cve_id)
                all_findings.append(f)

    # Rank: version-applicable first, then KEV, then exploit availability
    # (PoC / Nuclei template), then real-world likelihood (EPSS), then CVSS.
    _verdict_rank = {"in": 0, "unknown": 1}
    all_findings.sort(key=lambda f: (
        _verdict_rank.get(f.version_verdict, 2),
        not f.is_kev,
        not (f.is_poc or f.has_nuclei_template),
        -f.epss_score,
        -f.cvss_score,
    ))
    ctx.vulnx = VulnxResult(findings=all_findings, searched_terms=searched_labels)

    crit_high = [f for f in all_findings if f.severity in ("critical", "high")]
    kev = [f for f in all_findings if f.is_kev]
    poc = [f for f in all_findings if f.is_poc]
    in_range = [f for f in all_findings if f.version_verdict == "in"]
    print_finding(
        "vulnx",
        f"{len(all_findings)} CVE(s) — "
        f"{len(in_range)} version-matched, {len(crit_high)} critical/high, "
        f"{len(kev)} KEV, {len(poc)} with PoC",
    )
