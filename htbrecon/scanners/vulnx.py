from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass

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
- Never invent CVEs or products you don't recognise — omit them instead."""


async def _normalize_with_ai(raw_technologies: list[str], nmap_versions: list[str]) -> list[SearchTerm] | None:
    """Use Claude Haiku to parse and normalize detected technologies.

    Returns None if AI is unavailable (no API key, import error, or exception).
    """
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        return None

    try:
        import anthropic
    except ImportError:
        return None

    payload = {
        "whatweb_plugins": raw_technologies,
        "nmap_service_versions": nmap_versions,
    }
    user_msg = (
        "Normalize these detected technologies for NVD CVE lookup.\n"
        f"Input: {json.dumps(payload, ensure_ascii=False)}"
    )

    try:
        client = anthropic.AsyncAnthropic(api_key=api_key)
        response = await client.messages.create(
            model="claude-haiku-4-5-20251001",
            max_tokens=1024,
            system=_AI_SYSTEM_PROMPT,
            messages=[{"role": "user", "content": user_msg}],
        )
        if not response.content:
            return None
        raw = response.content[0]
        text = raw.text if hasattr(raw, "text") else ""

        # Strip accidental markdown fences
        text = re.sub(r"```(?:json)?\s*", "", text).strip().rstrip("`").strip()

        data = json.loads(text)
        terms: list[SearchTerm] = []
        for item in data:
            vendor = str(item.get("vendor", "")).strip().lower()
            product = str(item.get("product", "")).strip().lower()
            version = str(item.get("version", "")).strip()
            if vendor and product:
                terms.append(SearchTerm(vendor=vendor, product=product, version=version))
        return terms
    except Exception as exc:
        logger.debug("AI tech normalisation failed: %s", exc)
        return None


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

            version = ""
            if value and re.match(r"^\d", value):
                version = value.split()[0]

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


def _collect_raw_inputs(ctx: ReconContext) -> tuple[list[str], list[str]]:
    """Collect raw technology strings from WhatWeb and nmap for AI normalisation."""
    whatweb_techs: list[str] = []
    for wwresult in ctx.whatweb:
        for tech in wwresult.technologies:
            # Collapse multi-line WhatWeb artefacts before sending to AI
            tech = " ".join(tech.splitlines()).strip()
            whatweb_techs.append(tech)

    nmap_versions: list[str] = []
    for port in ctx.open_ports:
        # Prefer the structured CPE(s) — they normalise far better than the
        # free-text service/version string. Fall back to the display string.
        if port.cpe:
            nmap_versions.extend(port.cpe)
        elif port.version:
            nmap_versions.append(f"{port.service} {port.version}".strip())

    return whatweb_techs, nmap_versions


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
        findings.append(
            CveInfo(
                cve_id=cve_id,
                severity=r.get("severity", "unknown"),
                cvss_score=float(r.get("cvss_score") or 0.0),
                epss_score=float(r.get("epss_score") or 0.0),
                description=r.get("description", "")[:200],
                product=product,
                is_poc=bool(r.get("is_poc", False)),
                is_kev=bool(r.get("is_kev", False)),
                is_remote=bool(r.get("is_remote", False)),
                has_nuclei_template=bool(r.get("is_template", False)),
            )
        )
    return findings


def _build_query(term: SearchTerm, *, with_version: bool = True) -> str:
    """Build a vulnx search query string from a SearchTerm.

    ``with_version=False`` drops the version constraint — nmap's exact version
    rarely matches NVD's version field, so a version-less query is used as a
    last resort to keep the vendor/product hit instead of returning nothing.
    """
    parts = [
        f"affected_products.vendor:{term.vendor}",
        f"affected_products.product:{term.product}",
    ]
    if with_version and term.version:
        parts.append(f"affected_products.version:{term.version}")
    return " && ".join(parts)


def _base_cmd(query: str) -> list[str]:
    return [
        "vulnx", "search", query,
        "--json", "--silent", "--disable-update-check",
        "--severity", "critical,high,medium",
        "--sort-desc", "cvss_score",
        "-n", "15",
    ]


async def _search_structured(term: SearchTerm) -> list[CveInfo]:
    """Search by vendor/product using vulnx query syntax with tiered fallback."""
    base_cmd = _base_cmd(_build_query(term))

    # Tier 1: KEV + PoC + remote exploit (the gold)
    result = await run(base_cmd + ["--kev", "--poc", "--remote-exploit"], timeout=30)
    findings = _parse_vulnx_json(result.stdout, term.product)

    # Tier 2: PoC + remote (no KEV requirement)
    if not findings:
        result = await run(base_cmd + ["--poc", "--remote-exploit"], timeout=30)
        findings = _parse_vulnx_json(result.stdout, term.product)

    # Tier 3: has Nuclei template (actionable for automated scanning)
    if not findings:
        result = await run(base_cmd + ["--template"], timeout=30)
        findings = _parse_vulnx_json(result.stdout, term.product)

    # Tier 4: broad search (no exploit filters, still version-pinned)
    if not findings:
        result = await run(base_cmd, timeout=30)
        findings = _parse_vulnx_json(result.stdout, term.product)

    # Tier 5: drop the version constraint (exact NVD version match is brittle)
    if not findings and term.version:
        result = await run(_base_cmd(_build_query(term, with_version=False)), timeout=30)
        findings = _parse_vulnx_json(result.stdout, term.product)

    if findings:
        logger.debug("vulnx %s: %d CVE(s)", term, len(findings))
    return findings


async def run_vulnx(ctx: ReconContext) -> None:
    """Run vulnx CVE search for all detected technologies."""
    import asyncio

    whatweb_techs, nmap_versions = _collect_raw_inputs(ctx)

    # Try AI-based normalisation first
    ai_terms = await _normalize_with_ai(whatweb_techs, nmap_versions)

    if ai_terms is not None:
        print_info("vulnx: using AI-based technology normalisation")
        all_terms = _deduplicate_struct(ai_terms)
    else:
        if os.environ.get("ANTHROPIC_API_KEY"):
            print_warning("vulnx: AI normalisation failed — falling back to static parser")
        else:
            print_info("vulnx: no API key — using static technology parser")
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

    all_findings.sort(key=lambda f: (not f.is_kev, -f.cvss_score))
    ctx.vulnx = VulnxResult(findings=all_findings, searched_terms=searched_labels)

    crit_high = [f for f in all_findings if f.severity in ("critical", "high")]
    kev = [f for f in all_findings if f.is_kev]
    poc = [f for f in all_findings if f.is_poc]
    print_finding(
        "vulnx",
        f"{len(all_findings)} CVE(s) — "
        f"{len(crit_high)} critical/high, {len(kev)} KEV, {len(poc)} with PoC",
    )
