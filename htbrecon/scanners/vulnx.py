from __future__ import annotations

import json
import re
from dataclasses import dataclass

from htbrecon.console import logger, print_finding, print_info, print_warning
from htbrecon.executor import run
from htbrecon.models import CveInfo, ReconContext, VulnxResult

# Nmap version strings often look like "Apache httpd 2.4.51 ((Unix))"
_NMAP_VERSION_RE = re.compile(r"^([\w\-]+(?:\s[\w\-]+)?)\s+(\d+[\d.]+)", re.IGNORECASE)

# Pure metadata/HTTP plugins — not real products to search CVEs for
_SKIP_PLUGINS = frozenset({
    "HTTPServer", "X-Powered-By", "X-Frame-Options", "Strict-Transport-Security",
    "X-Content-Type-Options", "Content-Security-Policy", "X-XSS-Protection",
    "Via-Proxy", "RedirectLocation", "IP", "Country", "Title", "Meta-Author",
    "Meta-Generator", "Email", "Script", "Frame", "Cookies", "HTML5",
    "Bootstrap", "JQuery", "jQuery", "UncommonHeaders",
})

# Vendor normalisation map: plugin name → (vendor, product)
_VENDOR_MAP: dict[str, tuple[str, str]] = {
    "Apache": ("apache", "apache"),
    "Nginx": ("nginx", "nginx"),
    "nginx": ("nginx", "nginx"),
    "IIS": ("microsoft", "iis"),
    "WordPress": ("wordpress", "wordpress"),
    "Joomla": ("joomla", "joomla"),
    "Drupal": ("drupal", "drupal"),
    "PHP": ("php", "php"),
    "OpenSSL": ("openssl", "openssl"),
    "Tomcat": ("apache", "tomcat"),
    "Jenkins": ("jenkins", "jenkins"),
    "GitLab": ("gitlab", "gitlab"),
    "Grafana": ("grafana", "grafana"),
    "Kibana": ("elastic", "kibana"),
    "Elasticsearch": ("elastic", "elasticsearch"),
    "Spring": ("vmware", "spring"),
    "Rails": ("rubyonrails", "rails"),
    "Django": ("djangoproject", "django"),
    "Express": ("expressjs", "express"),
    "Laravel": ("laravel", "laravel"),
    "Symfony": ("sensiolabs", "symfony"),
    "Magento": ("magento", "magento"),
    "SharePoint": ("microsoft", "sharepoint"),
    "Exchange": ("microsoft", "exchange"),
    "Outlook": ("microsoft", "outlook"),
    "OWA": ("microsoft", "exchange"),
}


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


def _extract_from_whatweb(ctx: ReconContext) -> list[SearchTerm]:
    """Parse all WhatWeb results (main host + subdomains) into structured search terms.

    - "nginx[1.24.0]"   → SearchTerm(nginx, nginx, 1.24.0)
    - "WordPress[6.1]"  → SearchTerm(wordpress, wordpress, 6.1)
    - "Title[...]", "HTML5", "Script", etc. → ignored
    """
    terms: list[SearchTerm] = []

    for wwresult in ctx.whatweb:
        for tech in wwresult.technologies:
            tech = tech.strip()
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
                version = value.split()[0]  # "1.24.0 (Ubuntu)" → "1.24.0"

            terms.append(SearchTerm(vendor=vendor, product=product, version=version))

    return terms


def _extract_from_nmap(ctx: ReconContext) -> list[SearchTerm]:
    """Parse nmap service version strings into SearchTerms."""
    terms: list[SearchTerm] = []
    for port in ctx.open_ports:
        if not port.version:
            continue
        m = _NMAP_VERSION_RE.match(port.version)
        if not m:
            continue
        raw_name = m.group(1).strip()
        version = m.group(2)
        # Normalise: "Apache httpd" → "apache", "OpenSSH" → "openssh"
        name = raw_name.split()[0]  # take first word
        if name in _VENDOR_MAP:
            vendor, product = _VENDOR_MAP[name]
        else:
            vendor = name.lower()
            product = name.lower()
        terms.append(SearchTerm(vendor=vendor, product=product, version=version))
    return terms


def _deduplicate_struct(terms: list[SearchTerm]) -> list[SearchTerm]:
    """Keep unique (vendor, product) pairs, preferring entries that have a version."""
    seen: dict[tuple[str, str], SearchTerm] = {}
    for t in terms:
        key = (t.vendor, t.product)
        if key not in seen or (not seen[key].version and t.version):
            seen[key] = t
    return list(seen.values())


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
                description=r.get("description", "")[:200],
                product=product,
                is_poc=bool(r.get("is_poc", False)),
                is_kev=bool(r.get("is_kev", False)),
                is_remote=bool(r.get("is_remote", False)),
            )
        )
    return findings


async def _search_structured(term: SearchTerm) -> list[CveInfo]:
    """Search by vendor/product with strict→relaxed fallback."""
    base_cmd = [
        "vulnx", "search",
        "--json", "--silent", "--disable-update-check",
        "--vendor", term.vendor,
        "--product", term.product,
        "--severity", "critical,high,medium",
        "-n", "10",
    ]
    # Strict first: PoC + remotely exploitable
    result = await run(base_cmd + ["--poc", "--remote-exploit"], timeout=30)
    findings = _parse_vulnx_json(result.stdout, term.product)
    if not findings:
        result = await run(base_cmd, timeout=30)
        findings = _parse_vulnx_json(result.stdout, term.product)
    if findings:
        logger.debug("vulnx %s: %d CVE(s)", term, len(findings))
    return findings


async def run_vulnx(ctx: ReconContext) -> None:
    """Run vulnx CVE search for all detected technologies."""
    import asyncio

    struct_ww = _extract_from_whatweb(ctx)
    struct_nmap = _extract_from_nmap(ctx)
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
