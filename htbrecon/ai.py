from __future__ import annotations

import os

from htbrecon import llm
from htbrecon.console import print_info, print_warning
from htbrecon.models import ReconContext

# This tehnologies are excluded from AI CVE analysis due to low signal.
_DEFAULT_LOW_SIGNAL = frozenset({
    "nginx", "http_server", "openssh", "openssl", "bind",
    "linux_kernel", "ubuntu_linux", "debian_linux", "windows",
    "php", "proftpd", "vsftpd",
})


def _low_signal_products() -> frozenset[str]:
    """Resolve the low-signal product denylist, honouring env overrides.

    HTBRECON_CVE_EXCLUDE        replaces the default set (comma-separated names).
    HTBRECON_CVE_EXCLUDE_EXTRA  adds to the active set.
    Both are case-insensitive product names.
    """
    base_env = os.environ.get("HTBRECON_CVE_EXCLUDE", "").strip()
    base = (
        frozenset(p.strip().lower() for p in base_env.split(",") if p.strip())
        if base_env else _DEFAULT_LOW_SIGNAL
    )
    extra_env = os.environ.get("HTBRECON_CVE_EXCLUDE_EXTRA", "").strip()
    extra = frozenset(p.strip().lower() for p in extra_env.split(",") if p.strip())
    return base | extra


def _build_prompt(ctx: ReconContext) -> str:
    """Build a concise summary of findings for AI to analyze."""
    sections: list[str] = []

    sections.append(f"Target: {ctx.config.ip} ({ctx.config.hostname})")

    if ctx.nmap:
        ports_str = "\n".join(
            f"  {p.port}/{p.protocol} {p.service} {p.version}"
            for p in ctx.nmap.ports
            if p.state == "open"
        )
        sections.append(f"Open ports:\n{ports_str}")

    if ctx.whatweb:
        for w in ctx.whatweb:
            techs = ", ".join(w.technologies[:15])
            sections.append(f"Technologies on {w.url}: {techs}")

    if ctx.subdomains:
        sections.append(f"Subdomains found: {', '.join(ctx.subdomains)}")

    if ctx.directories:
        for d in ctx.directories:
            if d.found_items:
                items = ", ".join(d.found_items[:20])
                sections.append(f"Directories on {d.target}: {items}")

    if ctx.nuclei and ctx.nuclei.findings:
        findings_str = "\n".join(
            f"  [{f.severity}] {f.name} @ {f.matched_at}"
            for f in ctx.nuclei.findings[:20]
        )
        sections.append(f"Nuclei findings:\n{findings_str}")

    if ctx.smb:
        if ctx.smb.shares:
            sections.append(f"SMB shares: {', '.join(ctx.smb.shares)}")
        if ctx.smb.users:
            sections.append(f"SMB users ({len(ctx.smb.users)}): {', '.join(ctx.smb.users)}")
        smb_vulns = []
        if ctx.smb.ntlm_reflection_vulnerable:
            smb_vulns.append("NTLM Reflection (CVE-2025-33073)")
        if ctx.smb.nopac_vulnerable:
            smb_vulns.append("NoPac (CVE-2021-42278/42287)")
        if smb_vulns:
            sections.append(f"SMB vulnerabilities: {', '.join(smb_vulns)}")
        if ctx.smb.coerce_vulns:
            sections.append(f"NTLM coercion vulnerabilities: {', '.join(ctx.smb.coerce_vulns)}")
        if ctx.smb.av_products:
            sections.append(f"AV/EDR on target: {', '.join(ctx.smb.av_products)}")

    if ctx.spider and ctx.spider.interesting_files:
        files = "\n".join(f"  {f}" for f in ctx.spider.interesting_files[:25])
        sections.append(
            f"SMB spidered files ({len(ctx.spider.interesting_files)} interesting — "
            f"inspect for creds/configs/scripts/keys):\n{files}"
        )

    if ctx.ftp:
        if ctx.ftp.anonymous:
            sections.append(f"FTP: anonymous login ALLOWED on port {ctx.ftp.port}")
        elif ctx.ftp.accessible:
            sections.append(f"FTP: authenticated access on port {ctx.ftp.port}")

    if ctx.winrm and ctx.winrm.accessible:
        sections.append(
            f"WinRM: access CONFIRMED on port {ctx.winrm.port} — evil-winrm foothold available"
        )

    if ctx.ssh and ctx.ssh.accessible:
        sections.append(f"SSH: authenticated access CONFIRMED on port {ctx.ssh.port}")

    if ctx.mssql and ctx.mssql.accessible:
        sections.append(
            f"MSSQL access on port {ctx.mssql.port} — "
            f"sysadmin={ctx.mssql.sysadmin}, xp_cmdshell={ctx.mssql.xp_cmdshell}"
        )
        if ctx.mssql.databases:
            sections.append(f"MSSQL databases: {', '.join(ctx.mssql.databases)}")

    if ctx.spray:
        if ctx.spray.valid_creds:
            sections.append(f"Valid credentials from spray: {', '.join(ctx.spray.valid_creds)}")
        else:
            sections.append(f"Password spray: no matches ({ctx.spray.users_tested} users tested, username=password)")

    if ctx.ldap:
        sections.append(f"LDAP base DN: {ctx.ldap.base_dn}")
        sections.append(f"LDAP entries: {ctx.ldap.entries_count}")
        if ctx.ldap.domain_admins:
            sections.append(f"Domain Admins: {', '.join(ctx.ldap.domain_admins)}")
        if ctx.ldap.unconstrained_delegation:
            sections.append(f"Unconstrained delegation: {', '.join(ctx.ldap.unconstrained_delegation)}")
        if ctx.ldap.descriptions:
            sections.append(f"Account descriptions (check for creds): {'; '.join(ctx.ldap.descriptions[:10])}")
        if ctx.ldap.domain_trusts:
            sections.append(f"Domain trusts: {', '.join(ctx.ldap.domain_trusts)}")
        if ctx.ldap.adcs_vulns:
            sections.append(f"ADCS vulnerabilities: {', '.join(ctx.ldap.adcs_vulns)}")
        if ctx.ldap.asreproast_hashes:
            sections.append(f"AS-REP Roastable hashes found: {len(ctx.ldap.asreproast_hashes)}")
        if ctx.ldap.kerberoast_hashes:
            sections.append(f"Kerberoastable hashes found: {len(ctx.ldap.kerberoast_hashes)}")

    if ctx.kerbrute and ctx.kerbrute.valid_users:
        sections.append(
            f"Kerbrute — {len(ctx.kerbrute.valid_users)} valid AD user(s) enumerated "
            f"(no creds needed; AS-REP roast candidates): "
            f"{', '.join(ctx.kerbrute.valid_users[:30])}"
        )

    if ctx.bloodhound and ctx.bloodhound.summary_text:
        sections.append(f"BloodHound AD enumeration:\n{ctx.bloodhound.summary_text}")

    if ctx.api:
        if ctx.api.spec_urls:
            sections.append(f"API specs exposed: {', '.join(ctx.api.spec_urls)}")
        if ctx.api.graphql_endpoints:
            sections.append(f"GraphQL introspection open: {', '.join(ctx.api.graphql_endpoints)}")
        if ctx.api.endpoints:
            notable = [e for e in ctx.api.endpoints if any(
                kw in e for kw in ("401", "403", "credential", "admin", "token", "auth", "key", "secret", "config", "env")
            )]
            all_shown = notable[:20] or ctx.api.endpoints[:20]
            sections.append(f"API endpoints ({len(ctx.api.endpoints)} total, sample):\n" +
                            "\n".join(f"  {e}" for e in all_shown))

    # Products rarely exploitable on HTB — keep in full report but skip in AI prompt
    low_signal = _low_signal_products()

    if ctx.katana and ctx.katana.interesting_urls:
        sections.append(
            f"Katana crawl — {len(ctx.katana.urls_found)} URL(s) crawled, "
            f"{len(ctx.katana.interesting_urls)} interesting:\n" +
            "\n".join(f"  {u}" for u in ctx.katana.interesting_urls[:30])
        )

    if ctx.vulnx and ctx.vulnx.findings:
        actionable = [f for f in ctx.vulnx.findings if f.product.lower() not in low_signal]
        excluded = len(ctx.vulnx.findings) - len(actionable)
        kev = [f for f in actionable if f.is_kev]
        crit = [f for f in actionable if f.severity == "critical"]
        high_poc = [f for f in actionable if f.severity == "high" and f.is_poc]
        in_range = [f for f in actionable if f.version_verdict == "in"]
        # Build the candidate set, then surface version-matched CVEs first.
        candidates: list = []
        seen: set[str] = set()
        for f in in_range + kev + crit + high_poc:
            if f.cve_id not in seen:
                seen.add(f.cve_id)
                candidates.append(f)
        vuln_lines = []
        for f in candidates[:15]:
            tags = []
            if f.version_verdict == "in":
                tags.append("VER-MATCH")
            if f.is_kev:
                tags.append("KEV")
            if f.is_poc:
                tags.append("PoC")
            tag_str = f" [{', '.join(tags)}]" if tags else ""
            line = f"  {f.cve_id} (CVSS {f.cvss_score}) {f.product}: {f.description[:120]}{tag_str}"
            if f.poc_urls:
                line += f"\n    PoC: {f.poc_urls[0]}"
            if f.remediation:
                line += f"\n    Fix: {f.remediation[:80]}"
            vuln_lines.append(line)
        if vuln_lines:
            sections.append(
                f"CVE intelligence — {len(actionable)} actionable CVE(s) "
                f"({excluded} common/low-signal CVE(s) excluded for HTB) "
                f"({len(in_range)} version-matched, {len(kev)} KEV, {len(crit)} critical):\n"
                + "\n".join(vuln_lines)
            )

    if ctx.config.credentials:
        sections.append(f"Credentials available: {ctx.config.credentials[0]}:***")

    return "\n\n".join(sections)


SYSTEM_PROMPT = """\
You are an expert penetration tester analyzing reconnaissance data from a Hack The Box or CTF machine.

Based on the provided scan results, you must:
1. Identify the most likely attack vectors, ordered by probability of success
2. Suggest specific exploits, CVEs, or AD attack techniques to investigate (Kerberoasting, ASREPRoast, DCSync, ESC1/ESC8, BadSuccessor, etc.)
3. Recommend concrete next manual steps for initial foothold or privilege escalation
4. Highlight any high-value targets from BloodHound data (admin users, delegation, DCSync rights)

Be specific and actionable. Reference port numbers, service versions, user names, and ADCS vulnerabilities.
Format your response in Markdown with clear sections."""


async def analyze(ctx: ReconContext) -> str:
    """Send aggregated findings to the active LLM (Anthropic or Ollama) for analysis."""
    if llm.active_provider() is None:
        print_warning(
            "No LLM provider configured — skipping AI analysis "
            "(set ANTHROPIC_API_KEY, or HTBRECON_LLM_PROVIDER=ollama + HTBRECON_OLLAMA_MODEL in .env)"
        )
        return ""

    findings_summary = _build_prompt(ctx)
    if not findings_summary.strip():
        print_info("No findings to analyze")
        return ""

    try:
        temperature = float(os.environ.get("HTBRECON_AI_TEMPERATURE", "0.2"))
    except ValueError:
        temperature = 0.2

    text = await llm.complete(
        system=SYSTEM_PROMPT,
        user=f"Analyze these reconnaissance results and suggest attack vectors:\n\n{findings_summary}",
        tier="large",
        max_tokens=4096,
        temperature=temperature,
    )
    return text or ""
