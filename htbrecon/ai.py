from __future__ import annotations

import os

from htbrecon.console import print_info, print_warning
from htbrecon.models import ReconContext


def _build_prompt(ctx: ReconContext) -> str:
    """Build a concise summary of findings for Claude to analyze."""
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

    if ctx.ftp:
        if ctx.ftp.anonymous:
            sections.append(f"FTP: anonymous login ALLOWED on port {ctx.ftp.port}")
        elif ctx.ftp.accessible:
            sections.append(f"FTP: authenticated access on port {ctx.ftp.port}")

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

    if ctx.bloodhound and ctx.bloodhound.summary_text:
        sections.append(f"BloodHound AD enumeration:\n{ctx.bloodhound.summary_text}")

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
    """Send aggregated findings to Claude for analysis."""
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        print_warning("ANTHROPIC_API_KEY not set — skipping AI analysis")
        return ""

    try:
        import anthropic
    except ImportError:
        print_warning("anthropic package not installed — skipping AI analysis")
        return ""

    findings_summary = _build_prompt(ctx)
    if not findings_summary.strip():
        print_info("No findings to analyze")
        return ""

    client = anthropic.AsyncAnthropic(api_key=api_key)

    response = await client.messages.create(
        model="claude-sonnet-4-20250514",
        max_tokens=4096,
        system=SYSTEM_PROMPT,
        messages=[
            {
                "role": "user",
                "content": f"Analyze these reconnaissance results and suggest attack vectors:\n\n{findings_summary}",
            }
        ],
    )

    if not response.content:
        return ""
    block = response.content[0]
    return block.text if hasattr(block, "text") else ""
