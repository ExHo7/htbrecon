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
            sections.append(f"SMB users: {', '.join(ctx.smb.users)}")

    if ctx.ldap:
        sections.append(f"LDAP base DN: {ctx.ldap.base_dn}")
        sections.append(f"LDAP entries: {ctx.ldap.entries_count}")

    if ctx.config.credentials:
        sections.append(f"Credentials available: {ctx.config.credentials[0]}:***")

    return "\n\n".join(sections)


SYSTEM_PROMPT = """\
You are an expert penetration tester analyzing reconnaissance data from a Hack The Box machine.

Based on the provided scan results, you must:
1. Identify the most likely attack vectors, ordered by probability of success
2. Suggest specific exploits, CVEs, or techniques to investigate
3. Recommend concrete next manual steps to find the initial foothold
4. Highlight any interesting or unusual findings that deserve attention

Be specific and actionable. Reference port numbers, service versions, and discovered paths.
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
