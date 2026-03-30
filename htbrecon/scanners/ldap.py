from __future__ import annotations

import re

from htbrecon import executor
from htbrecon.console import print_finding, print_info, print_success
from htbrecon.models import LdapResult, ReconContext


def _extract_base_dn(output: str) -> str:
    """Extract base DN from ldapsearch namingContexts query."""
    for line in output.splitlines():
        match = re.match(r"namingContexts:\s*(.+)", line, re.IGNORECASE)
        if match:
            return match.group(1).strip()
    return ""


async def run(ctx: ReconContext) -> None:
    """Run LDAP enumeration with ldapsearch."""
    config = ctx.config
    out_dir = config.project_dir / "ldap"
    out_dir.mkdir(parents=True, exist_ok=True)

    # Step 1: discover base DN
    base_cmd = [
        "ldapsearch",
        "-x",
        "-H",
        f"ldap://{config.ip}",
        "-s",
        "base",
        "namingContexts",
    ]

    base_result = await executor.run(base_cmd, timeout=30)

    if base_result.returncode == 127:
        ctx.errors.append("ldapsearch not found")
        return

    base_dn = _extract_base_dn(base_result.stdout)
    if not base_dn:
        print_info("LDAP: could not determine base DN")
        ctx.ldap = LdapResult(raw_output=base_result.stdout)
        return

    print_success(f"LDAP base DN: {base_dn}")

    # Step 2: full enumeration
    out_file = out_dir / "ldapsearch.txt"
    enum_cmd = [
        "ldapsearch",
        "-x",
        "-H",
        f"ldap://{config.ip}",
        "-b",
        base_dn,
    ]

    if config.credentials:
        enum_cmd.extend(["-D", config.credentials[0], "-w", config.credentials[1]])

    enum_result = await executor.run(enum_cmd, timeout=60, output_file=out_file)

    entries_count = len(re.findall(r"^dn:\s+", enum_result.stdout, re.MULTILINE))

    ctx.ldap = LdapResult(
        raw_output=enum_result.stdout,
        base_dn=base_dn,
        entries_count=entries_count,
    )

    if entries_count > 0:
        print_success(f"LDAP: {entries_count} entries enumerated")
        # Show some interesting attributes
        for line in enum_result.stdout.splitlines():
            if any(
                kw in line.lower()
                for kw in ["samaccountname:", "serviceprincipalname:", "memberof:"]
            ):
                print_finding("info", line.strip())
    else:
        print_info("LDAP: no entries found")
