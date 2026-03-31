from __future__ import annotations

import asyncio
import re

from htbrecon import executor
from htbrecon.console import print_finding, print_info, print_success, print_warning
from htbrecon.models import MssqlResult, ReconContext


def _parse_accessible(output: str) -> bool:
    """Return True if nxc mssql output indicates successful authentication."""
    for line in output.splitlines():
        parts = line.split(None, 4)
        if len(parts) < 5:
            continue
        msg = parts[4]
        if "(Pwn3d!)" in msg:
            return True
        if msg.startswith("[+]") and "STATUS_LOGON_FAILURE" not in msg:
            return True
    return False


def _parse_databases(output: str) -> list[str]:
    """Extract database names from nxc mssql --get-db output."""
    dbs: list[str] = []
    for line in output.splitlines():
        parts = line.split(None, 4)
        if len(parts) < 5:
            continue
        msg = parts[4]
        # nxc outputs each db on a [+] line like: "[+] DOMAIN\user  Database: master"
        m = re.search(r"Database[:\s]+(\S+)", msg, re.IGNORECASE)
        if m:
            dbs.append(m.group(1))
    return sorted(set(dbs))


def _parse_mssql_priv(output: str) -> tuple[bool, bool]:
    """Return (sysadmin, xp_cmdshell) from nxc mssql_priv module output."""
    sysadmin = False
    xp_cmdshell = False
    for line in output.splitlines():
        lower = line.lower()
        if "sysadmin" in lower and ("true" in lower or "1" in lower or "yes" in lower):
            sysadmin = True
        if "xp_cmdshell" in lower and ("true" in lower or "1" in lower or "enabled" in lower):
            xp_cmdshell = True
    return sysadmin, xp_cmdshell


async def run(ctx: ReconContext) -> None:
    config = ctx.config
    out_dir = config.project_dir / "mssql"
    out_dir.mkdir(parents=True, exist_ok=True)

    assert config.credentials is not None
    user, password = config.credentials

    open_ports = {p.port for p in ctx.open_ports}
    port = 1433 if 1433 in open_ports else 1434

    print_info(f"Enumerating MSSQL on port {port}...")

    nxc_base = ["nxc", "mssql", config.ip, "-u", user, "-p", password]
    if port != 1433:
        nxc_base.extend(["--port", str(port)])

    auth_r, db_r, priv_r = await asyncio.gather(
        executor.run(nxc_base, timeout=60, output_file=out_dir / "mssql_auth.txt"),
        executor.run([*nxc_base, "--get-db"], timeout=60, output_file=out_dir / "mssql_dbs.txt"),
        executor.run([*nxc_base, "-M", "mssql_priv"], timeout=60, output_file=out_dir / "mssql_priv.txt"),
        return_exceptions=True,
    )

    if isinstance(auth_r, BaseException):
        ctx.errors.append(f"MSSQL error: {auth_r}")
        return

    if auth_r.returncode == 127:
        ctx.errors.append("nxc not found — skipping MSSQL check")
        print_warning("nxc not found")
        return

    accessible = _parse_accessible(auth_r.stdout)
    raw = auth_r.stdout

    databases: list[str] = []
    if not isinstance(db_r, BaseException):
        databases = _parse_databases(db_r.stdout)
        raw += db_r.stdout

    sysadmin, xp_cmdshell = False, False
    if not isinstance(priv_r, BaseException):
        sysadmin, xp_cmdshell = _parse_mssql_priv(priv_r.stdout)
        raw += priv_r.stdout

    ctx.mssql = MssqlResult(
        accessible=accessible,
        sysadmin=sysadmin,
        xp_cmdshell=xp_cmdshell,
        databases=databases,
        port=port,
        raw_output=raw,
    )

    if not accessible:
        print_info(f"MSSQL access denied on port {port} ({user})")
        return

    print_success(f"MSSQL access GRANTED on port {port} as {user}")

    if xp_cmdshell:
        print_finding("critical", f"MSSQL: xp_cmdshell ENABLED → RCE possible as {user}")
    if sysadmin:
        print_finding("critical", f"MSSQL: {user} is sysadmin")
    if databases:
        print_finding("info", f"MSSQL databases: {', '.join(databases)}")
    elif accessible:
        print_finding("info", f"MSSQL: authenticated as {user} on port {port}")
