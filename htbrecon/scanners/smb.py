from __future__ import annotations

import asyncio
import re

from htbrecon import executor
from htbrecon.console import print_finding, print_info, print_success
from htbrecon.models import ReconContext, SmbResult


def _parse_shares(nxc_output: str) -> list[str]:
    """Extract share names from netexec output."""
    shares: list[str] = []
    for line in nxc_output.splitlines():
        match = re.search(r"\s+([\w$]+)\s+(READ|WRITE|NO ACCESS|READ,WRITE)", line)
        if match:
            shares.append(f"{match.group(1)} ({match.group(2)})")
    return shares


def _parse_enum4linux_users(output: str) -> list[str]:
    """Extract usernames from enum4linux-ng output (username: <name> format)."""
    users: list[str] = []
    for line in output.splitlines():
        match = re.search(r"^\s+username:\s+(.+)", line, re.IGNORECASE)
        if match:
            users.append(match.group(1).strip())
    return users


def _parse_nxc_users(output: str) -> list[str]:
    """Extract usernames from 'nxc smb --users' table output."""
    users: list[str] = []
    for line in output.splitlines():
        parts = line.split(None, 4)
        if len(parts) < 5:
            continue
        msg = parts[4]
        # Skip status lines ([*], [+], [-]) and header line (-Username-)
        if msg.startswith("[") or msg.startswith("-"):
            continue
        username = msg.split()[0]
        if re.match(r"^[\w][\w.$-]*$", username):
            users.append(username)
    return users


def _nxc_msg(output: str) -> list[str]:
    """Strip nxc prefix columns and return the message part of each line."""
    msgs = []
    for line in output.splitlines():
        parts = line.split(None, 4)
        if len(parts) >= 5:
            msgs.append(parts[4])
    return msgs


def _parse_ntlm_reflection(output: str) -> bool:
    return any("VULNERABLE" in msg for msg in _nxc_msg(output))


def _parse_enum_av(output: str) -> list[str]:
    products = []
    for msg in _nxc_msg(output):
        m = re.search(r"Found (.+?) INSTALLED", msg)
        if m:
            products.append(m.group(1).strip())
    return products


def _parse_nopac(output: str) -> bool:
    return any(msg.strip() == "VULNERABLE" for msg in _nxc_msg(output))


def _parse_rid_users(output: str) -> list[str]:
    """Extract usernames from nxc --rid-brute output (SidTypeUser entries only)."""
    users: list[str] = []
    for msg in _nxc_msg(output):
        m = re.search(r"\d+:\s+\S+\\([\w.\-]+)\s+\(SidTypeUser\)", msg)
        if m:
            users.append(m.group(1))
    return sorted(set(users))


_SMB_DENIED = ("STATUS_ACCESS_DENIED", "STATUS_USER_SESSION_DELETED", "STATUS_LOGON_FAILURE")


def _has_access_denied(output: str) -> bool:
    return any(p in output for p in _SMB_DENIED)


async def run(ctx: ReconContext) -> None:
    """Run SMB enumeration with enum4linux-ng and netexec."""
    config = ctx.config
    out_dir = config.project_dir / "smb"
    out_dir.mkdir(parents=True, exist_ok=True)

    enum_out = out_dir / "enum4linux.txt"
    nxc_shares_out = out_dir / "nxc_shares.txt"

    # enum4linux-ng
    enum_cmd = ["enum4linux-ng", "-A", config.ip]
    if config.credentials:
        enum_cmd.extend(["-u", config.credentials[0], "-p", config.credentials[1]])

    # nxc --shares (always) + nxc --users (with credentials), run in parallel
    nxc_shares_cmd = ["nxc", "smb", config.ip, "--shares"]
    if config.credentials:
        nxc_shares_cmd.extend(["-u", config.credentials[0], "-p", config.credentials[1]])

    tasks = [
        executor.run(enum_cmd, timeout=120, output_file=enum_out),
        executor.run(nxc_shares_cmd, timeout=60, output_file=nxc_shares_out),
    ]

    nxc_users_output = ""
    if config.credentials:
        nxc_users_cmd = [
            "nxc", "smb", config.ip,
            "-u", config.credentials[0], "-p", config.credentials[1],
            "--users",
        ]
        tasks.append(executor.run(nxc_users_cmd, timeout=60, output_file=out_dir / "nxc_users.txt"))

    results = await asyncio.gather(*tasks, return_exceptions=True)

    enum_result = results[0]
    nxc_shares_result = results[1]
    nxc_users_result = results[2] if config.credentials else None

    if isinstance(enum_result, Exception) or enum_result.returncode == 127:
        ctx.errors.append("enum4linux-ng not found")
        enum_output = ""
    else:
        enum_output = enum_result.stdout

    if isinstance(nxc_shares_result, Exception) or nxc_shares_result.returncode == 127:
        ctx.errors.append("nxc (netexec) not found")
        nxc_output = ""
    else:
        nxc_output = nxc_shares_result.stdout

    if nxc_users_result and not isinstance(nxc_users_result, Exception):
        nxc_users_output = nxc_users_result.stdout

    shares = _parse_shares(nxc_output)

    # Merge users from enum4linux-ng and nxc --users, deduplicated
    users_set: set[str] = set()
    users_set.update(_parse_enum4linux_users(enum_output))
    users_set.update(_parse_nxc_users(nxc_users_output))
    users = sorted(users_set)

    # Vulnerability checks (credentials required)
    ntlm_vuln = False
    av_products: list[str] = []
    nopac_vuln = False

    if config.credentials:
        user, password = config.credentials
        nxc_base = ["nxc", "smb", config.ip, "-u", user, "-p", password]
        vuln_results = await asyncio.gather(
            executor.run([*nxc_base, "-M", "ntlm_reflection"], timeout=30,
                         output_file=out_dir / "nxc_ntlm_reflection.txt"),
            executor.run([*nxc_base, "-M", "enum_av"], timeout=30,
                         output_file=out_dir / "nxc_enum_av.txt"),
            executor.run([*nxc_base, "-M", "nopac"], timeout=60,
                         output_file=out_dir / "nxc_nopac.txt"),
            return_exceptions=True,
        )
        ntlm_r, av_r, nopac_r = vuln_results
        if not isinstance(ntlm_r, Exception):
            ntlm_vuln = _parse_ntlm_reflection(ntlm_r.stdout)
        if not isinstance(av_r, Exception):
            av_products = _parse_enum_av(av_r.stdout)
        if not isinstance(nopac_r, Exception):
            nopac_vuln = _parse_nopac(nopac_r.stdout)

    # RID brute (only without credentials — enumerates users via RID cycling)
    rid_users: list[str] = []
    if not config.credentials:
        rid_result = await executor.run(
            ["nxc", "smb", config.ip, "--rid-brute", "10000"],
            timeout=120,
            output_file=out_dir / "nxc_rid_brute.txt",
        )
        if not isinstance(rid_result, Exception) and rid_result.returncode != 127:
            rid_users = _parse_rid_users(rid_result.stdout)

    ctx.smb = SmbResult(
        shares=shares,
        users=users,
        ntlm_reflection_vulnerable=ntlm_vuln,
        av_products=av_products,
        nopac_vulnerable=nopac_vuln,
        rid_users=rid_users,
        enum4linux_output=enum_output,
        nxc_output=nxc_output,
    )

    if shares:
        print_success(f"SMB shares found: {len(shares)}")
        for s in shares:
            print_finding("info", f"Share: {s}")

    if users:
        print_success(f"SMB users found: {len(users)}")
        for u in users:
            print_finding("info", f"User: {u}")

    if not shares and not users:
        if _has_access_denied(nxc_output) or _has_access_denied(enum_output):
            print_finding("warn", "SMB: access denied")
        else:
            print_info("SMB enumeration: no shares or users found")

    if ntlm_vuln:
        print_finding("critical", "NTLM Reflection vulnerable (CVE-2025-33073)")
    if nopac_vuln:
        print_finding("critical", "NoPac vulnerable (CVE-2021-42278/42287)")
    if av_products:
        print_finding("info", f"AV/EDR detected: {', '.join(av_products)}")

    if rid_users:
        print_success(f"RID brute: {len(rid_users)} user(s) found")
        for u in rid_users:
            print_finding("info", f"RID user: {u}")
