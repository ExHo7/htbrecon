from __future__ import annotations

import re

from htbrecon import executor
from htbrecon.console import print_finding, print_info, print_success
from htbrecon.models import ReconContext, SmbResult


def _parse_shares(nxc_output: str) -> list[str]:
    """Extract share names from netexec output."""
    shares: list[str] = []
    for line in nxc_output.splitlines():
        # nxc output format: SMB  ip  445  NAME  [*]  ShareName  Permissions  Comment
        match = re.search(r"\s+([\w$]+)\s+(READ|WRITE|NO ACCESS|READ,WRITE)", line)
        if match:
            shares.append(f"{match.group(1)} ({match.group(2)})")
    return shares


def _parse_users(enum4linux_output: str) -> list[str]:
    """Extract usernames from enum4linux-ng output."""
    users: list[str] = []
    for line in enum4linux_output.splitlines():
        match = re.search(r"user:\[([^\]]+)\]", line, re.IGNORECASE)
        if match:
            users.append(match.group(1))
    return users


async def run(ctx: ReconContext) -> None:
    """Run SMB enumeration with enum4linux-ng and netexec."""
    config = ctx.config
    out_dir = config.project_dir / "smb"
    out_dir.mkdir(parents=True, exist_ok=True)

    enum_out = out_dir / "enum4linux.txt"
    nxc_out = out_dir / "nxc_shares.txt"

    # enum4linux-ng
    enum_cmd = ["enum4linux-ng", "-A", config.ip]
    if config.credentials:
        enum_cmd.extend(["-u", config.credentials[0], "-p", config.credentials[1]])

    enum_result = await executor.run(enum_cmd, timeout=120, output_file=enum_out)

    if enum_result.returncode == 127:
        ctx.errors.append("enum4linux-ng not found")
        enum_output = ""
    else:
        enum_output = enum_result.stdout

    # netexec (nxc)
    nxc_cmd = ["nxc", "smb", config.ip, "--shares"]
    if config.credentials:
        nxc_cmd.extend(["-u", config.credentials[0], "-p", config.credentials[1]])

    nxc_result = await executor.run(nxc_cmd, timeout=60, output_file=nxc_out)

    if nxc_result.returncode == 127:
        ctx.errors.append("nxc (netexec) not found")
        nxc_output = ""
    else:
        nxc_output = nxc_result.stdout

    shares = _parse_shares(nxc_output)
    users = _parse_users(enum_output)

    ctx.smb = SmbResult(
        shares=shares,
        users=users,
        enum4linux_output=enum_output,
        nxc_output=nxc_output,
    )

    if shares:
        print_success(f"SMB shares found: {len(shares)}")
        for s in shares:
            print_finding("info", f"Share: {s}")

    if users:
        print_success(f"Users found: {len(users)}")
        for u in users:
            print_finding("info", f"User: {u}")

    if not shares and not users:
        print_info("SMB enumeration: no shares or users found")
