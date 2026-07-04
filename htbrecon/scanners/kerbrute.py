from __future__ import annotations

import re

from htbrecon import executor, paths
from htbrecon.console import print_finding, print_info, print_success, print_warning
from htbrecon.models import KerbruteResult, ReconContext

_VALID_RE = re.compile(r"\[\+\] VALID USERNAME:\s+(\S+?)@", re.IGNORECASE)
_TESTED_RE = re.compile(r"Tested (\d+) usernames", re.IGNORECASE)


async def run(ctx: ReconContext) -> None:
    config = ctx.config
    out_dir = config.project_dir / "kerbrute"
    out_dir.mkdir(parents=True, exist_ok=True)
    log_file = out_dir / "kerbrute.txt"

    wordlist = paths.resolve_wordlist("usernames")
    if wordlist is None:
        ctx.errors.append(paths.wordlist_hint("usernames"))
        print_warning("Kerbrute: username wordlist not found — skipping")
        return

    print_info("Starting Kerbrute user enumeration...")

    cmd = [
        "kerbrute",
        "userenum",
        "--dc", config.ip,
        "-d", config.hostname,
        "-o", str(log_file),
        "--safe",
        str(wordlist),
    ]

    result = await executor.run(cmd, timeout=120, output_file=out_dir / "kerbrute_stdout.txt")

    if result.returncode == 127:
        ctx.errors.append("kerbrute not found — skipping Kerberos user enumeration")
        print_warning("kerbrute not found")
        return

    output = result.stdout + result.stderr

    valid_users = sorted({m.group(1) for m in _VALID_RE.finditer(output)})

    tested_count = 0
    m = _TESTED_RE.search(output)
    if m:
        tested_count = int(m.group(1))

    ctx.kerbrute = KerbruteResult(
        valid_users=valid_users,
        tested_count=tested_count,
        raw_output=output,
    )

    if valid_users:
        print_success(f"Kerbrute: {len(valid_users)} valid user(s) found")
        for u in valid_users:
            print_finding("info", f"Valid user: {u}")
    else:
        print_info(f"Kerbrute: no valid users found ({tested_count} tested)")
