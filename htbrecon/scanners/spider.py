from __future__ import annotations

import json
from pathlib import Path

from htbrecon import executor
from htbrecon.console import print_finding, print_info, print_success, print_warning
from htbrecon.models import ReconContext, SpiderResult

_INTERESTING_EXTS = {
    ".ps1", ".bat", ".cmd", ".xml", ".config", ".conf", ".ini", ".cfg",
    ".txt", ".kdbx", ".pfx", ".pem", ".key", ".xlsx", ".docx",
}


def _parse_spider_json(json_path: Path) -> tuple[list[str], list[str]]:
    """Parse spider_plus JSON output into (interesting_files, shares_spidered)."""
    try:
        data = json.loads(json_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return [], []

    interesting: list[str] = []
    shares: list[str] = list(data.keys())

    for share, files in data.items():
        for filepath in files:
            suffix = Path(filepath).suffix.lower()
            if suffix in _INTERESTING_EXTS:
                interesting.append(f"{share}/{filepath}")

    return sorted(interesting), shares


async def run(ctx: ReconContext) -> None:
    config = ctx.config
    out_dir = config.project_dir / "spider"
    out_dir.mkdir(parents=True, exist_ok=True)

    print_info("Spidering SMB shares with spider_plus...")

    cmd = ["nxc", "smb", config.ip]
    if config.credentials:
        user, password = config.credentials
        cmd.extend(["-u", user, "-p", password])
    else:
        cmd.extend(["-u", "", "-p", ""])

    cmd.extend(["-M", "spider_plus", "-o", f"OUTPUT_FOLDER={out_dir}"])

    result = await executor.run(cmd, timeout=120, output_file=out_dir / "spider_stdout.txt")

    if result.returncode == 127:
        ctx.errors.append("nxc not found — skipping SMB spider")
        print_warning("nxc not found")
        return

    # spider_plus saves JSON as <ip>.json in OUTPUT_FOLDER
    json_files = list(out_dir.glob("*.json"))
    interesting_files: list[str] = []
    shares_spidered: list[str] = []

    for jf in json_files:
        files, shares = _parse_spider_json(jf)
        interesting_files.extend(files)
        shares_spidered.extend(s for s in shares if s not in shares_spidered)

    ctx.spider = SpiderResult(
        interesting_files=sorted(interesting_files),
        shares_spidered=shares_spidered,
        output_dir=str(out_dir),
        raw_output=result.stdout,
    )

    if interesting_files:
        print_success(f"Spider: {len(interesting_files)} interesting file(s) found")
        for f in interesting_files[:10]:
            print_finding("info", f"File: {f}")
        if len(interesting_files) > 10:
            print_info(f"... and {len(interesting_files) - 10} more (see report)")
    else:
        print_info("Spider: no interesting files found")
