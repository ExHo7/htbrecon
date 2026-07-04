from __future__ import annotations

import asyncio
import json
from pathlib import Path

from htbrecon import executor
from htbrecon.console import print_info, print_success
from htbrecon.models import FfufResult, ReconContext


async def _scan_target(
    base_url: str, target: str, wordlist: str, out_file: str
) -> FfufResult:
    """Run ffuf directory scan on a single target."""
    cmd = [
        "ffuf",
        "-u",
        f"{base_url}/FUZZ",
        "-w",
        wordlist,
        "-mc",
        "200,204,301,302,307,401,403",
        "-o",
        out_file,
        "-of",
        "json",
        "-t",
        "25",
        "-recursion",
        "-recursion-depth",
        "2",
        "-ac",
        "-r",
    ]

    result = await executor.run(cmd, timeout=300)

    found: list[str] = []
    try:
        data = json.loads(Path(out_file).read_text(encoding="utf-8"))
        for entry in data.get("results", []):
            path = entry.get("input", {}).get("FUZZ", "")
            status = entry.get("status", 0)
            found.append(f"/{path} [{status}]")
    except (json.JSONDecodeError, FileNotFoundError, KeyError):
        pass

    return FfufResult(target=target, found_items=found, raw_output=result.stdout)


async def run(ctx: ReconContext) -> None:
    """Run directory scanning on main domain and all subdomains."""
    config = ctx.config
    out_dir = config.project_dir / "ffuf"
    out_dir.mkdir(parents=True, exist_ok=True)

    if not ctx.http_ports:
        print_info("No HTTP ports — skipping directory scanning")
        return

    wordlist = config.directory_wordlist
    if wordlist is None or not wordlist.exists():
        from htbrecon import paths
        ctx.errors.append(paths.wordlist_hint("directories"))
        return

    # Build URL for each hostname x each HTTP port
    tasks = []
    for hostname in ctx.all_hostnames:
        for port_info, url in ctx.web_urls(hostname):
            safe_name = hostname.replace(".", "_")
            tasks.append(
                _scan_target(
                    base_url=url,
                    target=f"{hostname}:{port_info.port}",
                    wordlist=str(wordlist),
                    out_file=str(out_dir / f"dirs_{safe_name}_{port_info.port}.json"),
                )
            )

    results = await asyncio.gather(*tasks, return_exceptions=True)

    for r in results:
        if isinstance(r, BaseException):
            ctx.errors.append(f"ffuf dirs error: {r}")
            continue
        ctx.directories.append(r)
        if r.found_items:
            print_success(f"Directories on {r.target}: {len(r.found_items)} found")
            for item in r.found_items[:15]:
                print_info(f"  {item}")
        else:
            print_info(f"No directories found on {r.target}")
