from __future__ import annotations

import json

from htbrecon import executor
from htbrecon.console import print_info, print_success
from htbrecon.hosts import add_host
from htbrecon.models import ReconContext


async def _get_baseline_size(base_url: str, hostname: str) -> int | None:
    """Get the response size for a non-existent subdomain to use as filter."""
    result = await executor.run(
        [
            "curl",
            "-s",
            "-k",
            "-o",
            "/dev/null",
            "-w",
            "%{size_download}",
            "-H",
            f"Host: htbrecon-baseline-nonexistent.{hostname}",
            base_url,
        ],
        timeout=10,
    )
    if result.returncode == 0 and result.stdout.strip().isdigit():
        return int(result.stdout.strip())
    return None


async def run(ctx: ReconContext) -> None:
    """Enumerate subdomains using ffuf with vhost fuzzing."""
    config = ctx.config
    out_dir = config.project_dir / "ffuf"
    out_dir.mkdir(parents=True, exist_ok=True)

    if not ctx.http_ports:
        print_info("No HTTP ports — skipping subdomain enumeration")
        return

    # Pick the best HTTP port for vhost fuzzing (prefer 80, then 443, then first)
    web_urls = ctx.web_urls()
    if not web_urls:
        print_info("No web URLs — skipping subdomain enumeration")
        return
    # Prefer port 80, then 443, then first available
    _, target_url = web_urls[0]
    for pi, url in web_urls:
        if pi.port == 80:
            target_url = url
            break
        if pi.port == 443:
            target_url = url

    wordlist = config.subdomain_wordlist
    if not wordlist.exists():
        ctx.errors.append(f"Subdomain wordlist not found: {wordlist}")
        return

    baseline_size = await _get_baseline_size(target_url, config.hostname)

    out_file = out_dir / "subdomains.json"

    cmd = [
        "ffuf",
        "-u",
        target_url,
        "-H",
        f"Host: FUZZ.{config.hostname}",
        "-w",
        str(wordlist),
        "-mc",
        "200,301,302,401,403",
        "-ac",
        "-o",
        str(out_file),
        "-of",
        "json",
        "-t",
        "25",
    ]

    if baseline_size is not None and baseline_size > 0:
        cmd.extend(["-fs", str(baseline_size)])

    result = await executor.run(cmd, timeout=300)

    if result.returncode == 127:
        ctx.errors.append("ffuf not found")
        return

    found: list[str] = []
    if out_file.exists():
        try:
            data = json.loads(out_file.read_text(encoding="utf-8"))
            for entry in data.get("results", []):
                subdomain = f"{entry['input']['FUZZ']}.{config.hostname}"
                found.append(subdomain)
        except (json.JSONDecodeError, KeyError):
            pass

    ctx.subdomains = found

    if found:
        print_success(f"Found {len(found)} subdomain(s):")
        for sub in found:
            print_success(f"  {sub}")
            add_host(config.ip, sub)
    else:
        print_info("No subdomains found")
