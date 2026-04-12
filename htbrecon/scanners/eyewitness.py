from __future__ import annotations

from htbrecon import executor
from htbrecon.console import print_info, print_success, print_warning
from htbrecon.models import EyeWitnessResult, ReconContext


async def run(ctx: ReconContext) -> None:
    config = ctx.config
    out_dir = config.project_dir / "eyewitness"
    out_dir.mkdir(parents=True, exist_ok=True)

    # Build URL list: main hostname + all discovered subdomains
    urls: list[str] = []
    seen: set[str] = set()
    for hostname in ctx.all_hostnames:
        for _, url in ctx.web_urls(hostname=hostname):
            if url not in seen:
                seen.add(url)
                urls.append(url)

    if not urls:
        return

    # urls.txt lives in eyewitness/ ; screenshots go into eyewitness/screenshots/
    # so EyeWitness only clears the screenshots subdir, not the urls file.
    urls_file = (out_dir / "urls.txt").resolve()
    screenshots_dir = (out_dir / "screenshots").resolve()
    urls_file.write_text("\n".join(urls), encoding="utf-8")
    print_info(f"EyeWitness: screenshotting {len(urls)} URL(s)...")

    cmd = [
        "/opt/tools/EyeWitness/venv/bin/python3",
        "/opt/tools/EyeWitness/Python/EyeWitness.py",
        "--web",
        "-f", str(urls_file),
        "-d", str(screenshots_dir),
        "--no-prompt",
        "--timeout", "20",
        "--threads", "2",
    ]

    result = await executor.run(cmd, timeout=300, output_file=out_dir / "eyewitness_stdout.txt")

    if result.returncode == 127 or "No such file" in (result.stderr or ""):
        ctx.errors.append("EyeWitness not found — skipping web screenshots")
        print_warning("EyeWitness not found")
        return

    screenshots_count = len(list(screenshots_dir.glob("screens/*.png"))) if screenshots_dir.exists() else 0

    ctx.eyewitness = EyeWitnessResult(
        screenshots_count=screenshots_count,
        output_dir=str(screenshots_dir),
    )

    if screenshots_count > 0:
        print_success(f"EyeWitness: {screenshots_count} screenshot(s) saved to {screenshots_dir}")
    elif result.returncode != 0:
        err = result.stderr[:200] if result.stderr else "unknown error"
        ctx.errors.append(f"EyeWitness failed (rc={result.returncode}): {err}")
        print_warning(f"EyeWitness failed: {err}")
    else:
        print_info("EyeWitness: no screenshots produced")
