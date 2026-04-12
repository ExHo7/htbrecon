from __future__ import annotations

import re
from pathlib import Path

from htbrecon import executor
from htbrecon.console import print_finding, print_info, print_success, print_warning
from htbrecon.models import KatanaResult, ReconContext

# Extensions worth highlighting in console output
_INTERESTING_EXTS = {
    ".js", ".json", ".xml", ".config", ".conf", ".ini", ".cfg", ".env",
    ".txt", ".bak", ".sql", ".log", ".key", ".pem", ".pfx", ".zip", ".tar",
    ".php", ".py", ".rb", ".sh", ".bash",
}

_INTERESTING_PATTERNS = re.compile(
    r"(api|graphql|admin|login|auth|token|key|secret|config|upload|backup|debug|swagger|openapi)",
    re.IGNORECASE,
)


def _classify(url: str) -> tuple[bool, bool]:
    """Return (is_interesting_ext, is_interesting_path)."""
    path = url.split("?")[0]
    ext = Path(path).suffix.lower()
    return ext in _INTERESTING_EXTS, bool(_INTERESTING_PATTERNS.search(path))


async def run(ctx: ReconContext) -> None:
    """Crawl all web targets with katana."""
    config = ctx.config
    out_dir = config.project_dir / "katana"
    out_dir.mkdir(parents=True, exist_ok=True)

    if not ctx.http_ports:
        print_info("No HTTP ports — skipping katana crawl")
        return

    # Build target list: all hostnames x all HTTP ports
    target_urls: list[str] = []
    seen: set[str] = set()
    for hostname in ctx.all_hostnames:
        for _, url in ctx.web_urls(hostname):
            if url not in seen:
                seen.add(url)
                target_urls.append(url)

    if not target_urls:
        print_info("No web URLs — skipping katana crawl")
        return

    targets_file = out_dir / "targets.txt"
    targets_file.write_text("\n".join(target_urls), encoding="utf-8")
    out_file = out_dir / "katana.txt"

    print_info(f"Katana: crawling {len(target_urls)} target(s)...")

    cmd = [
        "katana",
        "-list", str(targets_file),
        "-jsl",          # JS link extraction
        "-jc",           # JS crawling
        "-aff",          # Crawl all file formats
        "-fr", "assets", # Filter regex: skip /assets paths
        "-o", str(out_file),
        "-silent",
    ]

    result = await executor.run(cmd, timeout=300)

    if result.returncode == 127:
        ctx.errors.append("katana not found — skipping web crawl")
        print_warning("katana not found")
        return

    if result.timed_out:
        ctx.errors.append("katana timed out after 300s (partial results saved)")

    urls_found: list[str] = []
    interesting: list[str] = []

    if out_file.exists():
        for line in out_file.read_text(encoding="utf-8").splitlines():
            url = line.strip()
            if not url:
                continue
            urls_found.append(url)
            is_ext, is_path = _classify(url)
            if is_ext or is_path:
                interesting.append(url)

    ctx.katana = KatanaResult(
        urls_found=urls_found,
        interesting_urls=interesting,
        output_file=str(out_file),
    )

    if interesting:
        print_success(f"Katana: {len(urls_found)} URL(s) crawled, {len(interesting)} interesting")
        for u in interesting[:15]:
            print_finding("katana", u)
        if len(interesting) > 15:
            print_info(f"  ... and {len(interesting) - 15} more (see {out_file})")
    elif urls_found:
        print_info(f"Katana: {len(urls_found)} URL(s) crawled, nothing particularly interesting")
    else:
        print_info("Katana: no URLs found")
