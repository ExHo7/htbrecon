from __future__ import annotations

import re
from pathlib import Path
from typing import TYPE_CHECKING

from htbrecon import executor
from htbrecon.console import print_finding, print_info, print_success, print_warning
from htbrecon.models import ReconContext, WhatWebResult

if TYPE_CHECKING:
    from htbrecon.models import PortInfo


def _parse_whatweb(output: str) -> list[str]:
    """Extract technology names from whatweb output."""
    techs: list[str] = []
    for line in output.splitlines():
        if not line.strip():
            continue
        # WhatWeb outputs comma-separated plugins in brackets
        for part in line.split(","):
            part = part.strip()
            if "[" in part:
                name = part.split("[")[0].strip()
                # Skip URL status lines like "http://host [200 OK]"
                if name and not name.startswith("http"):
                    techs.append(part.strip())
            elif part and not part.startswith("http"):
                techs.append(part.strip())
    return techs


def _detects_https_redirect(output: str) -> bool:
    """Check if WhatWeb output shows a redirect from HTTP to HTTPS."""
    # WhatWeb shows lines like: "http://x [301 Moved Permanently]" then "https://x [200 OK]"
    lines = output.splitlines()
    for line in lines:
        if re.search(r"\[30[1237]\s", line) and "RedirectLocation[https://" in line:
            return True
    # Also check if output contains both http 301 and a subsequent https 200
    has_301 = any("301" in l and "http://" in l for l in lines)
    has_https_200 = any("200" in l and "https://" in l for l in lines)
    return has_301 and has_https_200


async def _scan_url(
    ctx: ReconContext, url: str, port_info: "PortInfo", out_file: "Path"
) -> bool:
    """Scan a single URL with WhatWeb. Returns False if whatweb is missing."""
    cmd = ["whatweb", "-a", "3", "--color=never", url]
    result = await executor.run(cmd, timeout=120, output_file=out_file)

    if result.returncode == 127:
        ctx.errors.append("whatweb not found")
        return False

    # Detect HTTP→HTTPS redirects (e.g. "301 Moved" followed by "https://")
    if url.startswith("http://") and _detects_https_redirect(result.stdout):
        print_warning(
            f"Port {port_info.port} redirects to HTTPS — switching scheme"
        )
        ctx.https_redirect_ports.add(port_info.port)

    techs = _parse_whatweb(result.stdout)
    ctx.whatweb.append(
        WhatWebResult(url=url, technologies=techs, raw_output=result.stdout)
    )

    if techs:
        print_success(f"WhatWeb {url}:")
        for tech in techs[:10]:
            print_finding("info", tech)
    else:
        print_info(f"WhatWeb {url}: no technologies identified")
    return True


async def run(ctx: ReconContext) -> None:
    """Run WhatWeb on each HTTP port for the main hostname."""
    out_dir = ctx.config.project_dir / "web"
    out_dir.mkdir(parents=True, exist_ok=True)

    for port_info, url in ctx.web_urls():
        out_file = out_dir / f"whatweb_{port_info.port}.txt"
        if not await _scan_url(ctx, url, port_info, out_file):
            return


async def run_subdomains(ctx: ReconContext) -> None:
    """Run WhatWeb on each discovered subdomain."""
    out_dir = ctx.config.project_dir / "web"
    out_dir.mkdir(parents=True, exist_ok=True)

    for subdomain in ctx.subdomains:
        for port_info, url in ctx.web_urls(subdomain):
            safe_name = subdomain.replace(".", "_")
            out_file = out_dir / f"whatweb_{safe_name}_{port_info.port}.txt"
            if not await _scan_url(ctx, url, port_info, out_file):
                return
