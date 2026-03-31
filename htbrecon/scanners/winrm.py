from __future__ import annotations

from htbrecon import executor
from htbrecon.console import print_finding, print_info, print_success, print_warning
from htbrecon.models import ReconContext, WinRmResult


def _parse_accessible(output: str) -> bool:
    """Return True if nxc winrm output indicates successful authentication."""
    for line in output.splitlines():
        parts = line.split(None, 4)
        if len(parts) < 5:
            continue
        msg = parts[4]
        if "(Pwn3d!)" in msg:
            return True
        if msg.startswith("[+]") and "STATUS_LOGON_FAILURE" not in msg:
            return True
    return False


async def run(ctx: ReconContext) -> None:
    config = ctx.config
    out_dir = config.project_dir / "winrm"
    out_dir.mkdir(parents=True, exist_ok=True)

    user, password = config.credentials  # type: ignore[misc]  # gated in pipeline

    # Prefer 5985 (http), fallback to 5986 (https) if that's the only one open
    port = 5985
    open_ports = {p.port for p in ctx.open_ports}
    if 5985 not in open_ports and 5986 in open_ports:
        port = 5986

    print_info(f"Checking WinRM access on port {port}...")

    cmd = ["nxc", "winrm", config.ip, "-u", user, "-p", password]
    if port != 5985:
        cmd.extend(["--port", str(port)])

    result = await executor.run(cmd, timeout=60, output_file=out_dir / "winrm.txt")

    if result.returncode == 127:
        ctx.errors.append("nxc not found — skipping WinRM check")
        print_warning("nxc not found")
        return

    accessible = _parse_accessible(result.stdout)

    ctx.winrm = WinRmResult(
        accessible=accessible,
        port=port,
        raw_output=result.stdout,
    )

    if accessible:
        print_success(f"WinRM access GRANTED on port {port} as {user}")
        print_finding(f"WinRM: {user}:{password} → port {port}")
    else:
        print_info(f"WinRM access denied on port {port} ({user})")
