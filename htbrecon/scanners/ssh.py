from __future__ import annotations

from htbrecon import executor
from htbrecon.console import print_finding, print_info, print_success, print_warning
from htbrecon.models import ReconContext, SshResult


def _parse_accessible(output: str) -> bool:
    """Return True if nxc ssh output indicates successful authentication."""
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
    out_dir = config.project_dir / "ssh"
    out_dir.mkdir(parents=True, exist_ok=True)

    assert config.credentials is not None
    user, password = config.credentials

    # Prefer 22, fallback to any other detected SSH port
    open_ports = {p.port for p in ctx.open_ports}
    port = 22 if 22 in open_ports else next(
        (p for p in open_ports if p in (2222, 22222)), 22
    )

    print_info(f"Checking SSH access on port {port}...")

    cmd = ["nxc", "ssh", config.ip, "-u", user, "-p", password]
    if port != 22:
        cmd.extend(["--port", str(port)])

    result = await executor.run(cmd, timeout=60, output_file=out_dir / "ssh.txt")

    if result.returncode == 127:
        ctx.errors.append("nxc not found — skipping SSH check")
        print_warning("nxc not found")
        return

    accessible = _parse_accessible(result.stdout)

    ctx.ssh = SshResult(
        accessible=accessible,
        port=port,
        raw_output=result.stdout,
    )

    if accessible:
        print_success(f"SSH access GRANTED on port {port} as {user}")
        print_finding("critical", f"SSH: {user}:{password} → port {port}")
    else:
        print_info(f"SSH access denied on port {port} ({user})")
