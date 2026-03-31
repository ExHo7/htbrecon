from __future__ import annotations

from htbrecon import executor
from htbrecon.console import print_finding, print_info, print_success, print_warning
from htbrecon.models import FtpResult, ReconContext


def _parse_accessible(output: str) -> bool:
    """Return True if nxc ftp output indicates successful authentication."""
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
    out_dir = config.project_dir / "ftp"
    out_dir.mkdir(parents=True, exist_ok=True)

    open_ports = {p.port for p in ctx.open_ports}
    port = 21 if 21 in open_ports else 2121

    print_info(f"Checking FTP access on port {port}...")

    # Step 1: anonymous login (always attempted)
    anon_cmd = ["nxc", "ftp", config.ip, "-u", "anonymous", "-p", "anonymous"]
    if port != 21:
        anon_cmd.extend(["--port", str(port)])

    anon_result = await executor.run(anon_cmd, timeout=60, output_file=out_dir / "ftp_anon.txt")

    if anon_result.returncode == 127:
        ctx.errors.append("nxc not found — skipping FTP check")
        print_warning("nxc not found")
        return

    anonymous = _parse_accessible(anon_result.stdout)
    accessible = anonymous
    raw = anon_result.stdout

    # Step 2: credential-based login (only if anonymous failed and creds available)
    if not anonymous and config.credentials:
        user, password = config.credentials
        cred_cmd = ["nxc", "ftp", config.ip, "-u", user, "-p", password]
        if port != 21:
            cred_cmd.extend(["--port", str(port)])
        cred_result = await executor.run(cred_cmd, timeout=60, output_file=out_dir / "ftp_creds.txt")
        accessible = _parse_accessible(cred_result.stdout)
        raw += cred_result.stdout

    ctx.ftp = FtpResult(
        anonymous=anonymous,
        accessible=accessible,
        port=port,
        raw_output=raw,
    )

    if anonymous:
        print_success(f"FTP anonymous login ALLOWED on port {port}")
        print_finding("critical", f"FTP anonymous login → port {port}")
    elif accessible:
        assert config.credentials is not None
        print_success(f"FTP access GRANTED on port {port} as {config.credentials[0]}")
        print_finding("high", f"FTP: {config.credentials[0]}:{config.credentials[1]} → port {port}")
    else:
        print_info(f"FTP access denied on port {port}")
