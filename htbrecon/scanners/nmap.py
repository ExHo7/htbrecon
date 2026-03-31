from __future__ import annotations

import re

from htbrecon import executor
from htbrecon.console import print_info, print_ports_table, print_success
from htbrecon.models import NmapResult, PortInfo, ReconContext

PORT_RE = re.compile(
    r"^(\d+)/(tcp|udp)\s+(open|filtered|closed)\s+(\S+)\s*(.*?)$", re.MULTILINE
)
PORT_EMBEDDED_RE = re.compile(
    r"^(\d+)/(tcp|udp)\s+(open|filtered|closed)\s+(\S+)\s*(.*)", re.IGNORECASE
)


def _parse_nmap_output(output: str) -> list[PortInfo]:
    ports: list[PortInfo] = []
    for m in PORT_RE.finditer(output):
        version = m.group(5).strip()
        embedded = PORT_EMBEDDED_RE.match(version)
        if embedded:
            ports.append(PortInfo(
                port=int(m.group(1)),
                protocol=m.group(2),
                state=m.group(3),
                service=m.group(4),
                version="",
            ))
            ports.append(PortInfo(
                port=int(embedded.group(1)),
                protocol=embedded.group(2),
                state=embedded.group(3),
                service=embedded.group(4),
                version=embedded.group(5).strip(),
            ))
        else:
            ports.append(PortInfo(
                port=int(m.group(1)),
                protocol=m.group(2),
                state=m.group(3),
                service=m.group(4),
                version=version,
            ))
    return ports


async def run(ctx: ReconContext) -> None:
    """Run port scan — RustScan (fast, full range) with nmap fallback."""
    config = ctx.config
    out_dir = config.project_dir / "nmap"
    out_dir.mkdir(parents=True, exist_ok=True)

    nmap_file = out_dir / "full_scan.nmap"
    xml_file = out_dir / "full_scan.xml"

    # ── Try RustScan first (discovers all ports then feeds them to nmap -sV) ──
    rustscan_cmd = [
        "rustscan",
        "--addresses", config.ip,
        "--range", "1-65535",
        "--ulimit", "5000",
        "--",
        "-Pn", "-sV",
        "-oN", str(nmap_file),
        "-oX", str(xml_file),
    ]
    result = await executor.run(rustscan_cmd, timeout=600)

    if result.returncode == 127:
        # RustScan not available — fall back to nmap
        print_info("rustscan not found — falling back to nmap")
        nmap_cmd = [
            "nmap",
            "-F", "-sV", "-Pn",
            "-oN", str(nmap_file),
            "-oX", str(xml_file),
            config.ip,
        ]
        result = await executor.run(nmap_cmd, timeout=600)
        if result.returncode == 127:
            ctx.errors.append("nmap not found — install nmap or rustscan, or run inside Exegol")
            return

    if result.timed_out:
        ctx.errors.append("port scan timed out after 600s")

    output = nmap_file.read_text(encoding="utf-8") if nmap_file.exists() else result.stdout
    ports = _parse_nmap_output(output)

    ctx.nmap = NmapResult(ports=ports, raw_output=output)

    open_ports = [p for p in ports if p.state == "open"]
    if open_ports:
        print_success(f"Found {len(open_ports)} open port(s)")
        print_ports_table(open_ports)
    else:
        print_info("No open ports found")

    if result.returncode not in (0,) and not result.timed_out:
        ctx.errors.append(f"scan exited with code {result.returncode}: {result.stderr[:200]}")
