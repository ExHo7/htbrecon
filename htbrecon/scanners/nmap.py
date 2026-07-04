from __future__ import annotations

import re
from pathlib import Path
from xml.etree import ElementTree as ET

from htbrecon import executor
from htbrecon.console import logger, print_info, print_ports_table, print_success
from htbrecon.models import NmapResult, PortInfo, ReconContext

PORT_RE = re.compile(
    r"^(\d+)/(tcp|udp)\s+(open|filtered|closed)\s+(\S+)\s*(.*?)$", re.MULTILINE
)
PORT_EMBEDDED_RE = re.compile(
    r"^(\d+)/(tcp|udp)\s+(open|filtered|closed)\s+(\S+)\s*(.*)", re.IGNORECASE
)


def _parse_nmap_xml(xml_path: Path) -> list[PortInfo]:
    """Parse nmap -oX output into PortInfo with structured product/version/CPE.

    Preferred over text parsing: nmap's XML carries clean ``product``/``version``
    attributes and ``<cpe>`` entries — exactly the (vendor, product, version)
    data vulnx needs — instead of a lossy display string.
    """
    tree = ET.parse(xml_path)
    root = tree.getroot()
    ports: list[PortInfo] = []
    for port_el in root.iter("port"):
        portid = port_el.get("portid")
        protocol = port_el.get("protocol", "tcp")
        if portid is None:
            continue

        state_el = port_el.find("state")
        state = state_el.get("state", "") if state_el is not None else ""

        svc = port_el.find("service")
        if svc is not None:
            service = svc.get("name", "")
            product = svc.get("product", "")
            ver = svc.get("version", "")
            cpes = [c.text for c in svc.findall("cpe") if c.text]
            # Build a display string compatible with the text parser's `version`
            # field (consumers like is_ssl scan it for "ssl"/"tls").
            display = " ".join(p for p in (product, ver) if p)
            extra = svc.get("extrainfo", "")
            if extra:
                display = f"{display} ({extra})".strip()
            if svc.get("tunnel") == "ssl" and "ssl" not in display.lower():
                display = f"{display} ssl".strip()
        else:
            service = product = ver = display = ""
            cpes = []

        ports.append(PortInfo(
            port=int(portid),
            protocol=protocol,
            state=state,
            service=service,
            version=display,
            product=product,
            cpe=cpes,
        ))
    return ports


def _parse_nmap_output(output: str) -> list[PortInfo]:
    """Text fallback parser, used only when XML is missing/unreadable."""
    ports: list[PortInfo] = []
    for m in PORT_RE.finditer(output):
        version = m.group(5).strip()
        embedded = PORT_EMBEDDED_RE.match(version)
        if embedded:
            # Two port entries concatenated on one line: the first port's own
            # version is unknown, the embedded match carries the second port.
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
            ctx.errors.append("nmap not found — install nmap or rustscan (htbrecon setup)")
            return

    if result.timed_out:
        ctx.errors.append("port scan timed out after 600s")

    output = nmap_file.read_text(encoding="utf-8") if nmap_file.exists() else result.stdout

    # Prefer the structured XML (clean product/version/CPE); fall back to the
    # lossy text parser only if the XML is missing or unparseable.
    ports: list[PortInfo] = []
    if xml_file.exists():
        try:
            ports = _parse_nmap_xml(xml_file)
        except ET.ParseError as exc:
            logger.warning("nmap XML parse failed (%s) — using text parser", exc)
    if not ports:
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
