from __future__ import annotations

import logging
from pathlib import Path

from rich.console import Console
from rich.logging import RichHandler
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table
from rich.theme import Theme

from htbrecon.models import PortInfo

_theme = Theme(
    {
        "phase": "bold cyan",
        "success": "bold green",
        "warning": "bold yellow",
        "error": "bold red",
        "info": "dim white",
        "critical": "bold white on red",
        "high": "bold red",
        "medium": "bold yellow",
        "low": "bold blue",
    }
)

console = Console(theme=_theme)
logger = logging.getLogger("htbrecon")


def setup_logging(log_file: Path, debug: bool = False) -> None:
    """Configure dual logging: Rich console + file.

    The file always receives DEBUG-level output.
    The console receives DEBUG only when debug=True, INFO otherwise.
    """
    log_file.parent.mkdir(parents=True, exist_ok=True)

    file_handler = logging.FileHandler(log_file, mode="w", encoding="utf-8")
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(
        logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
    )

    rich_handler = RichHandler(
        console=console, show_path=False, show_time=False, markup=True
    )
    rich_handler.setLevel(logging.DEBUG if debug else logging.INFO)

    logger.setLevel(logging.DEBUG)
    logger.addHandler(file_handler)
    logger.addHandler(rich_handler)


_ASCII = r"""
    __  ____________  ____
   / / / /_  __/ __ )/ __ \___  _________  ____
  / /_/ / / / / __  / /_/ / _ \/ ___/ __ \/ __ \
 / __  / / / / /_/ / _, _/  __/ /__/ /_/ / / / /
/_/ /_/ /_/ /_____/_/ |_|\___/\___/\____/_/ /_/ """


def print_banner(name: str, ip: str) -> None:
    banner = f"[bold cyan]{_ASCII}[/]\n[dim]Target: {escape(name)}.htb ({escape(ip)})[/]"
    console.print(Panel(banner, border_style="cyan", expand=False))


def print_phase(title: str) -> None:
    console.print(f"\n[phase]>>> {escape(title)}[/]")


def print_finding(severity: str, text: str) -> None:
    style = severity.lower() if severity.lower() in _theme.styles else "info"
    console.print(f"  [{style}][{severity.upper()}][/] {escape(text)}")


def print_error(text: str) -> None:
    console.print(f"  [error][!] {escape(text)}[/]")
    logger.error(text)


def print_success(text: str) -> None:
    console.print(f"  [success][+] {escape(text)}[/]")


def print_warning(text: str) -> None:
    console.print(f"  [warning][*] {escape(text)}[/]")


def print_info(text: str) -> None:
    console.print(f"  [info][-] {escape(text)}[/]")


def print_ports_table(ports: list[PortInfo]) -> None:
    table = Table(title="Open Ports", border_style="cyan", show_lines=False)
    table.add_column("Port", style="bold")
    table.add_column("Protocol")
    table.add_column("State", style="green")
    table.add_column("Service", style="cyan")
    table.add_column("Version", style="dim")

    for p in sorted(ports, key=lambda x: x.port):
        table.add_row(str(p.port), p.protocol, p.state, p.service, p.version)

    console.print(table)
