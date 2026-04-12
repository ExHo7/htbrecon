from __future__ import annotations

import asyncio
from typing import Optional

import typer

from htbrecon.config import build_config
from htbrecon.console import console, print_banner, print_error

app = typer.Typer(
    name="htbrecon",
    help="HTBRecon — Automated reconnaissance for Hack The Box",
    add_completion=False,
)


@app.command()
def run(
    ip: str = typer.Option(..., "-i", help="Target IP address"),
    name: str = typer.Option(..., "-n", help="Machine name"),
    domain: str = typer.Option("htb", "-d", "--domain", help="TLD / domain suffix (e.g. htb, local, thm)"),
    credentials: Optional[str] = typer.Option(
        None, "--credentials", help="Credentials in user:password format"
    ),
    skip_ai: bool = typer.Option(False, "--skip-ai", help="Skip AI analysis"),
    debug: bool = typer.Option(False, "--debug", help="Enable debug output"),
) -> None:
    """Run automated reconnaissance against a target machine."""
    try:
        config = build_config(
            ip=ip,
            name=name,
            domain=domain,
            credentials=credentials,
            skip_ai=skip_ai,
            debug=debug,
        )
    except ValueError as e:
        print_error(str(e))
        raise typer.Exit(1)

    print_banner(config.name, config.ip)

    from htbrecon.pipeline import run_pipeline

    try:
        asyncio.run(run_pipeline(config))
    except KeyboardInterrupt:
        console.print("\n[warning]Interrupted by user.[/]")
        raise typer.Exit(130)
    except Exception as e:
        print_error(f"Fatal error: {e}")
        raise typer.Exit(1)


@app.command()
def setup(
    force: bool = typer.Option(False, "--force", help="Reinstall even if already present"),
) -> None:
    """Install vulnx binary (CVE intelligence) into /usr/local/bin."""
    from htbrecon.setup import run_setup, run_setup_force

    if force:
        run_setup_force()
    else:
        run_setup()
