from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Optional

import typer

# Load .env (LLM provider, API keys, Ollama model/host) before anything reads
# os.environ. Optional dependency — degrade gracefully if unavailable.
try:
    from dotenv import load_dotenv

    load_dotenv()
    load_dotenv(Path(__file__).resolve().parents[1] / ".env")
except ImportError:
    import sys

    print(
        "htbrecon: python-dotenv not installed — .env will not be loaded "
        "(pip install python-dotenv, or reinstall: pip install -e .)",
        file=sys.stderr,
    )

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
    html: bool = typer.Option(False, "--html", help="Generate HTML report and open in Firefox"),
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
            html=html,
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
    only: Optional[str] = typer.Option(
        None, "--only", help="Comma-separated tool names to install (e.g. ffuf,nuclei,vulnx)"
    ),
    force: bool = typer.Option(False, "--force", help="Reinstall even if already present"),
    system: bool = typer.Option(
        False, "--system", help="Install to /usr/local/bin (needs root) instead of ~/.local/bin"
    ),
) -> None:
    """Install the external pentest tools HTBRecon needs (per architecture)."""
    from htbrecon.setup import run_setup

    tool_list = [t for t in only.split(",") if t.strip()] if only else None
    run_setup(only=tool_list, force=force, system=system)


@app.command()
def doctor() -> None:
    """Diagnose which external tools and wordlists are available on this host."""
    from htbrecon.setup import run_doctor

    raise typer.Exit(run_doctor())
