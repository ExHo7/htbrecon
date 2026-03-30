from __future__ import annotations

import asyncio

from htbrecon.console import console, print_error, print_phase, print_success, print_warning, setup_logging
from htbrecon.hosts import add_host
from htbrecon.models import ReconConfig, ReconContext
from htbrecon.scanners import (
    ffuf_dirs,
    ffuf_subdomains,
    ldap,
    nmap,
    nuclei,
    smb,
    vulnx,
    whatweb,
)


def _setup_dirs(config: ReconConfig) -> None:
    """Create project directory structure."""
    for subdir in ("nmap", "web", "ffuf", "nuclei", "smb", "ldap", "vulnx"):
        (config.project_dir / subdir).mkdir(parents=True, exist_ok=True)


async def run_pipeline(config: ReconConfig) -> ReconContext:
    """Execute the fast reconnaissance pipeline."""
    ctx = ReconContext(config)

    setup_logging(config.project_dir / "htbrecon.log", debug=config.debug)

    # ── Phase 1: Setup ──────────────────────────────────────────
    print_phase("Setup")
    _setup_dirs(config)
    print_success(f"Project directory: {config.project_dir}")

    if not add_host(config.ip, config.hostname):
        print_error("Failed to update /etc/hosts — continuing anyway")

    # ── Phase 2: Port Discovery ─────────────────────────────────
    print_phase("Port Discovery")
    with console.status("[bold cyan]Running nmap fast port scan...", spinner="dots"):
        await nmap.run(ctx)

    if not ctx.open_ports:
        print_error("No open ports found — reconnaissance may be limited")

    # ── Phase 3: Service Enumeration (parallel) ─────────────────
    print_phase("Service Enumeration")
    phase3_tasks: list = []

    if ctx.http_ports:
        phase3_tasks.append(("WhatWeb", whatweb.run(ctx)))
    if ctx.has_smb:
        phase3_tasks.append(("SMB", smb.run(ctx)))
    if ctx.has_ldap:
        phase3_tasks.append(("LDAP", ldap.run(ctx)))

    if phase3_tasks:
        names = ", ".join(name for name, _ in phase3_tasks)
        with console.status(f"[bold cyan]Running: {names}...", spinner="dots"):
            results = await asyncio.gather(
                *(task for _, task in phase3_tasks), return_exceptions=True
            )
        for (name, _), result in zip(phase3_tasks, results):
            if isinstance(result, Exception):
                ctx.errors.append(f"{name} scanner error: {result}")
                print_error(f"{name}: {result}")
    else:
        print_success("No services to enumerate in this phase")

    # ── Phase 4: Web Recon ──────────────────────────────────────
    if ctx.http_ports:
        print_phase("Web Reconnaissance")

        with console.status(
            "[bold cyan]Enumerating subdomains with ffuf...", spinner="dots"
        ):
            await ffuf_subdomains.run(ctx)

        # Run WhatWeb on newly discovered subdomains
        if ctx.subdomains:
            with console.status(
                "[bold cyan]Running WhatWeb on subdomains...", spinner="dots"
            ):
                await whatweb.run_subdomains(ctx)

        phase4_tasks = []
        phase4_tasks.append(("Directory scan", ffuf_dirs.run(ctx)))
        phase4_tasks.append(("Nuclei scan", nuclei.run(ctx)))

        names = ", ".join(name for name, _ in phase4_tasks)
        with console.status(f"[bold cyan]Running: {names}...", spinner="dots"):
            results = await asyncio.gather(
                *(task for _, task in phase4_tasks), return_exceptions=True
            )
        for (name, _), result in zip(phase4_tasks, results):
            if isinstance(result, Exception):
                ctx.errors.append(f"{name} error: {result}")
                print_error(f"{name}: {result}")
    else:
        print_phase("Web Reconnaissance (skipped — no HTTP ports)")

    # ── Phase 4b: CVE Intelligence (vulnx) ─────────────────────
    from htbrecon.setup import check_vulnx

    print_phase("CVE Intelligence")
    if not check_vulnx():
        print_warning(
            "vulnx not found — skipping CVE intelligence. "
            "Run [bold]htbrecon setup[/] to install it."
        )
    else:
        with console.status("[bold cyan]Searching CVEs for detected technologies...", spinner="dots"):
            try:
                await vulnx.run_vulnx(ctx)
            except Exception as e:
                ctx.errors.append(f"vulnx error: {e}")
                print_error(f"vulnx failed: {e}")

    # ── Phase 5: AI Analysis ────────────────────────────────────
    if not config.skip_ai:
        print_phase("AI Analysis")
        with console.status("[bold cyan]Analyzing findings with Claude...", spinner="dots"):
            from htbrecon.ai import analyze

            try:
                ctx.ai_analysis = await analyze(ctx)
                if ctx.ai_analysis:
                    print_success("AI analysis complete")
            except Exception as e:
                ctx.errors.append(f"AI analysis error: {e}")
                print_error(f"AI analysis failed: {e}")
    else:
        print_phase("AI Analysis (skipped)")

    # ── Phase 6: Report Generation ──────────────────────────────
    print_phase("Report Generation")
    from htbrecon.report import generate

    report_path = generate(ctx)
    print_success(f"Report saved to: {report_path}")

    # Final summary
    console.print()
    if ctx.errors:
        print_phase(f"Completed with {len(ctx.errors)} warning(s)/error(s)")
        for err in ctx.errors:
            print_error(err)
    else:
        print_phase("Reconnaissance complete!")

    return ctx
