from __future__ import annotations

import asyncio

from htbrecon.console import console, print_error, print_phase, print_success, print_warning, setup_logging
from htbrecon.hosts import add_host
from htbrecon.models import ReconConfig, ReconContext
from htbrecon.scanners import (
    api,
    bloodhound,
    eyewitness,
    ffuf_dirs,
    ffuf_subdomains,
    ftp,
    katana,
    kerbrute,
    ldap,
    mssql,
    nmap,
    nuclei,
    smb,
    spider,
    spray,
    ssh,
    vulnx,
    whatweb,
    winrm,
)


def _setup_dirs(config: ReconConfig) -> None:
    """Create project directory structure."""
    for subdir in ("nmap", "web", "ffuf", "nuclei", "smb", "ldap", "vulnx", "spider", "eyewitness", "kerbrute", "winrm", "ssh", "ftp", "mssql", "api", "katana"):
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
    with console.status("[bold cyan]Running deep port scan...🧉", spinner="dots"):
        await nmap.run(ctx)

    if not ctx.open_ports:
        print_error("No open ports found — reconnaissance may be limited")

    # ── Phase 3: Service Enumeration (parallel) ─────────────────
    print_phase("Service Enumeration")
    phase3_tasks: list = []

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

    # ── Phase 3a: SMB Share Spidering ──────────────────────────
    if ctx.has_smb:
        print_phase("SMB Share Spidering")
        with console.status("[bold cyan]Spidering SMB shares...", spinner="dots"):
            try:
                await spider.run(ctx)
            except Exception as e:
                ctx.errors.append(f"Spider error: {e}")
                print_error(f"Spider: {e}")

    # ── Phase 3b: Kerberos User Enumeration ────────────────────
    if ctx.has_kerberos and not ctx.config.credentials:
        print_phase("Kerberos User Enumeration")
        with console.status("[bold cyan]Enumerating users via Kerberos...", spinner="dots"):
            try:
                await kerbrute.run(ctx)
            except Exception as e:
                ctx.errors.append(f"Kerbrute error: {e}")
                print_error(f"Kerbrute: {e}")

    # ── Phase 3c: Active Directory (BloodHound) ─────────────────
    if ctx.has_ldap and ctx.config.credentials:
        print_phase("Active Directory Enumeration")
        with console.status("[bold cyan]Collecting BloodHound data...", spinner="dots"):
            try:
                await bloodhound.run(ctx)
            except Exception as e:
                ctx.errors.append(f"BloodHound error: {e}")
                print_error(f"BloodHound: {e}")

    # ── Phase 3d: Password Spray ────────────────────────────────
    if ctx.has_smb:
        print_phase("Password Spray")
        with console.status("[bold cyan]Testing username=password...", spinner="dots"):
            try:
                await spray.run(ctx)
            except Exception as e:
                ctx.errors.append(f"Spray error: {e}")
                print_error(f"Spray: {e}")

    # ── Phase 3e: WinRM Access Check ───────────────────────────
    if ctx.has_winrm and ctx.config.credentials:
        print_phase("WinRM Access Check")
        with console.status("[bold cyan]Checking WinRM access...", spinner="dots"):
            try:
                await winrm.run(ctx)
            except Exception as e:
                ctx.errors.append(f"WinRM error: {e}")
                print_error(f"WinRM: {e}")

    # ── Phase 3f: SSH Access Check ─────────────────────────────
    if ctx.has_ssh and ctx.config.credentials:
        print_phase("SSH Access Check")
        with console.status("[bold cyan]Checking SSH access...", spinner="dots"):
            try:
                await ssh.run(ctx)
            except Exception as e:
                ctx.errors.append(f"SSH error: {e}")
                print_error(f"SSH: {e}")

    # ── Phase 3g: FTP Access Check ─────────────────────────────
    if ctx.has_ftp:
        print_phase("FTP Access Check")
        with console.status("[bold cyan]Checking FTP access...", spinner="dots"):
            try:
                await ftp.run(ctx)
            except Exception as e:
                ctx.errors.append(f"FTP error: {e}")
                print_error(f"FTP: {e}")

    # ── Phase 3h: MSSQL Enumeration ────────────────────────────
    if ctx.has_mssql and ctx.config.credentials:
        print_phase("MSSQL Enumeration")
        with console.status("[bold cyan]Enumerating MSSQL...", spinner="dots"):
            try:
                await mssql.run(ctx)
            except Exception as e:
                ctx.errors.append(f"MSSQL error: {e}")
                print_error(f"MSSQL: {e}")

    # ── Phase 4: Web Recon ──────────────────────────────────────
    if ctx.http_ports:
        print_phase("Web Reconnaissance")

        with console.status(
            "[bold cyan]Enumerating subdomains with ffuf...", spinner="dots"
        ):
            await ffuf_subdomains.run(ctx)

        # Web enumeration: fingerprint main host + all discovered subdomains
        with console.status(
            "[bold cyan]Running WhatWeb (web enumeration)...", spinner="dots"
        ):
            await whatweb.run(ctx)
            if ctx.subdomains:
                await whatweb.run_subdomains(ctx)

        phase4_tasks = []
        phase4_tasks.append(("Directory scan", ffuf_dirs.run(ctx)))
        phase4_tasks.append(("API scan", api.run(ctx)))
        phase4_tasks.append(("Katana crawl", katana.run(ctx)))
        phase4_tasks.append(("Nuclei scan", nuclei.run(ctx)))
        phase4_tasks.append(("EyeWitness", eyewitness.run(ctx)))

        names = ", ".join(name for name, _ in phase4_tasks)
        with console.status(f"[bold cyan]Running: {names}...🍹", spinner="dots"):
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
        with console.status("[bold cyan]Analyzing findings with AI...🤖", spinner="dots"):
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

    if ctx.config.html:
        from htbrecon.report import generate_html
        import subprocess
        html_path = generate_html(ctx)
        print_success(f"HTML report: {html_path}")
        subprocess.Popen(
            ["firefox", str(html_path)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        print_success("Opening report in Firefox...")

    # Final summary
    console.print()
    if ctx.errors:
        print_phase(f"Completed with {len(ctx.errors)} warning(s)/error(s)")
        for err in ctx.errors:
            print_error(err)
    else:
        print_phase("Reconnaissance complete!")

    return ctx
