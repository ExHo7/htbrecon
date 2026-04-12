from __future__ import annotations

import json

from htbrecon import executor
from htbrecon.console import print_finding, print_info, print_success
from htbrecon.models import NucleiFinding, NucleiResult, ReconContext

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


async def run(ctx: ReconContext) -> None:
    """Run nuclei vulnerability scan on all discovered hostnames."""
    config = ctx.config
    out_dir = config.project_dir / "nuclei"
    out_dir.mkdir(parents=True, exist_ok=True)

    if not ctx.http_ports:
        print_info("No HTTP ports — skipping nuclei scan")
        return

    # Build target URLs with correct scheme for each hostname x port
    target_urls: list[str] = []
    for hostname in ctx.all_hostnames:
        for _, url in ctx.web_urls(hostname):
            target_urls.append(url)
    if not target_urls:
        print_info("No web URLs — skipping nuclei scan")
        return

    target_list = out_dir / "targets.txt"
    target_list.write_text("\n".join(target_urls) + "\n", encoding="utf-8")

    out_file = out_dir / "scan.jsonl"

    cmd = [
        "nuclei",
        "-l",
        str(target_list),
        "-jsonl",
        "-o",
        str(out_file),
        "-silent",
        "-severity",
        "low,medium,high,critical",
        "-as",
    ]

    result = await executor.run(cmd, timeout=600)

    if result.returncode == 127:
        ctx.errors.append("nuclei not found")
        return

    findings: list[NucleiFinding] = []
    if out_file.exists():
        for line in out_file.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                data = json.loads(line)
                findings.append(
                    NucleiFinding(
                        template_id=data.get("template-id", data.get("templateID", "")),
                        severity=data.get("info", {}).get("severity", "info"),
                        name=data.get("info", {}).get("name", ""),
                        matched_at=data.get("matched-at", data.get("matched", "")),
                    )
                )
            except (json.JSONDecodeError, KeyError):
                continue

    # Sort by severity
    findings.sort(key=lambda f: SEVERITY_ORDER.get(f.severity, 99))

    ctx.nuclei = NucleiResult(
        target=", ".join(target_urls),
        findings=findings,
        raw_output=result.stdout,
    )

    if findings:
        print_success(f"Nuclei: {len(findings)} finding(s)")
        for f in findings:
            print_finding(f.severity, f"{f.name} @ {f.matched_at}")
    else:
        print_info("Nuclei: no findings")

    if result.timed_out:
        ctx.errors.append("nuclei scan timed out after 600s (partial results saved)")
