from __future__ import annotations

import json
import re
from pathlib import Path

from htbrecon import executor
from htbrecon.console import print_finding, print_info, print_success, print_warning
from htbrecon.models import BloodHoundResult, ReconContext


def _base_dn_to_domain(base_dn: str) -> str:
    """Convert 'DC=sevenkingdoms,DC=local' → 'sevenkingdoms.local'."""
    parts = re.findall(r"DC=([^,]+)", base_dn, re.IGNORECASE)
    return ".".join(parts).lower() if parts else ""


def _parse_results(json_files: list[Path]) -> BloodHoundResult:
    """Parse bloodhound-python JSON files and extract high-value AD targets."""
    if not json_files:
        return BloodHoundResult()

    users_count = groups_count = computers_count = 0
    ad_domain = func_level = ""
    admin_users: list[str] = []
    spn_users: list[str] = []
    asrep_users: list[str] = []
    unconstrained_users: list[str] = []
    getchanges: set[str] = set()
    getchangesall: set[str] = set()

    for jf in json_files:
        try:
            data = json.loads(jf.read_text(encoding="utf-8"))
        except Exception:
            continue

        meta = data.get("meta", {})
        obj_type = meta.get("type", "")

        if obj_type == "domains":
            for d in data.get("data", []):
                props = d.get("Properties", {})
                ad_domain = props.get("domain", "")
                func_level = str(props.get("functionallevel", ""))
                for ace in d.get("Aces", []):
                    right = ace.get("RightName", "")
                    sid = ace.get("PrincipalSID", "")
                    if right == "GetChanges":
                        getchanges.add(sid)
                    elif right == "GetChangesAll":
                        getchangesall.add(sid)

        elif obj_type == "users":
            users_count = meta.get("count", 0)
            for u in data.get("data", []):
                props = u.get("Properties", {})
                if not props.get("enabled", False):
                    continue
                name = props.get("name", "").split("@")[0]
                if not name:
                    continue
                if props.get("admincount"):
                    admin_users.append(name)
                if props.get("hasspn") and name.upper() != "KRBTGT":
                    spn_users.append(name)
                if props.get("dontreqpreauth"):
                    asrep_users.append(name)
                if props.get("unconstraineddelegation"):
                    unconstrained_users.append(name)

        elif obj_type == "groups":
            groups_count = meta.get("count", 0)

        elif obj_type == "computers":
            computers_count = meta.get("count", 0)

    dcsync_principals = sorted(getchanges & getchangesall)

    lines = [f"BloodHound DCOnly — {ad_domain} (FL: {func_level})"]
    lines.append(f"Objects: {users_count} users, {groups_count} groups, {computers_count} computers")
    if admin_users:
        lines.append(f"Admin users (admincount=1): {', '.join(admin_users)}")
    if spn_users:
        lines.append(f"Kerberoastable (SPN): {', '.join(spn_users)}")
    if asrep_users:
        lines.append(f"ASREPRoastable (no preauth): {', '.join(asrep_users)}")
    if unconstrained_users:
        lines.append(f"Unconstrained delegation: {', '.join(unconstrained_users)}")
    if dcsync_principals:
        lines.append(f"DCSync capable (GetChanges+GetChangesAll): {', '.join(dcsync_principals)}")

    return BloodHoundResult(
        ad_domain=ad_domain,
        func_level=func_level,
        users_count=users_count,
        groups_count=groups_count,
        computers_count=computers_count,
        admin_users=admin_users,
        spn_users=spn_users,
        asrep_users=asrep_users,
        unconstrained_users=unconstrained_users,
        dcsync_principals=dcsync_principals,
        summary_text="\n".join(lines),
    )


async def run(ctx: ReconContext) -> None:
    """Run BloodHound DCOnly collection when credentials are available."""
    if not ctx.config.credentials:
        return
    if not ctx.ldap or not ctx.ldap.base_dn:
        print_info("BloodHound: skipped (no LDAP base DN)")
        return

    config = ctx.config
    out_dir = config.project_dir / "bloodhound"
    out_dir.mkdir(parents=True, exist_ok=True)

    ad_domain = _base_dn_to_domain(ctx.ldap.base_dn)
    if not ad_domain:
        print_info("BloodHound: skipped (could not derive AD domain from base DN)")
        return

    user, password = config.credentials

    cmd = [
        "bloodhound-python",
        "-c", "DCOnly",
        "-d", ad_domain,
        "-u", user,
        "-p", password,
        "-ns", config.ip,
        "--auth-method", "ntlm",
        "-op", "htbrecon",
    ]

    result = await executor.run(cmd, timeout=300, cwd=out_dir, output_file=out_dir / "bloodhound.log")

    if result.returncode == 127:
        ctx.errors.append("bloodhound-python not found")
        return

    # Don't rely on returncode: bash -lc may exit non-zero due to Exegol alias
    # file syntax errors even when bloodhound-python ran successfully.
    # Instead, check whether JSON output files were actually produced.
    json_files = list(out_dir.glob("*.json"))
    if not json_files:
        ctx.errors.append(f"bloodhound-python produced no output (rc={result.returncode})")
        print_warning(f"BloodHound: no JSON files produced — {result.stderr[:150]}")
        return

    bh = _parse_results(json_files)
    ctx.bloodhound = bh

    if bh.users_count > 0:
        print_success(
            f"BloodHound: {bh.users_count} users, {bh.groups_count} groups, {bh.computers_count} computers"
        )
    if bh.admin_users:
        print_finding("info", f"Admin users: {', '.join(bh.admin_users)}")
    if bh.spn_users:
        print_finding("high", f"Kerberoastable (SPN): {', '.join(bh.spn_users)}")
    if bh.asrep_users:
        print_finding("high", f"ASREPRoastable: {', '.join(bh.asrep_users)}")
    if bh.unconstrained_users:
        print_finding("high", f"Unconstrained delegation: {', '.join(bh.unconstrained_users)}")
    if bh.dcsync_principals:
        print_finding("high", f"DCSync capable: {', '.join(bh.dcsync_principals)}")
    if bh.users_count == 0:
        print_info("BloodHound: no data parsed (check bloodhound/bloodhound.log)")
