from __future__ import annotations

import asyncio
import re

from htbrecon import executor
from htbrecon.console import print_finding, print_info, print_success
from htbrecon.models import LdapResult, ReconContext


def _extract_base_dn(output: str) -> str:
    """Extract base DN from ldapsearch namingContexts query."""
    for line in output.splitlines():
        match = re.match(r"namingContexts:\s*(.+)", line, re.IGNORECASE)
        if match:
            return match.group(1).strip()
    return ""


def _nxc_msg(output: str) -> list[str]:
    """Strip the nxc prefix columns and return the message part of each line."""
    msgs = []
    for line in output.splitlines():
        # nxc format: "MODULE  IP  PORT  DC  message"
        parts = line.split(None, 4)
        if len(parts) >= 5:
            msgs.append(parts[4])
    return msgs


def _parse_asreproast(content: str) -> list[str]:
    return [l.strip() for l in content.splitlines() if l.strip().startswith("$krb5asrep")]


def _parse_kerberoasting(content: str) -> list[str]:
    return [l.strip() for l in content.splitlines() if l.strip().startswith("$krb5tgs")]


def _parse_adcs(output: str) -> list[str]:
    cas = []
    for msg in _nxc_msg(output):
        if "Found PKI Enrollment Server:" in msg or "Found CN:" in msg:
            cas.append(msg.strip())
    return cas


def _parse_adcs_vulns(output: str) -> list[str]:
    vulns = []
    for msg in _nxc_msg(output):
        m = re.search(r"(ESC\d+)\s*:\s*(.+)", msg)
        if m:
            vulns.append(f"{m.group(1)}: {m.group(2).strip()}")
    return vulns


def _parse_badsuccessor(output: str) -> list[str]:
    dmsas = []
    for msg in _nxc_msg(output):
        if re.search(r"\(S-1-5-", msg):
            dmsas.append(msg.strip())
    return dmsas


_LDAP_DENIED = ("LdapErr:", "Operations error", "Insufficient access", "result: 1")


async def run(ctx: ReconContext) -> None:
    """Run LDAP enumeration with ldapsearch, then nxc when credentials are available."""
    config = ctx.config
    out_dir = config.project_dir / "ldap"
    out_dir.mkdir(parents=True, exist_ok=True)

    # Step 1: discover base DN
    base_cmd = [
        "ldapsearch", "-x", "-H", f"ldap://{config.ip}",
        "-s", "base", "namingContexts",
    ]
    base_result = await executor.run(base_cmd, timeout=30)

    if base_result.returncode == 127:
        ctx.errors.append("ldapsearch not found")
        return

    base_dn = _extract_base_dn(base_result.stdout)
    if not base_dn:
        print_info("LDAP: could not determine base DN")
        ctx.ldap = LdapResult(raw_output=base_result.stdout)
        return

    print_success(f"LDAP base DN: {base_dn}")

    # Step 2: full ldapsearch enumeration
    out_file = out_dir / "ldapsearch.txt"
    enum_cmd = [
        "ldapsearch", "-x", "-H", f"ldap://{config.ip}", "-b", base_dn,
    ]
    if config.credentials:
        enum_cmd.extend(["-D", config.credentials[0], "-w", config.credentials[1]])

    enum_result = await executor.run(enum_cmd, timeout=60, output_file=out_file)

    ldap_access_denied = any(p in enum_result.stdout for p in _LDAP_DENIED)
    entries_count = len(re.findall(r"^dn:\s+", enum_result.stdout, re.MULTILINE))

    # Step 3: nxc credential-based enumeration (parallel)
    asreproast_hashes: list[str] = []
    kerberoast_hashes: list[str] = []
    adcs_cas: list[str] = []
    adcs_vulns: list[str] = []
    badsuccessor_dmsas: list[str] = []

    if config.credentials:
        user, password = config.credentials
        nxc_base = ["nxc", "ldap", config.ip, "-u", user, "-p", password]
        asrep_file = out_dir / "asreproast.txt"
        kerb_file = out_dir / "kerberoasting.txt"

        results = await asyncio.gather(
            executor.run(
                [*nxc_base, "--asreproast", str(asrep_file)],
                timeout=60, output_file=out_dir / "nxc_asreproast.txt",
            ),
            executor.run(
                [*nxc_base, "--kerberoasting", str(kerb_file)],
                timeout=60, output_file=out_dir / "nxc_kerberoasting.txt",
            ),
            executor.run(
                [*nxc_base, "-M", "adcs"],
                timeout=60, output_file=out_dir / "nxc_adcs.txt",
            ),
            executor.run(
                [*nxc_base, "-M", "certipy-find"],
                timeout=120, output_file=out_dir / "nxc_certipy.txt",
            ),
            executor.run(
                [*nxc_base, "-M", "badsuccessor"],
                timeout=60, output_file=out_dir / "nxc_badsuccessor.txt",
            ),
            return_exceptions=True,
        )

        asrep_r, kerb_r, adcs_r, certipy_r, badsucc_r = results

        if not isinstance(asrep_r, Exception):
            try:
                asreproast_hashes = _parse_asreproast(asrep_file.read_text(encoding="utf-8"))
            except OSError:
                pass
        if not isinstance(kerb_r, Exception):
            try:
                kerberoast_hashes = _parse_kerberoasting(kerb_file.read_text(encoding="utf-8"))
            except OSError:
                pass
        if not isinstance(adcs_r, Exception):
            adcs_cas = _parse_adcs(adcs_r.stdout)
        if not isinstance(certipy_r, Exception):
            adcs_vulns = _parse_adcs_vulns(certipy_r.stdout)
        if not isinstance(badsucc_r, Exception):
            badsuccessor_dmsas = _parse_badsuccessor(badsucc_r.stdout)

    # Assemble result
    ctx.ldap = LdapResult(
        raw_output=enum_result.stdout,
        base_dn=base_dn,
        entries_count=entries_count,
        asreproast_hashes=asreproast_hashes,
        kerberoast_hashes=kerberoast_hashes,
        adcs_cas=adcs_cas,
        adcs_vulns=adcs_vulns,
        badsuccessor_dmsas=badsuccessor_dmsas,
    )

    # Print ldapsearch results
    if entries_count > 0:
        print_success(f"LDAP: {entries_count} entries enumerated")
        for line in enum_result.stdout.splitlines():
            if any(kw in line.lower() for kw in ["samaccountname:", "serviceprincipalname:", "memberof:"]):
                print_finding("info", line.strip())
    elif ldap_access_denied:
        print_finding("warn", "LDAP: access denied (anonymous bind insufficient)")
    else:
        print_info("LDAP: no entries found")

    # Print nxc findings
    if asreproast_hashes:
        print_finding("high", f"AS-REP Roastable: {len(asreproast_hashes)} account(s)")
        for h in asreproast_hashes:
            print_finding("info", h[:100] + ("..." if len(h) > 100 else ""))
    if kerberoast_hashes:
        print_finding("high", f"Kerberoastable: {len(kerberoast_hashes)} account(s)")
        for h in kerberoast_hashes:
            print_finding("info", h[:100] + ("..." if len(h) > 100 else ""))
    if adcs_cas:
        print_success(f"ADCS: {len(adcs_cas)} CA(s) found")
        for ca in adcs_cas:
            print_finding("info", ca)
    if adcs_vulns:
        for v in adcs_vulns:
            print_finding("high", f"ADCS vuln: {v}")
    if badsuccessor_dmsas:
        print_finding("info", f"BadSuccessor: {len(badsuccessor_dmsas)} dMSA object(s)")
        for d in badsuccessor_dmsas:
            print_finding("info", d)
