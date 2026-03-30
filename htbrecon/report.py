from __future__ import annotations

from datetime import datetime
from pathlib import Path

from jinja2 import Template

from htbrecon.models import ReconContext

REPORT_TEMPLATE = Template(
    """\
# Reconnaissance Report: {{ config.hostname }}

**Target:** {{ config.ip }} ({{ config.hostname }})
**Date:** {{ date }}
**Tool:** HTBRecon-ng v0.1.0

---

## Port Summary

{% if nmap and nmap.ports %}
| Port | Protocol | State | Service | Version |
|------|----------|-------|---------|---------|
{% for p in nmap.ports if p.state == "open" %}
| {{ p.port }} | {{ p.protocol }} | {{ p.state }} | {{ p.service }} | {{ p.version }} |
{% endfor %}
{% else %}
No open ports discovered.
{% endif %}

---

## Technology Stack (WhatWeb)

{% if whatweb %}
{% for w in whatweb %}
### {{ w.url }}
{% for tech in w.technologies %}
- {{ tech }}
{% endfor %}
{% endfor %}
{% else %}
No web technologies identified.
{% endif %}

---

## Subdomains

{% if subdomains %}
{% for sub in subdomains %}
- {{ sub }}
{% endfor %}
{% else %}
No subdomains discovered.
{% endif %}

---

## Directory Enumeration

{% if directories %}
{% for d in directories %}
### {{ d.target }}
{% if d.found_items %}
{% for item in d.found_items %}
- {{ item }}
{% endfor %}
{% else %}
No directories found.
{% endif %}
{% endfor %}
{% else %}
Directory scanning not performed.
{% endif %}

---

## CVE Intelligence (vulnx)

{% if vulnx and vulnx.findings %}
**Technologies searched:** {{ vulnx.searched_terms | join(", ") }}

| Severity | CVE ID | CVSS | Product | PoC | KEV | Description |
|----------|--------|------|---------|-----|-----|-------------|
{% for f in vulnx.findings %}
| {{ f.severity | upper }} | {{ f.cve_id }} | {{ "%.1f" | format(f.cvss_score) }} | {{ f.product }} | {{ "✓" if f.is_poc else "–" }} | {{ "✓" if f.is_kev else "–" }} | {{ f.description[:100] }}{% if f.description | length > 100 %}…{% endif %} |
{% endfor %}
{% else %}
No CVE intelligence gathered (no recognised technologies or vulnx unavailable).
{% endif %}

---

## Vulnerability Scan (Nuclei)

{% if nuclei and nuclei.findings %}
| Severity | Name | Template | Matched At |
|----------|------|----------|------------|
{% for f in nuclei.findings %}
| {{ f.severity | upper }} | {{ f.name }} | {{ f.template_id }} | {{ f.matched_at }} |
{% endfor %}
{% else %}
No vulnerabilities found by Nuclei.
{% endif %}

---

## SMB Enumeration

{% if smb %}
### Shares
{% if smb.shares %}
{% for s in smb.shares %}
- {{ s }}
{% endfor %}
{% else %}
No shares found.
{% endif %}

### Users ({{ smb.users | length }})
{% if smb.users %}
{% for u in smb.users %}
- {{ u }}
{% endfor %}
{% else %}
No users found.
{% endif %}

### Vulnerability Checks
- **NTLM Reflection (CVE-2025-33073):** {{ "**VULNERABLE**" if smb.ntlm_reflection_vulnerable else "Not vulnerable" }}
- **NoPac (CVE-2021-42278/42287):** {{ "**VULNERABLE**" if smb.nopac_vulnerable else "Not vulnerable" }}
- **AV/EDR:** {{ smb.av_products | join(", ") if smb.av_products else "None detected" }}
{% else %}
SMB enumeration not performed (no SMB ports detected).
{% endif %}

---

## Password Spray

{% if spray and spray.valid_creds %}
**Valid credentials found ({{ spray.valid_creds | length }}):**
{% for cred in spray.valid_creds %}
- `{{ cred }}`
{% endfor %}

*(Lockout threshold: {{ spray.lockout_threshold if spray.lockout_threshold > 0 else "disabled" }})*
{% elif spray %}
No valid credentials found via username=password spray ({{ spray.users_tested }} accounts tested).
*(Lockout threshold: {{ spray.lockout_threshold if spray.lockout_threshold > 0 else "disabled" }})*
{% else %}
Password spray not performed.
{% endif %}

---

## LDAP Enumeration

{% if ldap %}
**Base DN:** {{ ldap.base_dn or "N/A" }}
**Entries:** {{ ldap.entries_count }}

{% if ldap.adcs_cas %}
### ADCS Certificate Authorities
{% for ca in ldap.adcs_cas %}
- {{ ca }}
{% endfor %}
{% endif %}

{% if ldap.adcs_vulns %}
### ADCS Vulnerabilities
{% for v in ldap.adcs_vulns %}
- **{{ v }}**
{% endfor %}
{% endif %}

{% if ldap.asreproast_hashes %}
### AS-REP Roastable Hashes ({{ ldap.asreproast_hashes | length }})
```
{% for h in ldap.asreproast_hashes %}
{{ h }}
{% endfor %}
```
{% endif %}

{% if ldap.kerberoast_hashes %}
### Kerberoastable Hashes ({{ ldap.kerberoast_hashes | length }})
```
{% for h in ldap.kerberoast_hashes %}
{{ h }}
{% endfor %}
```
{% endif %}

{% if ldap.badsuccessor_dmsas %}
### BadSuccessor — dMSA Objects
{% for d in ldap.badsuccessor_dmsas %}
- {{ d }}
{% endfor %}
{% endif %}

{% else %}
LDAP enumeration not performed (no LDAP ports detected).
{% endif %}

---

## Active Directory — BloodHound

{% if bloodhound and bloodhound.users_count > 0 %}
**Domain:** {{ bloodhound.ad_domain }} (Functional Level: {{ bloodhound.func_level }})
**Objects:** {{ bloodhound.users_count }} users · {{ bloodhound.groups_count }} groups · {{ bloodhound.computers_count }} computers

{% if bloodhound.admin_users %}
### Admin Users (admincount=1)
{% for u in bloodhound.admin_users %}
- {{ u }}
{% endfor %}
{% endif %}

{% if bloodhound.spn_users %}
### Kerberoastable Accounts (SPN)
{% for u in bloodhound.spn_users %}
- {{ u }}
{% endfor %}
{% endif %}

{% if bloodhound.asrep_users %}
### ASREPRoastable Accounts (no preauth)
{% for u in bloodhound.asrep_users %}
- `{{ u }}`
{% endfor %}
{% endif %}

{% if bloodhound.unconstrained_users %}
### Unconstrained Delegation
{% for u in bloodhound.unconstrained_users %}
- {{ u }}
{% endfor %}
{% endif %}

{% if bloodhound.dcsync_principals %}
### DCSync Capable (GetChanges + GetChangesAll)
{% for p in bloodhound.dcsync_principals %}
- {{ p }}
{% endfor %}
{% endif %}

{% elif bloodhound %}
BloodHound collection ran but returned no data — check `bloodhound/bloodhound.log`.
{% else %}
BloodHound not run (no credentials provided or no LDAP detected).
{% endif %}

---

## AI Analysis

{% if ai_analysis %}
{{ ai_analysis }}
{% else %}
AI analysis was not performed.
{% endif %}

---

## Errors & Warnings

{% if errors %}
{% for err in errors %}
- {{ err }}
{% endfor %}
{% else %}
No errors encountered.
{% endif %}
"""
)


def generate(ctx: ReconContext) -> Path:
    """Generate the Markdown reconnaissance report."""
    report_path = ctx.config.project_dir / "report.md"
    report_path.parent.mkdir(parents=True, exist_ok=True)

    content = REPORT_TEMPLATE.render(
        config=ctx.config,
        date=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        nmap=ctx.nmap,
        whatweb=ctx.whatweb,
        subdomains=ctx.subdomains,
        directories=ctx.directories,
        vulnx=ctx.vulnx,
        nuclei=ctx.nuclei,
        smb=ctx.smb,
        ldap=ctx.ldap,
        bloodhound=ctx.bloodhound,
        spray=ctx.spray,
        ai_analysis=ctx.ai_analysis,
        errors=ctx.errors,
    )

    report_path.write_text(content, encoding="utf-8")
    return report_path
