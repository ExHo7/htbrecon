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

| Severity | CVE ID | CVSS | EPSS | Product | PoC | KEV | Nuclei | Description |
|----------|--------|------|------|---------|-----|-----|--------|-------------|
{% for f in vulnx.findings %}
| {{ f.severity | upper }} | {{ f.cve_id }} | {{ "%.1f" | format(f.cvss_score) }} | {{ "%.2f" | format(f.epss_score) }} | {{ f.product }} | {{ "✓" if f.is_poc else "–" }} | {{ "✓" if f.is_kev else "–" }} | {{ "✓" if f.has_nuclei_template else "–" }} | {{ f.description[:100] }}{% if f.description | length > 100 %}…{% endif %} |
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
- **Coercion (coerce_plus):** {{ "**VULNERABLE** — " + smb.coerce_vulns | join(", ") if smb.coerce_vulns else "Not vulnerable" }}
- **AV/EDR:** {{ smb.av_products | join(", ") if smb.av_products else "None detected" }}

{% if smb.rid_users %}
### RID Brute ({{ smb.rid_users | length }} users)
{% for u in smb.rid_users %}
- {{ u }}
{% endfor %}
{% endif %}
{% else %}
SMB enumeration not performed (no SMB ports detected).
{% endif %}

---

## SMB Share Spider

{% if spider and spider.interesting_files %}
**{{ spider.interesting_files | length }} interesting file(s) across {{ spider.shares_spidered | length }} share(s):**

{% for f in spider.interesting_files %}
- `{{ f }}`
{% endfor %}
{% elif spider %}
Spider ran — no interesting files found in {{ spider.shares_spidered | length }} share(s).
{% else %}
SMB spider not performed.
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

## WinRM

{% if winrm %}
**Port {{ winrm.port }}:** {{ "**ACCESS GRANTED** (Pwn3d!)" if winrm.accessible else "Access denied" }}
{% else %}
WinRM check not performed (no WinRM port detected or no credentials provided).
{% endif %}

---

## SSH

{% if ssh %}
**Port {{ ssh.port }}:** {{ "**ACCESS GRANTED** (Pwn3d!)" if ssh.accessible else "Access denied" }}
{% else %}
SSH check not performed (no SSH port detected or no credentials provided).
{% endif %}

---

## FTP

{% if ftp %}
**Port {{ ftp.port }}:**
{% if ftp.anonymous %}
**ANONYMOUS LOGIN ALLOWED**
{% elif ftp.accessible %}
ACCESS GRANTED (credentials)
{% else %}
Access denied (anonymous and credential-based login failed)
{% endif %}
{% else %}
FTP check not performed (no FTP port detected).
{% endif %}

---

## MSSQL

{% if mssql %}
**Port {{ mssql.port }}:** {{ "**ACCESS GRANTED**" if mssql.accessible else "Access denied" }}
- **Sysadmin:** {{ "**YES**" if mssql.sysadmin else "No" }}
- **xp_cmdshell:** {{ "**ENABLED**" if mssql.xp_cmdshell else "Disabled" }}
{% if mssql.databases %}
### Databases
{% for db in mssql.databases %}
- {{ db }}
{% endfor %}
{% endif %}
{% else %}
MSSQL enumeration not performed (no MSSQL port detected or no credentials provided).
{% endif %}

---

## LDAP Enumeration

{% if ldap %}
**Base DN:** {{ ldap.base_dn or "N/A" }}
**Entries:** {{ ldap.entries_count }}

{% if ldap.users %}
### Users ({{ ldap.users | length }})
{% for u in ldap.users %}
- {{ u }}
{% endfor %}
{% endif %}

{% if ldap.domain_admins %}
### Domain / Enterprise Admins
{% for u in ldap.domain_admins %}
- **{{ u }}**
{% endfor %}
{% endif %}

{% if ldap.unconstrained_delegation %}
### Unconstrained Delegation
{% for u in ldap.unconstrained_delegation %}
- {{ u }}
{% endfor %}
{% endif %}

{% if ldap.descriptions %}
### Account Descriptions (potential credentials)
{% for d in ldap.descriptions %}
- `{{ d }}`
{% endfor %}
{% endif %}

{% if ldap.domain_trusts %}
### Domain Trusts
{% for t in ldap.domain_trusts %}
- {{ t }}
{% endfor %}
{% endif %}

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

## Kerberos User Enumeration (Kerbrute)

{% if kerbrute and kerbrute.valid_users %}
**{{ kerbrute.valid_users | length }} valid user(s) found ({{ kerbrute.tested_count }} tested):**

{% for u in kerbrute.valid_users %}
- `{{ u }}`
{% endfor %}
{% elif kerbrute %}
No valid users found ({{ kerbrute.tested_count }} tested).
{% else %}
Kerbrute not run (credentials provided or port 88 not detected).
{% endif %}

---

## API Endpoints

{% if api and (api.endpoints or api.graphql_endpoints or api.spec_urls) %}
{% if api.api_tech_hints %}
**Detected API tech:** {{ api.api_tech_hints | join(", ") }}
{% endif %}

{% if api.spec_urls %}
### API Specs (Swagger / OpenAPI)
{% for s in api.spec_urls %}
- {{ s }}
{% endfor %}
{% endif %}

{% if api.graphql_endpoints %}
### GraphQL (introspection open)
{% for g in api.graphql_endpoints %}
- **{{ g }}** ← introspection enabled
{% endfor %}
{% endif %}

{% if api.endpoints %}
### Discovered Endpoints ({{ api.endpoints | length }})
{% for e in api.endpoints %}
- {{ e }}
{% endfor %}

*Note: API specs listed above are not repeated here.*
{% endif %}

{% else %}
No API endpoints discovered.
{% endif %}

---

## Web Crawl (Katana)

{% if katana and katana.urls_found %}
**{{ katana.urls_found | length }} URL(s) crawled** — {{ katana.interesting_urls | length }} interesting

{% if katana.interesting_urls %}
### Interesting URLs
{% for u in katana.interesting_urls %}
- {{ u }}
{% endfor %}
{% endif %}

Full results: `{{ katana.output_file }}`
{% elif katana %}
Katana ran but found no URLs.
{% else %}
Katana not run (no HTTP ports detected).
{% endif %}

---

## Web Screenshots (EyeWitness)

{% if eyewitness and eyewitness.screenshots_count > 0 %}
{{ eyewitness.screenshots_count }} screenshot(s) saved to: `{{ eyewitness.output_dir }}`
{% elif eyewitness %}
EyeWitness ran but produced no screenshots.
{% else %}
EyeWitness not run (no HTTP ports detected).
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
        spider=ctx.spider,
        ldap=ctx.ldap,
        bloodhound=ctx.bloodhound,
        spray=ctx.spray,
        kerbrute=ctx.kerbrute,
        winrm=ctx.winrm,
        ssh=ctx.ssh,
        ftp=ctx.ftp,
        mssql=ctx.mssql,
        eyewitness=ctx.eyewitness,
        api=ctx.api,
        katana=ctx.katana,
        ai_analysis=ctx.ai_analysis,
        errors=ctx.errors,
    )

    report_path.write_text(content, encoding="utf-8")
    return report_path
