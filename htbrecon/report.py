from __future__ import annotations

from datetime import datetime
from pathlib import Path

from jinja2 import Template

from htbrecon.models import ReconContext

REPORT_TEMPLATE = Template(
    """\
# Reconnaissance Report: {{ config.name }}.htb

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

### Users
{% if smb.users %}
{% for u in smb.users %}
- {{ u }}
{% endfor %}
{% else %}
No users found.
{% endif %}
{% else %}
SMB enumeration not performed (no SMB ports detected).
{% endif %}

---

## LDAP Enumeration

{% if ldap %}
**Base DN:** {{ ldap.base_dn or "N/A" }}
**Entries:** {{ ldap.entries_count }}
{% else %}
LDAP enumeration not performed (no LDAP ports detected).
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
        ai_analysis=ctx.ai_analysis,
        errors=ctx.errors,
    )

    report_path.write_text(content, encoding="utf-8")
    return report_path
