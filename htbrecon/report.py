from __future__ import annotations

from datetime import datetime
from pathlib import Path

from jinja2 import Template

from htbrecon.models import ReconContext

_HTML_WRAPPER = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>HTBRecon — {title}</title>
<style>
  :root {{
    --bg: #11111b;
    --bg2: #181825;
    --card: #1e1e2e;
    --surface: #313244;
    --surface2: #45475a;
    --text: #cdd6f4;
    --subtext: #a6adc8;
    --muted: #6c7086;
    --critical: #f38ba8;
    --high: #fab387;
    --medium: #f9e2af;
    --low: #89b4fa;
    --info: #a6e3a1;
    --accent: #cba6f7;
    --green: #a6e3a1;
    --red: #f38ba8;
    --teal: #94e2d5;
    --sidebar-w: 270px;
    --shadow: 0 4px 18px rgba(0,0,0,0.35);
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  html {{ scroll-behavior: smooth; }}
  body {{
    background: radial-gradient(1200px 600px at 80% -5%, #1b1b2e 0%, var(--bg) 55%) fixed;
    color: var(--text);
    font-family: 'Inter', 'Segoe UI', system-ui, sans-serif;
    font-size: 15px;
    line-height: 1.6;
  }}
  /* ---------- Layout ---------- */
  .layout {{ display: flex; align-items: flex-start; }}
  .sidebar {{
    position: sticky; top: 0; height: 100vh;
    width: var(--sidebar-w); flex: 0 0 var(--sidebar-w);
    background: var(--bg2); border-right: 1px solid var(--surface);
    padding: 1.2rem 0.8rem; overflow-y: auto;
  }}
  .sidebar .brand {{
    font-weight: 700; font-size: 1.1rem; color: var(--accent);
    padding: 0 0.6rem 0.8rem; letter-spacing: 0.02em;
  }}
  .sidebar .brand small {{ display:block; color: var(--muted); font-weight: 400; font-size: 0.72rem; }}
  #toc-search {{
    width: calc(100% - 0.4rem); margin: 0 0.2rem 0.7rem; padding: 0.45rem 0.6rem;
    background: var(--card); border: 1px solid var(--surface); border-radius: 8px;
    color: var(--text); font-size: 0.85rem; outline: none;
  }}
  #toc-search:focus {{ border-color: var(--accent); }}
  .toc a {{
    display: flex; align-items: center; justify-content: space-between; gap: 0.4rem;
    padding: 0.4rem 0.6rem; border-radius: 8px; color: var(--subtext);
    font-size: 0.86rem; text-decoration: none; border-left: 3px solid transparent;
  }}
  .toc a:hover {{ background: var(--surface); color: var(--text); }}
  .toc a.active {{ background: var(--surface); color: var(--text); border-left-color: var(--accent); }}
  .toc a.empty {{ color: var(--muted); opacity: 0.55; }}
  .toc a .count {{
    font-size: 0.7rem; background: var(--surface); color: var(--subtext);
    padding: 0.05rem 0.4rem; border-radius: 999px; min-width: 1.4rem; text-align: center;
  }}
  .toc a.hit .count {{ background: var(--critical); color: var(--bg); font-weight: 700; }}
  .toc-toggle {{
    margin: 0.6rem 0.2rem 0; display: flex; align-items: center; gap: 0.4rem;
    font-size: 0.78rem; color: var(--subtext); cursor: pointer; user-select: none;
  }}
  .content {{ flex: 1 1 auto; min-width: 0; padding: 2rem 2.4rem 5rem; max-width: 1200px; margin: 0 auto; }}
  /* ---------- Header / hero ---------- */
  .hero {{
    background: linear-gradient(135deg, var(--card), var(--bg2));
    border: 1px solid var(--surface); border-radius: 16px;
    padding: 1.6rem 1.8rem; margin-bottom: 1.4rem; box-shadow: var(--shadow);
  }}
  .hero h1 {{ color: var(--text); font-size: 1.9rem; border: none; padding: 0; margin: 0; }}
  .hero .meta {{ color: var(--subtext); font-size: 0.9rem; margin-top: 0.4rem; display:flex; gap:1.2rem; flex-wrap:wrap; }}
  .hero .meta b {{ color: var(--text); }}
  /* ---------- Dashboard stat cards ---------- */
  .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 0.8rem; margin-bottom: 1.2rem; }}
  .stat {{
    background: var(--card); border: 1px solid var(--surface); border-radius: 14px;
    padding: 0.9rem 1rem; position: relative; overflow: hidden;
  }}
  .stat .num {{ font-size: 1.8rem; font-weight: 800; line-height: 1; }}
  .stat .lbl {{ color: var(--subtext); font-size: 0.78rem; margin-top: 0.3rem; text-transform: uppercase; letter-spacing: 0.04em; }}
  .stat.crit .num {{ color: var(--critical); }}
  .stat.high .num {{ color: var(--high); }}
  .stat.good .num {{ color: var(--green); }}
  .stat.neutral .num {{ color: var(--low); }}
  /* ---------- Alert banner ---------- */
  .alerts {{ margin-bottom: 1.4rem; display: flex; flex-direction: column; gap: 0.5rem; }}
  .alert {{
    display: flex; align-items: center; gap: 0.6rem; padding: 0.7rem 1rem;
    border-radius: 12px; font-size: 0.9rem; border: 1px solid;
  }}
  .alert.win {{ background: rgba(166,227,161,0.10); border-color: var(--green); color: var(--green); }}
  .alert.vuln {{ background: rgba(243,139,168,0.10); border-color: var(--critical); color: var(--critical); }}
  .alert b {{ color: var(--text); }}
  .alert .tag {{ font-weight: 800; letter-spacing: 0.03em; }}
  /* ---------- Section cards ---------- */
  .section {{
    background: var(--card); border: 1px solid var(--surface); border-left: 3px solid var(--surface2);
    border-radius: 14px; padding: 0.2rem 1.4rem 1rem; margin-bottom: 1.1rem; box-shadow: var(--shadow);
    scroll-margin-top: 1rem;
  }}
  .section.has-hit {{ border-left-color: var(--critical); }}
  .section.is-empty {{ opacity: 0.6; }}
  .section > h2 {{
    display: flex; align-items: center; gap: 0.6rem; cursor: pointer; user-select: none;
    color: var(--teal); font-size: 1.25rem; margin: 0; padding: 1rem 0 0.7rem;
    border: none;
  }}
  .section > h2 .chev {{ color: var(--muted); font-size: 0.8rem; transition: transform 0.15s; margin-left: auto; }}
  .section.collapsed > h2 .chev {{ transform: rotate(-90deg); }}
  .section.collapsed > :not(h2) {{ display: none; }}
  .section .body {{ padding-top: 0.2rem; }}
  h1 {{ color: var(--accent); font-size: 2rem; }}
  h3 {{ color: var(--low); font-size: 1.05rem; margin: 1rem 0 0.4rem; }}
  p {{ margin: 0.5rem 0; }}
  a {{ color: var(--accent); text-decoration: none; }}
  a:hover {{ text-decoration: underline; }}
  hr {{ display: none; }}
  ul, ol {{ padding-left: 1.4rem; margin: 0.5rem 0; }}
  li {{ margin: 0.2rem 0; }}
  strong {{ color: var(--text); font-weight: 600; }}
  em {{ color: var(--subtext); }}
  code {{
    background: var(--bg2); color: var(--accent); padding: 0.1em 0.4em; border-radius: 4px;
    font-family: 'JetBrains Mono', 'Fira Code', monospace; font-size: 0.86em;
  }}
  pre {{
    background: var(--bg2); border: 1px solid var(--surface); border-radius: 8px;
    padding: 1rem; overflow-x: auto; margin: 0.8rem 0;
  }}
  pre code {{ background: none; padding: 0; color: var(--text); font-size: 0.84em; }}
  table {{ width: 100%; border-collapse: collapse; margin: 0.8rem 0; font-size: 0.88em; }}
  thead tr {{ background: var(--bg2); }}
  th {{
    color: var(--teal); font-weight: 600; text-align: left; padding: 0.5rem 0.8rem;
    border-bottom: 2px solid var(--surface2); position: sticky; top: 0;
  }}
  td {{ padding: 0.45rem 0.8rem; border-bottom: 1px solid var(--surface); vertical-align: top; }}
  tbody tr:nth-child(even) {{ background: var(--bg2); }}
  tbody tr:hover {{ background: var(--surface); }}
  /* ---------- Severity badges ---------- */
  .badge {{
    display: inline-block; font-size: 0.72rem; font-weight: 700; letter-spacing: 0.03em;
    padding: 0.15rem 0.55rem; border-radius: 999px; text-transform: uppercase;
  }}
  .badge.critical {{ background: var(--critical); color: var(--bg); }}
  .badge.high     {{ background: var(--high);     color: var(--bg); }}
  .badge.medium   {{ background: var(--medium);   color: var(--bg); }}
  .badge.low      {{ background: var(--low);      color: var(--bg); }}
  .badge.info     {{ background: var(--info);     color: var(--bg); }}
  blockquote {{
    border-left: 3px solid var(--surface2); padding-left: 1rem; color: var(--subtext); margin: 0.8rem 0;
  }}
  .back-top {{
    position: fixed; right: 1.4rem; bottom: 1.4rem; background: var(--surface);
    color: var(--text); border: 1px solid var(--surface2); border-radius: 999px;
    width: 42px; height: 42px; display: none; align-items: center; justify-content: center;
    cursor: pointer; box-shadow: var(--shadow); font-size: 1.1rem;
  }}
  @media (max-width: 900px) {{
    .sidebar {{ display: none; }}
    .content {{ padding: 1.2rem; }}
  }}
</style>
</head>
<body>
<div class="layout">
  <nav class="sidebar">
    <div class="brand">HTBRecon<small>{title}</small></div>
    <input id="toc-search" type="search" placeholder="Filter sections…" autocomplete="off">
    <div class="toc" id="toc"></div>
    <label class="toc-toggle"><input type="checkbox" id="hide-empty"> Hide empty sections</label>
  </nav>
  <main class="content">
    <div id="dashboard"></div>
    <div id="report">
{body}
    </div>
  </main>
</div>
<button class="back-top" id="back-top" title="Back to top">↑</button>
<script>
(function() {{
  const SEVS = ['critical','high','medium','low','info'];
  const report = document.getElementById('report');

  // ---- 1. Group each <h2> and its following siblings into a .section card ----
  const sections = [];
  const h1 = report.querySelector('h1');
  Array.from(report.querySelectorAll('h2')).forEach(h2 => {{
    const sec = document.createElement('section');
    sec.className = 'section';
    const body = document.createElement('div');
    body.className = 'body';
    let n = h2.nextElementSibling;
    while (n && n.tagName !== 'H2') {{ const next = n.nextElementSibling; body.appendChild(n); n = next; }}
    h2.parentNode.insertBefore(sec, h2);
    sec.appendChild(h2);
    sec.appendChild(body);
    const id = 'sec-' + h2.textContent.trim().toLowerCase().replace(/[^a-z0-9]+/g,'-').replace(/^-|-$/g,'');
    sec.id = id;
    sections.push({{ sec, h2, body, id, title: h2.textContent.trim() }});
  }});

  // ---- 2. Severity badges in tables ----
  document.querySelectorAll('#report td').forEach(td => {{
    const t = td.textContent.trim().toLowerCase();
    if (SEVS.includes(t)) {{
      td.innerHTML = '<span class="badge ' + t + '">' + t + '</span>';
    }}
  }});

  // ---- 3. Classify sections: empty? contains a "hit" (vuln / access / creds)? ----
  const EMPTY_RE = /(not performed|not run|no .* (found|discovered|identified)|no open ports|no vulnerabilities|no errors|no subdomains|no api endpoints|no web technologies|access denied)/i;
  const HIT_RE = /(VULNERABLE|ACCESS GRANTED|Pwn3d|ANONYMOUS LOGIN ALLOWED|Valid credentials|introspection enabled)/;
  sections.forEach(s => {{
    const txt = s.body.textContent;
    const hasBadge = s.body.querySelector('.badge.critical, .badge.high');
    s.hits = 0;
    (txt.match(new RegExp(HIT_RE.source, 'gi')) || []).forEach(() => s.hits++);
    if (hasBadge) s.hits += s.body.querySelectorAll('.badge.critical, .badge.high').length;
    s.empty = EMPTY_RE.test(txt.trim()) && s.body.querySelectorAll('table, li, img').length === 0 && s.hits === 0;
    if (s.empty) s.sec.classList.add('is-empty');
    if (s.hits > 0) s.sec.classList.add('has-hit');
    // collapsible chevron
    const chev = document.createElement('span');
    chev.className = 'chev'; chev.textContent = '▼';
    s.h2.appendChild(chev);
    s.h2.addEventListener('click', () => s.sec.classList.toggle('collapsed'));
    if (s.empty) s.sec.classList.add('collapsed');
  }});

  // ---- 4. Build the TOC ----
  const toc = document.getElementById('toc');
  sections.forEach(s => {{
    const a = document.createElement('a');
    a.href = '#' + s.id;
    a.className = 'toc-link' + (s.empty ? ' empty' : '') + (s.hits > 0 ? ' hit' : '');
    a.dataset.title = s.title.toLowerCase();
    a.innerHTML = '<span class="t">' + s.title + '</span>' +
      (s.hits > 0 ? '<span class="count">' + s.hits + '</span>' : '');
    toc.appendChild(a);
    s.link = a;
  }});

  // ---- 5. Dashboard (stats + alerts) ----
  const openPorts = (() => {{
    const portSec = sections.find(s => /port summary/i.test(s.title));
    if (!portSec) return 0;
    return portSec.body.querySelectorAll('tbody tr').length;
  }})();
  const sevCount = sev => document.querySelectorAll('#report .badge.' + sev).length;
  const crit = sevCount('critical'), high = sevCount('high');
  // Count access/vuln per line element (not per keyword) to avoid double-counting
  // lines like "ACCESS GRANTED (Pwn3d!)".
  const countLines = re => {{
    let c = 0;
    document.querySelectorAll('#report p, #report li').forEach(el => {{ if (re.test(el.textContent)) c++; }});
    return c;
  }};
  const accessCount = countLines(/ACCESS GRANTED|Pwn3d|ANONYMOUS LOGIN ALLOWED|Valid credentials/i);
  const vulnCount = countLines(/VULNERABLE/);

  const stats = [
    {{ n: openPorts, l: 'Open ports', c: 'neutral' }},
    {{ n: crit, l: 'Critical CVEs', c: crit ? 'crit' : 'neutral' }},
    {{ n: high, l: 'High CVEs', c: high ? 'high' : 'neutral' }},
    {{ n: vulnCount, l: 'Vuln checks hit', c: vulnCount ? 'crit' : 'neutral' }},
    {{ n: accessCount, l: 'Access obtained', c: accessCount ? 'good' : 'neutral' }},
  ];
  const dash = document.getElementById('dashboard');
  let html = '';
  if (h1) {{
    // pull target/date lines (first two <p> or the <p> right after h1)
    const metaP = h1.nextElementSibling && h1.nextElementSibling.tagName === 'P' ? h1.nextElementSibling.innerHTML : '';
    html += '<div class="hero"><h1>' + h1.textContent.replace(/^Reconnaissance Report:\\s*/,'') + '</h1>' +
            (metaP ? '<div class="meta">' + metaP.replace(/<br\\s*\\/?>/gi, '</span><span>').replace(/^/, '<span>').replace(/$/, '</span>') + '</div>' : '') +
            '</div>';
    h1.style.display = 'none';
    if (h1.nextElementSibling && h1.nextElementSibling.tagName === 'P') h1.nextElementSibling.style.display = 'none';
  }}
  html += '<div class="stats">' + stats.map(s =>
    '<div class="stat ' + s.c + '"><div class="num">' + s.n + '</div><div class="lbl">' + s.l + '</div></div>'
  ).join('') + '</div>';

  // alerts: scan sections with hits, extract the key lines
  const alerts = [];
  sections.forEach(s => {{
    s.body.querySelectorAll('p, li').forEach(el => {{
      const t = el.textContent;
      if (/VULNERABLE/.test(t)) alerts.push({{ cls: 'vuln', tag: 'VULN', title: s.title, text: t.trim() }});
      else if (/ACCESS GRANTED|Pwn3d|ANONYMOUS LOGIN ALLOWED|Valid credentials/.test(t))
        alerts.push({{ cls: 'win', tag: 'ACCESS', title: s.title, text: t.trim() }});
    }});
  }});
  if (alerts.length) {{
    html += '<div class="alerts">' + alerts.slice(0, 12).map(a =>
      '<div class="alert ' + a.cls + '"><span class="tag">' + a.tag + '</span>' +
      '<span><b>' + a.title + '</b> — ' + a.text.replace(/</g,'&lt;') + '</span></div>'
    ).join('') + '</div>';
  }}
  dash.innerHTML = html;

  // ---- 6. TOC search filter ----
  const search = document.getElementById('toc-search');
  search.addEventListener('input', () => {{
    const q = search.value.toLowerCase();
    sections.forEach(s => {{
      const match = s.title.toLowerCase().includes(q);
      s.link.style.display = match ? '' : 'none';
    }});
  }});

  // ---- 7. Hide empty toggle ----
  const hideEmpty = document.getElementById('hide-empty');
  hideEmpty.addEventListener('change', () => {{
    sections.forEach(s => {{
      if (s.empty) {{
        s.sec.style.display = hideEmpty.checked ? 'none' : '';
        s.link.style.display = hideEmpty.checked ? 'none' : '';
      }}
    }});
  }});

  // ---- 8. Scroll spy ----
  const spy = () => {{
    let cur = sections[0];
    for (const s of sections) {{
      if (s.sec.getBoundingClientRect().top <= 120) cur = s;
    }}
    sections.forEach(s => s.link.classList.toggle('active', s === cur));
    document.getElementById('back-top').style.display = window.scrollY > 400 ? 'flex' : 'none';
  }};
  window.addEventListener('scroll', spy, {{ passive: true }});
  spy();
  document.getElementById('back-top').addEventListener('click', () => window.scrollTo({{ top: 0 }}));
}})();
</script>
</body>
</html>
"""

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

*Ver column: ✓ = detected version is affected, ? = undetermined (`out`-of-range CVEs are filtered out).*

| Severity | CVE ID | CVSS | EPSS | Product | Ver | PoC | KEV | Nuclei | Description |
|----------|--------|------|------|---------|-----|-----|-----|--------|-------------|
{% for f in vulnx.findings %}
| {{ f.severity | upper }} | {{ f.cve_id }} | {{ "%.1f" | format(f.cvss_score) }} | {{ "%.2f" | format(f.epss_score) }} | {{ f.product }} | {{ "✓" if f.version_verdict == "in" else "?" }} | {% if f.poc_urls %}[link]({{ f.poc_urls[0] }}){% elif f.is_poc %}✓{% else %}–{% endif %} | {{ "✓" if f.is_kev else "–" }} | {{ "✓" if f.has_nuclei_template else "–" }} | {{ f.description[:100] }}{% if f.description | length > 100 %}…{% endif %} |
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


def _embed_eyewitness_screenshots(html: str, ctx: ReconContext) -> str:
    """Append base64-embedded screenshots after the EyeWitness section in the HTML."""
    import base64

    screens_dir = ctx.config.project_dir / "eyewitness" / "screenshots" / "screens"
    if not screens_dir.exists():
        return html

    pngs = sorted(screens_dir.glob("*.png"))
    if not pngs:
        return html

    imgs = []
    for png in pngs:
        b64 = base64.b64encode(png.read_bytes()).decode()
        label = png.stem.replace("_", " ").replace(".", " ")
        imgs.append(
            f'<div style="margin:0.8rem 0;">'
            f'<p style="color:var(--subtext);font-size:0.85em;margin-bottom:0.3rem;">{label}</p>'
            f'<img src="data:image/png;base64,{b64}" '
            f'style="max-width:100%;border:1px solid var(--surface);border-radius:6px;" />'
            f'</div>'
        )

    gallery = (
        '<div style="margin-top:1rem;">'
        + "\n".join(imgs)
        + "</div>"
    )

    # Insert gallery right after the EyeWitness section heading
    marker = "<h2>Web Screenshots (EyeWitness)</h2>"
    if marker in html:
        html = html.replace(marker, marker + "\n" + gallery, 1)
    else:
        # Fallback: append at end of body
        html = html.replace("</body>", gallery + "\n</body>")

    return html


def generate_html(ctx: ReconContext) -> Path:
    """Convert the Markdown report to a self-contained HTML file and return its path."""
    try:
        import mistune
    except ImportError:
        raise RuntimeError(
            "mistune is required for HTML export — run: pip install mistune"
        )

    md_path = ctx.config.project_dir / "report.md"
    html_path = ctx.config.project_dir / "report.html"

    md_content = md_path.read_text(encoding="utf-8")
    body = mistune.html(md_content)

    html = _HTML_WRAPPER.format(title=ctx.config.hostname, body=body)
    html = _embed_eyewitness_screenshots(html, ctx)
    html_path.write_text(html, encoding="utf-8")
    return html_path


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
