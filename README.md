# HTBRecon

```
    __  ____________  ____
   / / / /_  __/ __ )/ __ \___  _________  ____
  / /_/ / / / / __  / /_/ / _ \/ ___/ __ \/ __ \
 / __  / / / / /_/ / _, _/  __/ /__/ /_/ / / / /
/_/ /_/ /_/ /_____/_/ |_|\___/\___/\____/_/ /_/
```

> Automated reconnaissance pipeline for Hack The Box machines, built to run inside [Exegol](https://github.com/ThePorgs/Exegol) containers or Kali Linux.

---

## Features

- **Full port scan** with nmap (SYN + service detection)
- **Web fingerprinting** with WhatWeb on all HTTP/HTTPS ports
- **Subdomain enumeration** via ffuf vhost fuzzing (auto-added to `/etc/hosts`)
- **WhatWeb on discovered subdomains** for complete technology coverage
- **Directory brute-force** with ffuf across all hostnames and ports
- **Vulnerability scanning** with Nuclei (auto-scan mode, critical→low)
- **Web screenshots** with EyeWitness — headless Chrome screenshots of all HTTP ports + subdomains
- **CVE intelligence** with vulnx — searches CVEs for every detected technology
- **SMB enumeration** with enum4linux-ng + netexec (shares, users, NTLM reflection, NoPac, AV detection)
- **SMB share spidering** with nxc spider_plus — recursively lists shares and flags sensitive files (`.ps1`, `.xml`, `.kdbx`, `.pfx`, etc.)
- **RID brute-force** with nxc — enumerates domain users via RID cycling when no credentials are provided
- **LDAP enumeration** with ldapsearch (base DN, users, admins, AS-REP/Kerberoast hashes, ADCS, delegation, BadSuccessor)
- **Kerberos user enumeration** with kerbrute — validates usernames against the KDC without triggering lockouts (no credentials required)
- **Active Directory collection** with BloodHound/nxc (requires credentials) — admin users, SPNs, DCSync principals
- **Password spray** — tests username=password combos with lockout-policy awareness
- **WinRM access check** with nxc — verifies shell access on port 5985/5986 when credentials are available
- **AI analysis** powered by Claude (Anthropic) — suggests attack vectors and next steps
- **Markdown report** generated at the end of every run
- **Debug mode** — verbose command logging on demand

---

## Requirements

- Python 3.10+
- [Exegol](https://github.com/ThePorgs/Exegol) container or Kali Linux environment
- Tools available in Exegol: `nmap`, `ffuf`, `nuclei`, `whatweb`, `enum4linux-ng`, `nxc`, `ldapsearch`, `kerbrute`, `bloodhound-python`
- EyeWitness at `/opt/tools/EyeWitness/Python/EyeWitness.py` (pre-installed in Exegol)
- `vulnx` binary (installed via `htbrecon setup`, see below)
- Anthropic API key (optional, for AI analysis)

---

## Installation

Inside your Exegol container:

```bash
git clone https://github.com/ExHo7/HTBRecon.git /opt/HTBRecon
cd /opt/HTBRecon
pip install -e .
```

Then install the `vulnx` dependency:

```bash
htbrecon setup
```

This downloads the latest `vulnx` binary from GitHub releases and installs it to `/usr/local/bin/vulnx`.
Use `--force` to reinstall an existing version:

```bash
htbrecon setup --force
```

---

## Usage

### Basic run

```bash
htbrecon run -i 10.10.11.42 -n machinename
```

This will:
1. Create `results/machinename/` with subdirectories for each tool
2. Add `10.10.11.42 machinename.htb` to `/etc/hosts`
3. Run the full pipeline and generate `results/machinename/report.md`

### With credentials

```bash
htbrecon run -i 10.10.11.42 -n machinename --credentials admin:Password123
```

Credentials unlock additional scanners: SMB vuln checks, LDAP full dump, BloodHound collection, WinRM access check.
When credentials are provided, Kerbrute and RID brute-force are skipped (user enumeration is not needed).

### Custom domain

```bash
htbrecon run -i 10.10.11.42 -n dc01 --domain corp.local
```

Targets `dc01.corp.local` instead of `dc01.htb`.

### Skip AI analysis

```bash
htbrecon run -i 10.10.11.42 -n machinename --skip-ai
```

### Debug mode

```bash
htbrecon run -i 10.10.11.42 -n machinename --debug
```

Prints every command executed, its exit code, and duration to the console.
Debug output is always written to `results/machinename/htbrecon.log` regardless of this flag.

### Help

```bash
htbrecon --help
htbrecon run --help
```

---

## Pipeline

```
Phase 1 — Setup
  └─ Create output directories
  └─ Add target to /etc/hosts

Phase 2 — Port Discovery
  └─ nmap -sS -sV -F -Pn

Phase 3 — Service Enumeration (parallel)
  ├─ WhatWeb        (if HTTP ports found)
  ├─ SMB            (if port 139/445 open)
  │    └─ RID brute-force (if no credentials)
  └─ LDAP           (if port 389/636/3268 open)

Phase 3a — SMB Share Spidering
  └─ nxc spider_plus (if SMB open — anonymous or authenticated)

Phase 3b — Kerberos User Enumeration
  └─ kerbrute userenum (if port 88 open AND no credentials)

Phase 3c — Active Directory (BloodHound)
  └─ nxc + bloodhound-python (if LDAP open AND credentials provided)

Phase 3d — Password Spray
  └─ nxc smb username=password (if SMB open)

Phase 3e — WinRM Access Check
  └─ nxc winrm (if port 5985/5986 open AND credentials provided)

Phase 4 — Web Reconnaissance
  ├─ ffuf subdomain fuzzing → /etc/hosts
  ├─ WhatWeb on discovered subdomains
  ├─ ffuf directory brute-force (parallel, all hostnames)
  ├─ Nuclei vulnerability scan (parallel)
  └─ EyeWitness screenshots (parallel, all URLs + subdomains)

Phase 5 — CVE Intelligence
  └─ vulnx searches CVEs for every detected technology

Phase 6 — AI Analysis (skippable)
  └─ Claude Sonnet analyzes findings, suggests attack vectors

Phase 7 — Report Generation
  └─ Markdown report → results/<name>/report.md
```

---

## Output

All results are saved under `results/<machinename>/`:

```
results/machinename/
├── htbrecon.log          # Full debug log
├── report.md             # Final reconnaissance report
├── eyewitness_urls.txt   # URL list fed to EyeWitness
├── nmap/
│   ├── full_scan.nmap
│   └── full_scan.xml
├── web/
│   └── whatweb_*.txt
├── ffuf/
│   ├── subdomains.json
│   └── dirs_*.json
├── nuclei/
│   ├── targets.txt
│   └── scan.jsonl
├── eyewitness/           # Web screenshots (HTML report + PNG files)
├── smb/
│   ├── enum4linux.txt
│   ├── nxc_shares.txt
│   └── nxc_rid_brute.txt
├── spider/               # SMB spider JSON output
├── kerbrute/
│   └── kerbrute.txt
├── ldap/
│   └── ldapsearch.txt
├── winrm/
│   └── winrm.txt
└── vulnx/
```

---

## Scanner Conditions

| Scanner | Condition |
|---------|-----------|
| WhatWeb | HTTP/HTTPS ports open |
| SMB enum | Port 139 or 445 open |
| RID brute-force | SMB open **and** no credentials |
| SMB spider_plus | SMB open (anonymous or authenticated) |
| LDAP enum | Port 389, 636, 3268 or 3269 open |
| Kerbrute | Port 88 open **and** no credentials |
| BloodHound | LDAP open **and** credentials provided |
| Password spray | SMB open |
| WinRM check | Port 5985 or 5986 open **and** credentials provided |
| EyeWitness | HTTP/HTTPS ports open |
| Nuclei | HTTP/HTTPS ports open |
| vulnx | Always (if installed) |
| AI analysis | Always (unless `--skip-ai`) |

---

## Environment Variables

| Variable | Description |
|----------|-------------|
| `ANTHROPIC_API_KEY` | Required for AI analysis. Omit or use `--skip-ai` to disable. |

---

## Notes

- Designed for **Hack The Box** and similar CTF/lab environments. Use responsibly and only against machines you own or have explicit permission to test.
- `/etc/hosts` is modified directly — requires write access (standard inside Exegol containers).
- IP address format is validated at startup — an invalid IP will produce a clear error before any scan begins.
