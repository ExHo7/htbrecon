# HTBRecon

```
    __  ____________  ____
   / / / /_  __/ __ )/ __ \___  _________  ____
  / /_/ / / / / __  / /_/ / _ \/ ___/ __ \/ __ \
 / __  / / / / /_/ / _, _/  __/ /__/ /_/ / / / /
/_/ /_/ /_/ /_____/_/ |_|\___/\___/\____/_/ /_/
```

> Automated reconnaissance pipeline for Hack The Box machines, built to run inside [Exegol](https://github.com/ThePorgs/Exegol) containers or Kali linux.

---

## Features

- **Full port scan** with nmap (SYN + service detection)
- **Web fingerprinting** with WhatWeb on all HTTP/HTTPS ports
- **Subdomain enumeration** via ffuf vhost fuzzing (auto-added to `/etc/hosts`)
- **WhatWeb on discovered subdomains** for complete technology coverage
- **Directory brute-force** with ffuf across all hostnames and ports
- **Vulnerability scanning** with Nuclei (auto-scan mode, critical→low)
- **CVE intelligence** with vulnx — searches CVEs for every detected technology
- **SMB enumeration** with enum4linux-ng + netexec
- **LDAP enumeration** with ldapsearch (base DN discovery + full dump)
- **AI analysis** powered by Claude (Anthropic) — suggests attack vectors and next steps
- **Markdown report** generated at the end of every run
- **Debug mode** — verbose command logging on demand

---

## Requirements

- Python 3.10+
- [Exegol](https://github.com/ThePorgs/Exegol) container or Kali linux environment
- Tools available in Exegol: `nmap`, `ffuf`, `nuclei`, `whatweb`, `enum4linux-ng`, `nxc`, `ldapsearch`
- `vulnx` binary (installed via `htbrecon setup`, see below)
- Anthropic API key (optional, for AI analysis)

---

## Installation

Inside your Exegol container:

```bash
git clone https://github.com/youruser/HTBRecon /opt/HTBRecon
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

Credentials are passed to SMB (nxc + enum4linux-ng) and LDAP (ldapsearch) scanners.

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
  └─ LDAP           (if port 389/636/3268 open)

Phase 4 — Web Reconnaissance
  ├─ ffuf subdomain fuzzing → /etc/hosts
  ├─ WhatWeb on discovered subdomains
  ├─ ffuf directory brute-force (parallel, all hostnames)
  └─ Nuclei vulnerability scan (parallel)

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
├── smb/
│   ├── enum4linux.txt
│   └── nxc_shares.txt
├── ldap/
│   └── ldapsearch.txt
└── vulnx/
```

---

## Environment Variables

| Variable | Description |
|----------|-------------|
| `ANTHROPIC_API_KEY` | Required for AI analysis (Phase 5). Omit or use `--skip-ai` to disable. |

---

## Notes

- The tool is designed for **Hack The Box** and similar CTF/lab environments. Use responsibly and only against machines you own or have explicit permission to test.
- `/etc/hosts` is modified directly — requires write access (standard inside Exegol containers).
