# HTBRecon

**HTBRecon** is an automated reconnaissance tool for **Hack The Box** machines (or similar environments). It performs Nmap scans, detects subdomains, directories, and vulnerabilities using Nuclei, all in a single Bash script.

---

## 📌 Features
- **Nmap Scanning**: Discover open ports and services.
- **Subdomain Detection**: Use FFUF to identify subdomains.
- **Directory Scanning**: Search for sensitive files and directories.
- **Vulnerability Detection**: Use Nuclei to identify vulnerabilities.
- **Recursive Scanning**: Scan subdomains with the `-r` flag.
- **Report Generation**: Organized results in JSON/HTML files.

---

## 📦 Installation

### Requirements
- **OS**: Linux (tested on Kali Linux, Parrot OS, Ubuntu).
- **Required Tools**:
  ```bash
  sudo apt update && sudo apt install -y nmap ffuf nuclei jq xsltproc
Clone the Repository
git clone https://github.com/your-username/HTBScan.git
cd HTBScan
chmod +x htbscan.sh

🚀 Usage
Basic Command
sudo ./htbscan.sh -i <IP> -n <MACHINE_NAME>

<IP>: Target IP address.
<MACHINE_NAME>: Output directory name (e.g., machine1).

Options
-i <IP> Target IP address (required).
-n <NAME> Output directory name (required).
-r Enable recursive scans on subdomains (FFUF + Nuclei).
-h Display help.
Examples

Basic Scan:
sudo ./htbscan.sh -i 10.10.10.10 -n machine1

Recursive Scan:
sudo ./htbscan.sh -i 10.10.10.10 -n machine1 -r



📂 Results Structure
Results are saved in a directory named <MACHINE_NAME>/:
machine1/
├── nmap/
│   ├── initial.nmap
│   ├── full.xml
│   └── full.html
├── subdomains.json
├── dirscan.json
├── nuclei.json
└── scan_errors.log

🎥 Demo

(Replace demo.gif with the path or URL of your video/GIF.)

⚙️ Configuration

Wordlists: Modify the wordlist paths in the script (WORDLIST, VHOST_WORDLIST).
Recursion Depth: Adjust the DEPTH variable for FFUF scans.
Extensions: Customize EXTENSIONS to target specific file types (e.g., php,html,js).


🛠 Contributing
Contributions are welcome!

Add new features.
Fix bugs.
Improve documentation.

