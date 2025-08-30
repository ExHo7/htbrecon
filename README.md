# HTBScan



**HTBScan** is a powerful Bash script designed to automate reconnaissance and security scanning tasks on target machines, particularly for Hack The Box (HTB) challenges. It leverages popular tools like Nmap, FFUF, and Dirsearch to detect open ports, subdomains, directories, and potential vulnerabilities.

---

## 🌟 Features

- **Nmap Scanning**: Detect open ports and running services
- **Subdomain Discovery**: Use FFUF to discover subdomains
- **Directory Search**: Use FFUF to discover accessible directories and files
- **Vulnerability Detection**: (Optional) Integration with Nuclei to detect vulnerabilities
- **Additional HTTP Ports Detection**: Detect and notify about additional open HTTP ports (like 8080, 3000, etc.)
- **Automated Reporting**: Generate structured output for easy analysis
- **Colorful Output**: Easy-to-read colored console output

---

## 📋 Prerequisites

This is specficly designed to Exegol but you can use it by installing dependencies below.

Before using HTBScan, ensure you have the following tools installed:

| Tool       | Purpose                          | Installation Command (Debian/Ubuntu) |
|------------|----------------------------------|--------------------------------------|
| Nmap       | Port scanning                    | `sudo apt-get install nmap`        |
| FFUF       | Subdomain/directory discovery     | `sudo apt-get install ffuf`        |
| jq         | JSON file processing             | `sudo apt-get install jq`          |
| xsltproc   | Convert Nmap results to HTML     | `sudo apt-get install xsltproc`    |
| cURL       | HTTP requests                    | `sudo apt-get install curl`        |

Install all prerequisites with:
```bash
sudo apt-get update && sudo apt-get install -y nmap ffuf jq xsltproc curl
```

---

## 🚀 Installation

1. **Clone the repository** or download the `htbscan.sh` script:
   ```bash
   git clone https://github.com/yourusername/htbscan.git
   cd htbscan
   ```

2. **Make the script executable**:
   ```bash
   chmod +x htbscan.sh
   ```

---

## 🛠 Usage

### Basic Syntax
```bash
./htbscan.sh -i <TARGET_IP> -n <OUTPUT_NAME>
```

| Option | Description                     | Example          |
|--------|---------------------------------|------------------|
| `-i`    | Target IP address              | `10.10.10.10`    |
| `-n`    | Output directory name          | `machine1`        |

### Example
```bash
./htbscan.sh -i 10.10.10.10 -n machine1
```

---

## 📂 Results Structure

The scan results will be stored in a directory with the name you specified (`<OUTPUT_NAME>`):

```
<OUTPUT_NAME>/
├── nmap/
│   ├── initial.nmap    # Initial Nmap scan results
│   ├── initial.xml     # XML format of initial scan
│   ├── initial.html    # HTML report of initial scan
│   ├── full.xml        # Full port scan results
│   └── full.html       # HTML report of full scan
├── subdomain.json    # Subdomain discovery results
├── dirscan.json      # Directory discovery results
└── scan_errors.log     # Error log file
```

---

## 📝 Example Output

```bash
[+] Starting HTBScan for editor at IP 10.10.11.80
[*] Created directory: editor/nmap
[+] Running initial Nmap scan...
[+] Running full Nmap scan in background...
[*] Parsing initial Nmap for URL...
[*] Parsed HTTP_PORT: 80
[*] Other open HTTP ports detected: 8080
[+] Detected HTTP URL: http://editor.htb (Port: 80)
[*] Using domain for vhost fuzzing and hosts file: editor.htb
[+] Running subdomain/vhost scanning...
[*] Detecting common response sizes for filtering...
[+] subdomains/vhost scan completed. Results in machine1/ffuf_vhosts.json
[+] Running dirsearch...
[+] Dirsearch completed. Results in machine1/dirsearch.json
[+] Scan Summary for editor:
    Initial Nmap: editor/nmap/initial.nmap
    Detected URL: http://editor.htb
    Subdomain scan: editor/subdomain.json
    Directory scan: editor/dirsearch.json
[+] All scans completed.
```

---

## 🔧 Configuration

You can adjust the following environment variables at the top of the script:

```bash
export THREADS=25                  # Number of threads for FFUF
export DEPTH=1                     # Directory search depth
export EXTENSIONS=html,php,js,txt  # File extensions to search for
```

Wordlists paths (adjust according to your system):
```bash
export WORDLIST=/usr/share/wordlists/seclists/Discovery/Web-Content/raft-small-directories-lowercase.txt
export VHOST_WORDLIST=/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt
```

---

## 🤝 Contributing

Contributions are what make the open source community such an amazing place to learn, inspire, and create. Any contributions you make are **greatly appreciated**.

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

---

## �� License

Distributed under the MIT License. See `LICENSE` for more information.

---

## 📧 Contact

Project Link: [https://github.com/ExHo7/htbscan]

---

## 🙏 Acknowledgements

- [Exegol]
- [HackTheBox]
