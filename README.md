# HTBRecon
An automated reconnaissance script for Hack The Box

## Description

HTBRecon is a Bash script designed to automate the reconnaissance phase during Hack The Box challenges. It performs a series of scans to identify services, open ports, subdomains, web directories, and potential vulnerabilities.

## Features

- Initial Nmap scan to identify open ports and services.
- Full background Nmap scan.
- Automatic detection of HTTP/HTTPS URLs.
- Subdomain scanning with FFUF.
- Web directory scanning with FFUF.
- Option to perform vulnerability scans with Nuclei (disabled by default).
- Support for recursive scans on subdomains.
- Conversion of Nmap results to HTML format.
- Error handling and logging.

## Installation

### Dependencies

Before using HTBRecon, ensure the following tools are installed on your system:

- `nmap`: For port and service scanning.
- `ffuf`: For subdomain and directory fuzzing.
- `jq`: For JSON data processing.
- `xsltproc` (optional): For converting Nmap results to HTML.
- `nuclei` (optional): For vulnerability scanning.

### Installing Dependencies

You can install the required dependencies with the following command:

```bash
sudo apt update && sudo apt install -y nmap ffuf jq xsltproc
```

To install Nuclei, follow the instructions on the Nuclei GitHub repository.

Downloading the Script
Clone the repository or download the script directly:
```bash
git clone https://github.com/your-username/HTBRecon.git
cd HTBRecon
chmod +x htb-recon.sh
```

## Usage
Available Options
```bash
-i <IP> Target IP address (required).
-n <NAME> Output directory name (required).
-r Enable recursive scans on subdomains (can be slow).
--nuclei Enable vulnerability scans with Nuclei.
-h Display help.
```

### Example Usage
To perform a basic scan on a machine with IP 10.10.10.10 and save results in a directory named machine1:
```bash
./htb-recon.sh -i 10.10.10.10 -n machine1
```

To perform a full scan with recursion and Nuclei scans:
```bash
./htb-recon.sh -i 10.10.10.10 -n machine1 -r --nuclei
```

### Output
The script generates several output files organized in the directory specified by the -n parameter. Here's a description of the main files generated:

nmap/initial.nmap: Results of the initial Nmap scan.
nmap/full.html: Results of the full Nmap scan in HTML format (if xsltproc is installed).
subdomains.json: Results of the subdomain scan.
dirscan.json: Results of the directory scan.
nuclei.json: Results of the vulnerability scan with Nuclei (if enabled).
scan_errors.log: Log of any errors encountered.
