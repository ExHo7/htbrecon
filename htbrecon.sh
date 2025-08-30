#!/bin/bash

# Adjustable environment variables
export THREADS=25
export WORDLIST=/usr/share/wordlists/seclists/Discovery/Web-Content/raft-small-directories-lowercase.txt  # Default wordlist for dirsearch
export VHOST_WORDLIST=/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt  # Wordlist for vhost/subdomain fuzzing
export NMAP_FULL_OPTS="-A -p-"  # Options for full Nmap scan
export DEPTH=1 # Recursion depth for dirsearch
export EXTENSIONS=html,php,js,txt,bak,kdbx # Extensions for dirsearch
RECURSION=false 

# Color codes
RED="\e[31m"
GREEN="\e[32m"
YELLOW="\e[33m"
BLUE="\e[34m"
MAGENTA="\e[35m"
CYAN="\e[36m"
RESET="\e[0m"

# Function to display banner with blue-violet gradient
display_banner() {
echo -e "${BLUE}"
cat <<'EOF'
  _    _ _______ ____  _____                      
 | |  | |__   __|  _ \|  __ \                     
 | |__| |  | |  | |_) | |__) |___  ___ ___  _ __  
 |  __  |  | |  |  _ <|  _  // _ \/ __/ _ \| '_ \ 
 | |  | |  | |  | |_) | | \ \  __/ (_| (_) | | | |
 |_|  |_|  |_|  |____/|_|  \_\___|\___\___/|_| |_|
                                                  
EOF
echo -e "${RESET}"
echo -e "${MAGENTA}Made with 💚 by cyber_fish 🐡${RESET}"
echo ""
}

parse_args() {
    while getopts "i:n:rh" opt; do
        case $opt in
            i) IP="$OPTARG" ;;
            n) NAME="$OPTARG" ;;
            r) RECURSION=true ;;
            h)
                echo -e "${GREEN}HTBRecon - Recon scanner for Hack The Box${RESET}"
                echo -e "${YELLOW}Usage: $0 -i <IP> -n <NAME> [OPTIONS]${RESET}"
                echo -e "${YELLOW}Options:${RESET}"
                echo -e "  -i <IP>     Target IP address"
                echo -e "  -n <NAME>   Output directory name"
                echo -e "  -r          Enable recursive scans on subdomains (FFUF + Nuclei)"
                echo -e "  -h          Show this help message${RESET}"
                exit 0
                ;;
            *)
                echo -e "${RED}Error: Invalid option.${RESET}"
                echo -e "${RED}Usage: $0 -i <IP> -n <NAME> [-r]${RESET}"
                echo -e "${YELLOW}Use -h for help.${RESET}"
                exit 1
                ;;
        esac
    done

    if [ -z "$IP" ] || [ -z "$NAME" ]; then
        echo -e "${RED}Error: Missing required arguments.${RESET}"
        echo -e "${RED}Usage: $0 -i <IP> -n <NAME> [-r]${RESET}"
        echo -e "${YELLOW}Use -h for help.${RESET}"
        exit 1
    fi
}


# Function to update /etc/hosts
update_hosts() {
    local ip="$1"
    local domain="$2"
    local hosts_file="/etc/hosts"

    # Check if the domain already exists in /etc/hosts
    if grep -q "$domain" "$hosts_file"; then
        echo -e "${YELLOW}[*] Domain $domain already exists in $hosts_file. Skipping update.${RESET}"
        return
    fi

    # Check if we have write permissions
    if [ -w "$hosts_file" ]; then
        echo -e "${GREEN}[+] Adding $ip $domain to $hosts_file${RESET}"
        echo "$ip $domain" | tee -a "$hosts_file" >/dev/null 2>>"$LOG_FILE"
    else
        echo -e "${RED}[-] No write permission for $hosts_file. Please run with sudo or manually add the following to $hosts_file:${RESET}"
        echo -e "${CYAN}$ip $domain${RESET}"
        echo -e "${YELLOW}[*] Continuing without modifying $hosts_file.${RESET}"
    fi
}

# Function to check log file for errors
check_log() {
    if [ -s "$LOG_FILE" ]; then
        echo -e "${RED}[-] Errors occurred during scanning. Check $LOG_FILE for details.${RESET}"
    fi
}

# Check dependencies
check_dependencies() {
    if ! command -v nmap &> /dev/null; then
        echo -e "${RED}[-] Nmap is not installed. Please install it first.${RESET}"
        exit 1
    fi
    if ! command -v jq &> /dev/null; then
        echo -e "${RED}[-] jq is not installed. Please install it first.${RESET}"
        exit 1
    fi
    if ! command -v xsltproc &> /dev/null; then
        echo -e "${YELLOW}[*] xsltproc is not installed. HTML conversion will be skipped.${RESET}"
        NO_XSLTPROC=true
    fi
}

# Main function
main() {
    check_dependencies
    display_banner
    parse_args "$@"

    LOG_FILE="$NAME/scan_errors.log"

    echo -e "${GREEN}[+] Starting HTBScan for $NAME at IP $IP${RESET} 🚀"

    # Create directory structure
    mkdir -p "$NAME/nmap"
    echo -e "${YELLOW}[*] Created directory: $NAME/nmap${RESET}"

    # Initialize log file
    : > "$LOG_FILE"

    # Initial Nmap scan
    echo -e "${GREEN}[+] Running initial Nmap scan...${RESET}"
    if ! nmap -sC -sV -T4 $IP -oA "$NAME/nmap/initial" 2>>"$LOG_FILE"; then
        echo -e "${RED}[-] Initial Nmap scan failed. Check $LOG_FILE for details.${RESET}"
        cat "$LOG_FILE"
        exit 1
    fi

    # Check if Nmap output file exists
    if [ ! -f "$NAME/nmap/initial.nmap" ]; then
        echo -e "${RED}[-] Nmap output file $NAME/nmap/initial.nmap not found. Exiting.${RESET}"
        exit 1
    fi

    # Full Nmap scan in background with HTML conversion
    echo -e "${GREEN}[+] Running full Nmap scan in background...${RESET}"
    (nmap $NMAP_FULL_OPTS $IP -oX "$NAME/nmap/full.xml" >/dev/null 2>>"$LOG_FILE" && \
     if [ -z "$NO_XSLTPROC" ]; then \
        xsltproc "$NAME/nmap/full.xml" -o "$NAME/nmap/full.html" >/dev/null 2>>"$LOG_FILE" && \
        echo -e "${GREEN}[+] Full scan and HTML conversion completed.${RESET}"; \
    else \
        echo -e "${YELLOW}[*] xsltproc not installed. Skipping HTML conversion.${RESET}"; \
    fi) &

    # Parse initial Nmap for open HTTP/HTTPS ports and redirects
    echo -e "${YELLOW}[*] Parsing initial Nmap for URL...${RESET}"
    HTTP_PORT=$(grep -iE '80/tcp.*open.*http' "$NAME/nmap/initial.nmap" | awk -F/ '{print $1}')
    HTTPS_PORT=$(grep -iE '443/tcp.*open.*https' "$NAME/nmap/initial.nmap" | awk -F/ '{print $1}')
    REDIRECT_URL=$(grep -iE '_http-title:.*redirect to' "$NAME/nmap/initial.nmap" | sed -n 's/.*[Rr]edirect to \+\([^ ]*\).*/\1/p' | head -n 1)
 
    # Detect other open HTTP ports
    echo -e "${YELLOW}[*] Detect orther open HTTP ports...${RESET}"
    OTHER_HTTP_PORTS=$(grep -E '(8080|3000|8000|8888)/tcp.*open' "$NAME/nmap/initial.nmap" | awk -F/ '{print $1}' | tr '\n' ' ')

    # Inform the user about other open HTTP ports
    if [ -n "$OTHER_HTTP_PORTS" ]; then
        echo -e "${CYAN}[*] Other open HTTP ports detected: $OTHER_HTTP_PORTS${RESET}"
    else
        echo -e "${YELLOW}[-] No other open HTTP ports detected.${RESET}"
    fi
    
    # URL Detection
    if [ ! -z "$REDIRECT_URL" ]; then
        URL="$REDIRECT_URL"
        PORT=$(echo "$URL" | grep -q "https://" && echo 443 || echo 80)
        echo -e "${GREEN}[+] Detected redirect URL: $URL (Port: $PORT)${RESET}"
    elif [ ! -z "$HTTPS_PORT" ]; then
        URL="https://$IP"
        PORT=443
        echo -e "${GREEN}[+] Detected HTTPS URL: $URL (Port: $PORT)${RESET}"
    elif [ ! -z "$HTTP_PORT" ]; then
        URL="http://$IP"
        PORT=80
        echo -e "${GREEN}[+] Detected HTTP URL: $URL (Port: $PORT)${RESET}"
    else
        echo -e "${RED}[-] No HTTP/HTTPS ports or redirect found. Exiting.${RESET}"
        exit 1
    fi

    # Extract domain for FFUF vhost fuzzing and /etc/hosts update
    DOMAIN=$(echo "$URL" | sed -e 's|http[s]*://||' -e 's|/.*||')
    echo -e "${YELLOW}[*] Using domain for vhost fuzzing and hosts file: $DOMAIN${RESET}"

    # Update /etc/hosts with the domain
    update_hosts "$IP" "$DOMAIN"

    # FFUF for subdomains/vhosts
    echo -e "${GREEN}[+] Running subdomain scanning...${RESET}"
    # Initial FFUF run to detect common response sizes
    echo -e "${YELLOW}[*] Detecting common response sizes for filtering...${RESET}"
    ffuf -u "$URL" -H "Host: FUZZ.$DOMAIN" -w "$VHOST_WORDLIST" -t $THREADS -o $NAME/ffuf_initial.json > /dev/null 2>&1

    # Parse common sizes (assuming jq is installed for JSON parsing)
    COMMON_SIZES=$(jq '.results[] | .length' $NAME/ffuf_initial.json 2>>"$LOG_FILE" | sort | uniq -c | sort -nr | head -n 1 | awk '{print $2}' | paste -sd, -)
    if [ -n "$COMMON_SIZES" ]; then
        FS_PARAM="-fs $COMMON_SIZES"
        echo -e "${YELLOW}[*] Detected recurrent sizes: $COMMON_SIZES. Applying filter: $FS_PARAM${RESET}"
    else
        FS_PARAM=""
        echo -e "${YELLOW}[*] No common sizes detected. Proceeding without size filter.${RESET}"
    fi

    # Rerun FFUF with filter
    ffuf -u "$URL" -H "Host: FUZZ.$DOMAIN" -w "$VHOST_WORDLIST" -t $THREADS -mc all $FS_PARAM -o "$NAME/subdomains.json" > /dev/null 2>&1
    FFUF_EXIT=$?
    if [ $FFUF_EXIT -eq 0 ] || [ $FFUF_EXIT -eq 2 ]; then
        echo -e "${GREEN}[+] subdomains scan completed. Results in $NAME/subdomains.json${RESET}"
        FOUND_SUBDOMAINS=$(jq -r '.results[] | select(.status != 0) | .input.FUZZ' "$NAME/subdomains.json")
        if [ -n "$FOUND_SUBDOMAINS" ]; then
            echo -e "${CYAN}[+] Subdomain found ✨:${RESET}"
            while read -r sub; do
                full_subdomain="$sub.$DOMAIN"
                echo -e "${YELLOW}    $full_subdomain${RESET}"
                update_hosts "$IP" "$full_subdomain"
                if [ "$RECURSION" = true ]; then
                    echo -e "${GREEN}[+] Running Nuclei on $full_subdomain...please wait ☕${RESET}"
                    nuclei -u "http://$full_subdomain" -as -json-export "$NAME/nuclei_${sub}.json" > /dev/null 2>&1 &
                    echo -e "${GREEN}[+] Running directory scan on $full_subdomain...please wait ☕${RESET}"
                    ffuf -u "http://$full_subdomain/FUZZ" -w "$WORDLIST" -t $THREADS -recursion-depth $DEPTH -e $EXTENSIONS -o "$NAME/dirscan_${sub}.json" > /dev/null 2>&1 &
                fi
            done < <(echo "$FOUND_SUBDOMAINS")
            wait
        else
            echo -e "${YELLOW}[-] Sorry nothing find.${RESET}"
        fi
    fi

    # Dirsearch for directories using the full Nmap XML report
    echo -e "${GREEN}[+] Running dirsearch...please wait ☕${RESET}"
    ffuf -u "${URL%/}/FUZZ" -w "$WORDLIST" -t $THREADS -recursion-depth $DEPTH -e $EXTENSIONS -r -o "$NAME/dirscan.json" > /dev/null 2>&1
    FFUF_EXIT=$?
    if [ $FFUF_EXIT -eq 0 ] || [ $FFUF_EXIT -eq 2 ]; then
        echo -e "${GREEN}[+] Dirsearch completed. Results in $NAME/dirscan.json${RESET}"
	FOUND_DIRECTORY=$(jq -r '.results[] | select(.status != 0) | .input.FUZZ' "$NAME/dirscan.json")
        if [ -n "$FOUND_DIRECTORY" ]; then
            echo -e "${CYAN}[+] Directory found ✨:${RESET}"
            echo "$FOUND_DIRECTORY" | while read dir; do
                echo -e "${YELLOW}    $DOMAIN/$dir${RESET}"
            done
        else
            echo -e "${YELLOW}[-] Sorry nothing find.${RESET}"
        fi
    fi

    # Nuclei
    echo -e "${GREEN}[+] Running Nuclei...please wait ☕${RESET}"
    nuclei -u "$URL" -as -json-export "$NAME/nuclei.json" > /dev/null 2>&1
    FFUF_EXIT=$?
    if [ $FFUF_EXIT -eq 0 ] || [ $FFUF_EXIT -eq 2 ]; then
	echo -e "${GREEN}[+] Nuclei scan completed. Results in $NAME/nuclei.json${RESET}"
    FOUND_VULNERABILITY=$(jq -r '.[] | select(.info.severity as $severity | ($severity == "low" or $severity == "medium" or $severity == "high")) | "\(.info.name) - Severity: \(.info.severity)"' "$NAME/nuclei.json")
        if [ -n "$FOUND_VULNERABILITY" ]; then
            echo -e "${CYAN}[+] Vulnerability found ✨:${RESET}"
            echo "$FOUND_VULNERABILITY" | while read vuln; do
                echo -e "${YELLOW}    $vuln${RESET}"
            done
        else
            echo -e "${YELLOW}[*] Sorry nothing found.${RESET}"
        fi
    fi

    # Wait for background processes
    wait

    # Check for errors in log file
    check_log

    # Display subdomains found
    if [ -n "$FOUND_SUBDOMAINS" ]; then
        echo -e "${CYAN}Subdomains discovered:${RESET}"
        while read -r sub; do
            echo -e "${YELLOW}    $sub.$DOMAIN${RESET}"
        done < <(echo "$FOUND_SUBDOMAINS")
    fi

    # Display directories found
    if [ -n "$FOUND_DIRECTORY" ]; then
        echo -e "${CYAN}Directories discovered:${RESET}"
        echo "$FOUND_DIRECTORY" | while read dir; do
            echo -e "${YELLOW}    $DOMAIN/$dir${RESET}"
        done
    fi

    # Display vulnerabilities found
    if [ -n "$FOUND_VULNERABILITY" ]; then
        echo -e "${CYAN}Vulnerabilities discovered:${RESET}"
        echo "$FOUND_VULNERABILITY" | while read vuln; do
            echo -e "${YELLOW}    $vuln${RESET}"
        done
    fi

    # Display summary
    echo -e "${GREEN}[+] Scan Summary for $NAME:${RESET}"
    echo -e "${CYAN}Other open HTTP ports: $OTHER_HTTP_PORTS${RESET}"
    echo -e "${CYAN}Initial Nmap: $NAME/nmap/initial.nmap${RESET}"
    echo -e "${CYAN}Full Nmap: $NAME/nmap/full.html${RESET}"
    echo -e "${CYAN}Detected URL: $URL${RESET}"
    echo -e "${CYAN}Nuclei scan: $NAME/nuclei.json${RESET}"
    echo -e "${GREEN}[+] All scans completed.${RESET}"
}

main "$@"