#!/bin/bash

# Define the required tools
REQUIRED_TOOLS=(
    "nmap" "masscan" "nuclei" "ffuf" "gobuster" "dirsearch" "sqlmap" "xsstrike"
    "nikto" "wpscan" "whatweb" "wappalyzer" "sublist3r" "httpx" "shodan" "censys"
    "chaos" "feroxbuster" "gospider" "burpsuite" "acunetix" "openvas" "aqua" 
    "trivy" "docker-bench" "vulnscan" "webscan" "arachni" "zap" "grype" "curl" 
    "subfinder" "assetfinder" "httprobe" "wafw00f" "shuffledns" "dnsx" "dnsrecon"
    "theharvester" "recon-ng" "seclists" "alienvault" "binaryedge" "censys" "zoomeye"
)

# Function to check if a tool is installed
check_tool() {
    command -v "$1" >/dev/null 2>&1
}

# Check if all required tools are installed and collect uninstalled tools
UNINSTALLED_TOOLS=()
for tool in "${REQUIRED_TOOLS[@]}"; do
    if ! check_tool "$tool"; then
        UNINSTALLED_TOOLS+=("$tool")
    fi
done

# Report uninstalled tools if any
if [ ${#UNINSTALLED_TOOLS[@]} -ne 0 ]; then
    echo "The following required tools are not installed:"
    for tool in "${UNINSTALLED_TOOLS[@]}"; do
        echo "- $tool"
    done
    echo "Please install these tools before running the script."
    exit 1
fi

# Set the domain and timestamp for file naming
DOMAIN="example.com"  # Change this to your target domain
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
OUTPUT_DIR="./scan_results"
mkdir -p "$OUTPUT_DIR"

# Define the output file
OUTPUT_FILE="$OUTPUT_DIR/${DOMAIN}-${TIMESTAMP}-scan.txt"

# Start logging
exec > >(tee -a "$OUTPUT_FILE") 2>&1

echo "Starting deep scanning on $DOMAIN..."

# Load subdomains from reconnaissance results
SUBDOMAINS_FILE="${OUTPUT_DIR}/${DOMAIN}-${TIMESTAMP}-recon.txt"
if [ ! -f "$SUBDOMAINS_FILE" ]; then
    echo "Subdomain file not found! Please ensure reconnaissance phase has been completed."
    exit 1
fi

# Initialize command counter
COMMAND_COUNT=0

# Define a function to increment command count
increment_command_count() {
    COMMAND_COUNT=$((COMMAND_COUNT + 1))
    echo "Executing command #$COMMAND_COUNT"
}

# Port Scanning with nmap
echo "1. Port Scanning with nmap"
while read -r subdomain; do
    increment_command_count
    nmap -p- --open $subdomain -oN "${OUTPUT_DIR}/${subdomain}_nmap_scan.txt"
done < "$SUBDOMAINS_FILE"

# Port Scanning with masscan
echo "2. Port Scanning with masscan"
while read -r subdomain; do
    increment_command_count
    masscan -p1-65535 $subdomain --rate=1000 -oL "${OUTPUT_DIR}/${subdomain}_masscan_scan.txt"
done < "$SUBDOMAINS_FILE"

# Vulnerability Scanning with nuclei
echo "3. Vulnerability Scanning with nuclei"
while read -r subdomain; do
    increment_command_count
    nuclei -u $subdomain -t /path/to/nuclei-templates/ -o "${OUTPUT_DIR}/${subdomain}_nuclei_results.txt"
done < "$SUBDOMAINS_FILE"

# Directory and File Enumeration with ffuf
echo "4. Directory and File Enumeration with ffuf"
while read -r subdomain; do
    increment_command_count
    ffuf -u https://$subdomain/FUZZ -w /path/to/wordlist.txt -o "${OUTPUT_DIR}/${subdomain}_ffuf_results.txt"
done < "$SUBDOMAINS_FILE"

# Directory Enumeration with gobuster
echo "5. Directory Enumeration with gobuster"
while read -r subdomain; do
    increment_command_count
    gobuster dir -u https://$subdomain -w /path/to/wordlist.txt -o "${OUTPUT_DIR}/${subdomain}_gobuster_results.txt"
done < "$SUBDOMAINS_FILE"

# Directory Enumeration with dirsearch
echo "6. Directory Enumeration with dirsearch"
while read -r subdomain; do
    increment_command_count
    dirsearch -u https://$subdomain -w /path/to/wordlist.txt -o "${OUTPUT_DIR}/${subdomain}_dirsearch_results.txt"
done < "$SUBDOMAINS_FILE"

# SQL Injection Testing with sqlmap
echo "7. SQL Injection Testing with sqlmap"
while read -r subdomain; do
    increment_command_count
    sqlmap -u https://$subdomain --batch --crawl=3 -o "${OUTPUT_DIR}/${subdomain}_sqlmap_results.txt"
done < "$SUBDOMAINS_FILE"

# Cross-Site Scripting (XSS) Testing with xsstrike
echo "8. Cross-Site Scripting (XSS) Testing with xsstrike"
while read -r subdomain; do
    increment_command_count
    xsstrike -u https://$subdomain -o "${OUTPUT_DIR}/${subdomain}_xsstrike_results.txt"
done < "$SUBDOMAINS_FILE"

# Web Application Scanning with nikto
echo "9. Web Application Scanning with nikto"
while read -r subdomain; do
    increment_command_count
    nikto -h https://$subdomain -o "${OUTPUT_DIR}/${subdomain}_nikto_results.txt"
done < "$SUBDOMAINS_FILE"

# Web Application Scanning with wpscan (for WordPress sites)
echo "10. Web Application Scanning with wpscan"
while read -r subdomain; do
    increment_command_count
    wpscan --url https://$subdomain --enumerate p --disable-tls-checks -o "${OUTPUT_DIR}/${subdomain}_wpscan_results.txt"
done < "$SUBDOMAINS_FILE"

# Web Technology Detection with whatweb
echo "11. Web Technology Detection with whatweb"
while read -r subdomain; do
    increment_command_count
    whatweb -a 2 $subdomain -o "${OUTPUT_DIR}/${subdomain}_whatweb_results.txt"
done < "$SUBDOMAINS_FILE"

# Web Technology Detection with wappalyzer
echo "12. Web Technology Detection with wappalyzer"
while read -r subdomain; do
    increment_command_count
    wappalyzer -u https://$subdomain -o "${OUTPUT_DIR}/${subdomain}_wappalyzer_results.txt"
done < "$SUBDOMAINS_FILE"

# Subdomain Scanning with shodan
echo "13. Subdomain Scanning with shodan"
while read -r subdomain; do
    increment_command_count
    shodan host $subdomain -o "${OUTPUT_DIR}/${subdomain}_shodan_results.txt"
done < "$SUBDOMAINS_FILE"

# Subdomain Scanning with censys
echo "14. Subdomain Scanning with censys"
while read -r subdomain; do
    increment_command_count
    censys search "dns.domain: $subdomain" -o "${OUTPUT_DIR}/${subdomain}_censys_results.txt"
done < "$SUBDOMAINS_FILE"

# General Vulnerability Scanning with chaos
echo "15. General Vulnerability Scanning with chaos"
while read -r subdomain; do
    increment_command_count
    chaos -d $subdomain -o "${OUTPUT_DIR}/${subdomain}_chaos_results.txt"
done < "$SUBDOMAINS_FILE"

# Directory Enumeration with feroxbuster
echo "16. Directory Enumeration with feroxbuster"
while read -r subdomain; do
    increment_command_count
    feroxbuster -u https://$subdomain -w /path/to/wordlist.txt -o "${OUTPUT_DIR}/${subdomain}_feroxbuster_results.txt"
done < "$SUBDOMAINS_FILE"

# Spidering with gospider
echo "17. Spidering with gospider"
while read -r subdomain; do
    increment_command_count
    gospider -S https://$subdomain -o "${OUTPUT_DIR}/${subdomain}_gospider_results.txt"
done < "$SUBDOMAINS_FILE"

# Burp Suite Scan (requires configuration)
echo "18. Burp Suite Scan"
while read -r subdomain; do
    increment_command_count
    # Requires Burp Suite Pro and configuration
    # Example: burpsuite-pro --target https://$subdomain --output "${OUTPUT_DIR}/${subdomain}_burpsuite_results.txt"
done < "$SUBDOMAINS_FILE"

# Acunetix Scan (requires configuration)
echo "19. Acunetix Scan"
while read -r subdomain; do
    increment_command_count
    # Requires Acunetix and configuration
    # Example: acunetix scan --target https://$subdomain --output "${OUTPUT_DIR}/${subdomain}_acunetix_results.txt"
done < "$SUBDOMAINS_FILE"

# OpenVAS Scan (requires configuration)
echo "20. OpenVAS Scan"
while read -r subdomain; do
    increment_command_count
    # Requires OpenVAS and configuration
    # Example: openvas-cli -u https://$subdomain -o "${OUTPUT_DIR}/${subdomain}_openvas_results.txt"
done < "$SUBDOMAINS_FILE"

# Docker Vulnerability Scanning with trivy
echo "21. Docker Vulnerability Scanning with trivy"
while read -r subdomain; do
    increment_command_count
    trivy image $subdomain -o "${OUTPUT_DIR}/${subdomain}_trivy_results.txt"
done < "$SUBDOMAINS_FILE"

# Docker Bench Scanning with docker-bench
echo "22. Docker Bench Scanning with docker-bench"
while read -r subdomain; do
    increment_command_count
    docker-bench-security -i $subdomain -o "${OUTPUT_DIR}/${subdomain}_docker_bench_results.txt"
done < "$SUBDOMAINS_FILE"

# General Vulnerability Scanning with vulnscan
echo "23. General Vulnerability Scanning with vulnscan"
while read -r subdomain; do
    increment_command_count
    vulnscan -u https://$subdomain -o "${OUTPUT_DIR}/${subdomain}_vulnscan_results.txt"
done < "$SUBDOMAINS_FILE"

# Web Scanning with webscan
echo "24. Web Scanning with webscan"
while read -r subdomain; do
    increment_command_count
    webscan -u https://$subdomain -o "${OUTPUT_DIR}/${subdomain}_webscan_results.txt"
done < "$SUBDOMAINS_FILE"

# Web Application Scanning with arachni
echo "25. Web Application Scanning with arachni"
while read -r subdomain; do
    increment_command_count
    arachni https://$subdomain --output-json="${OUTPUT_DIR}/${subdomain}_arachni_results.json"
done < "$SUBDOMAINS_FILE"

# OWASP ZAP Scan (requires configuration)
echo "26. OWASP ZAP Scan"
while read -r subdomain; do
    increment_command_count
    # Requires OWASP ZAP and configuration
    # Example: zap-cli -u https://$subdomain -o "${OUTPUT_DIR}/${subdomain}_zap_results.txt"
done < "$SUBDOMAINS_FILE"

# Grype Scan (for container vulnerabilities)
echo "27. Grype Scan"
while read -r subdomain; do
    increment_command_count
    grype $subdomain -o "${OUTPUT_DIR}/${subdomain}_grype_results.txt"
done < "$SUBDOMAINS_FILE"

# HTTP Probe with httprobe
echo "28. HTTP Probe with httprobe"
while read -r subdomain; do
    increment_command_count
    httprobe -p https: -p http: -o "${OUTPUT_DIR}/${subdomain}_httprobe_results.txt"
done < "$SUBDOMAINS_FILE"

# WAF Detection with wafw00f
echo "29. WAF Detection with wafw00f"
while read -r subdomain; do
    increment_command_count
    wafw00f $subdomain -o "${OUTPUT_DIR}/${subdomain}_wafw00f_results.txt"
done < "$SUBDOMAINS_FILE"

# DNS Enumeration with dnsx
echo "30. DNS Enumeration with dnsx"
while read -r subdomain; do
    increment_command_count
    dnsx -d $subdomain -o "${OUTPUT_DIR}/${subdomain}_dnsx_results.txt"
done < "$SUBDOMAINS_FILE"

# DNS Recon with dnsrecon
echo "31. DNS Recon with dnsrecon"
while read -r subdomain; do
    increment_command_count
    dnsrecon -d $subdomain -o "${OUTPUT_DIR}/${subdomain}_dnsrecon_results.txt"
done < "$SUBDOMAINS_FILE"

# Subdomain Enumeration with subfinder
echo "32. Subdomain Enumeration with subfinder"
while read -r subdomain; do
    increment_command_count
    subfinder -d $subdomain -o "${OUTPUT_DIR}/${subdomain}_subfinder_results.txt"
done < "$SUBDOMAINS_FILE"

# Subdomain Enumeration with assetfinder
echo "33. Subdomain Enumeration with assetfinder"
while read -r subdomain; do
    increment_command_count
    assetfinder -subs-only $subdomain -o "${OUTPUT_DIR}/${subdomain}_assetfinder_results.txt"
done < "$SUBDOMAINS_FILE"

# Subdomain Enumeration with shuffledns
echo "34. Subdomain Enumeration with shuffledns"
while read -r subdomain; do
    increment_command_count
    shuffledns -d $subdomain -o "${OUTPUT_DIR}/${subdomain}_shuffledns_results.txt"
done < "$SUBDOMAINS_FILE"

# The Harvester for information gathering
echo "35. The Harvester"
while read -r subdomain; do
    increment_command_count
    theharvester -d $subdomain -b all -o "${OUTPUT_DIR}/${subdomain}_theharvester_results.txt"
done < "$SUBDOMAINS_FILE"

# Recon-ng for information gathering
echo "36. Recon-ng"
while read -r subdomain; do
    increment_command_count
    recon-ng -m recon/domains-hosts/brute_hosts -o ${subdomain} -o "${OUTPUT_DIR}/${subdomain}_recon-ng_results.txt"
done < "$SUBDOMAINS_FILE"

# AlienVault for information gathering
echo "37. AlienVault"
while read -r subdomain; do
    increment_command_count
    # Requires AlienVault and configuration
    # Example: alienvault --domain $subdomain -o "${OUTPUT_DIR}/${subdomain}_alienvault_results.txt"
done < "$SUBDOMAINS_FILE"

# BinaryEdge for information gathering
echo "38. BinaryEdge"
while read -r subdomain; do
    increment_command_count
    # Requires BinaryEdge and configuration
    # Example: binaryedge -d $subdomain -o "${OUTPUT_DIR}/${subdomain}_binaryedge_results.txt"
done < "$SUBDOMAINS_FILE"

# Censys for information gathering
echo "39. Censys"
while read -r subdomain; do
    increment_command_count
    censys search "dns.domain: $subdomain" -o "${OUTPUT_DIR}/${subdomain}_censys_results.txt"
done < "$SUBDOMAINS_FILE"

# ZoomEye for information gathering
echo "40. ZoomEye"
while read -r subdomain; do
    increment_command_count
    # Requires ZoomEye and configuration
    # Example: zoomeye search $subdomain -o "${OUTPUT_DIR}/${subdomain}_zoomeye_results.txt"
done < "$SUBDOMAINS_FILE"

echo "Scanning completed. Results saved to $OUTPUT_FILE"
