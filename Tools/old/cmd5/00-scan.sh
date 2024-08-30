#!/bin/bash

# Define the required tools
REQUIRED_TOOLS=(
    "nmap" "masscan" "nuclei" "ffuf" "gobuster" "dirsearch" "sqlmap" "xsstrike"
    "nikto" "wpscan" "whatweb" "wappalyzer" "sublist3r" "httpx" "shodan" "censys"
    "chaos" "feroxbuster" "gospider" "burpsuite" "acunetix" "openvas" "aqua" 
    "trivy" "docker-bench" "vulnscan" "webscan" "arachni" "zap" "grype" "curl" 
    "subfinder" "assetfinder" "httprobe" "wafw00f" "shuffledns" "dnsx" "dnsrecon"
    "theharvester" "recon-ng" "seclists" "alienvault" "binaryedge" "zoomeye"
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

echo "Starting deep reconnaissance and scanning on $DOMAIN..."

# Reconnaissance Phase

echo ""
echo "****************************************"
echo "1. Subdomain enumeration with sublist3r"
echo "****************************************"
sublist3r -d $DOMAIN -o "${OUTPUT_DIR}/${DOMAIN}-${TIMESTAMP}-sublist3r.txt"

echo ""
echo "****************************************"
echo "2. Subdomain enumeration with subfinder"
echo "****************************************"
subfinder -d $DOMAIN -o "${OUTPUT_DIR}/${DOMAIN}-${TIMESTAMP}-subfinder.txt"

echo ""
echo "****************************************"
echo "3. Subdomain enumeration with assetfinder"
echo "****************************************"
assetfinder -subs-only $DOMAIN -o "${OUTPUT_DIR}/${DOMAIN}-${TIMESTAMP}-assetfinder.txt"

echo ""
echo "****************************************"
echo "4. Subdomain enumeration with theharvester"
echo "****************************************"
theharvester -d $DOMAIN -b all -o "${OUTPUT_DIR}/${DOMAIN}-${TIMESTAMP}-theharvester.txt"

echo ""
echo "****************************************"
echo "5. Subdomain enumeration with recon-ng"
echo "****************************************"
recon-ng -m recon/domains-hosts/brute_hosts -o ${DOMAIN} -o "${OUTPUT_DIR}/${DOMAIN}-${TIMESTAMP}-recon-ng.txt"

# Combine all subdomains found
cat "${OUTPUT_DIR}/${DOMAIN}-${TIMESTAMP}-sublist3r.txt" \
    "${OUTPUT_DIR}/${DOMAIN}-${TIMESTAMP}-subfinder.txt" \
    "${OUTPUT_DIR}/${DOMAIN}-${TIMESTAMP}-assetfinder.txt" \
    "${OUTPUT_DIR}/${DOMAIN}-${TIMESTAMP}-theharvester.txt" \
    "${OUTPUT_DIR}/${DOMAIN}-${TIMESTAMP}-recon-ng.txt" | sort -u > "${OUTPUT_DIR}/${DOMAIN}-${TIMESTAMP}-recon.txt"

# Ensure there's a list of subdomains for scanning
if [ ! -s "${OUTPUT_DIR}/${DOMAIN}-${TIMESTAMP}-recon.txt" ]; then
    echo "No subdomains found during reconnaissance. Exiting."
    exit 1
fi

# Scanning Phase

echo ""
echo "****************************************"
echo "6. Port Scanning with nmap"
echo "****************************************"
while read -r subdomain; do
    nmap -p- --open $subdomain -oN "${OUTPUT_DIR}/${subdomain}_nmap_scan.txt"
done < "${OUTPUT_DIR}/${DOMAIN}-${TIMESTAMP}-recon.txt"

echo ""
echo "****************************************"
echo "7. Port Scanning with masscan"
echo "****************************************"
while read -r subdomain; do
    masscan -p1-65535 $subdomain --rate=1000 -oL "${OUTPUT_DIR}/${subdomain}_masscan_scan.txt"
done < "${OUTPUT_DIR}/${DOMAIN}-${TIMESTAMP}-recon.txt"

echo ""
echo "****************************************"
echo "8. Vulnerability Scanning with nuclei"
echo "****************************************"
while read -r subdomain; do
    nuclei -u $subdomain -t /path/to/nuclei-templates/ -o "${OUTPUT_DIR}/${subdomain}_nuclei_results.txt"
done < "${OUTPUT_DIR}/${DOMAIN}-${TIMESTAMP}-recon.txt"

echo ""
echo "****************************************"
echo "9. Directory and File Enumeration with ffuf"
echo "****************************************"
while read -r subdomain; do
    ffuf -u https://$subdomain/FUZZ -w /path/to/wordlist.txt -o "${OUTPUT_DIR}/${subdomain}_ffuf_results.txt"
done < "${OUTPUT_DIR}/${DOMAIN}-${TIMESTAMP}-recon.txt"

echo ""
echo "****************************************"
echo "10. Directory Enumeration with gobuster"
echo "****************************************"
while read -r subdomain; do
    gobuster dir -u https://$subdomain -w /path/to/wordlist.txt -o "${OUTPUT_DIR}/${subdomain}_gobuster_results.txt"
done < "${OUTPUT_DIR}/${DOMAIN}-${TIMESTAMP}-recon.txt"

echo ""
echo "****************************************"
echo "11. Directory Enumeration with dirsearch"
echo "****************************************"
while read -r subdomain; do
    dirsearch -u https://$subdomain -w /path/to/wordlist.txt -o "${OUTPUT_DIR}/${subdomain}_dirsearch_results.txt"
done < "${OUTPUT_DIR}/${DOMAIN}-${TIMESTAMP}-recon.txt"

echo ""
echo "****************************************"
echo "12. SQL Injection Testing with sqlmap"
echo "****************************************"
while read -r subdomain; do
    sqlmap -u https://$subdomain --batch --crawl=3 -o "${OUTPUT_DIR}/${subdomain}_sqlmap_results.txt"
done < "${OUTPUT_DIR}/${DOMAIN}-${TIMESTAMP}-recon.txt"

echo ""
echo "****************************************"
echo "13. Cross-Site Scripting (XSS) Testing with xsstrike"
echo "****************************************"
while read -r subdomain; do
    xsstrike -u https://$subdomain -o "${OUTPUT_DIR}/${subdomain}_xsstrike_results.txt"
done < "${OUTPUT_DIR}/${DOMAIN}-${TIMESTAMP}-recon.txt"

echo ""
echo "****************************************"
echo "14. Web Application Scanning with nikto"
echo "****************************************"
while read -r subdomain; do
    nikto -h https://$subdomain -o "${OUTPUT_DIR}/${subdomain}_nikto_results.txt"
done < "${OUTPUT_DIR}/${DOMAIN}-${TIMESTAMP}-recon.txt"

echo ""
echo "****************************************"
echo "15. Web Application Scanning with wpscan (for WordPress sites)"
echo "****************************************"
while read -r subdomain; do
    wpscan --url https://$subdomain --enumerate p --disable-tls-checks -o "${OUTPUT_DIR}/${subdomain}_wpscan_results.txt"
done < "${OUTPUT_DIR}/${DOMAIN}-${TIMESTAMP}-recon.txt"

echo ""
echo "****************************************"
echo "16. Web Technology Detection with whatweb"
echo "****************************************"
while read -r subdomain; do
    whatweb -a 2 $subdomain -o "${OUTPUT_DIR}/${subdomain}_whatweb_results.txt"
done < "${OUTPUT_DIR}/${DOMAIN}-${TIMESTAMP}-recon.txt"

echo ""
echo "****************************************"
echo "17. Web Technology Detection with wappalyzer"
echo "****************************************"
while read -r subdomain; do
    wappalyzer -u https://$subdomain -o "${OUTPUT_DIR}/${subdomain}_wappalyzer_results.txt"
done < "${OUTPUT_DIR}/${DOMAIN}-${TIMESTAMP}-recon.txt"

echo ""
echo "****************************************"
echo "18. Subdomain Scanning with shodan"
echo "****************************************"
while read -r subdomain; do
    shodan host $subdomain -o "${OUTPUT_DIR}/${subdomain}_shodan_results.txt"
done < "${OUTPUT_DIR}/${DOMAIN}-${TIMESTAMP}-recon.txt"

echo ""
echo "****************************************"
echo "19. Subdomain Scanning with censys"
echo "****************************************"
while read -r subdomain; do
    censys search "dns.domain: $subdomain" -o "${OUTPUT_DIR}/${subdomain}_censys_results.txt"
done < "${OUTPUT_DIR}/${DOMAIN}-${TIMESTAMP}-recon.txt"

echo ""
echo "****************************************"
echo "20. Docker Vulnerability Scanning with trivy"
echo "****************************************"
while read -r subdomain; do
    trivy image $subdomain -o "${OUTPUT_DIR}/${subdomain}_trivy_results.txt"
done < "${OUTPUT_DIR}/${DOMAIN}-${TIMESTAMP}-recon.txt"

echo ""
echo "****************************************"
echo "21. Docker Bench Scanning with docker-bench"
echo "****************************************"
while read -r subdomain; do
    docker-bench-security -i $subdomain -o "${OUTPUT_DIR}/${subdomain}_docker_bench_results.txt"
done < "${OUTPUT_DIR}/${DOMAIN}-${TIMESTAMP}-recon.txt"

echo ""
echo "****************************************"
echo "22. General Vulnerability Scanning with vulnscan"
echo "****************************************"
while read -r subdomain; do
    vulnscan -u https://$subdomain -o "${OUTPUT_DIR}/${subdomain}_vulnscan_results.txt"
done < "${OUTPUT_DIR}/${DOMAIN}-${TIMESTAMP}-recon.txt"

echo ""
echo "****************************************"
echo "23. Web Scanning with webscan"
echo "****************************************"
while read -r subdomain; do
    webscan -u https://$subdomain -o "${OUTPUT_DIR}/${subdomain}_webscan_results.txt"
done < "${OUTPUT_DIR}/${DOMAIN}-${TIMESTAMP}-recon.txt"

echo ""
echo "****************************************"
echo "24. Web Application Scanning with arachni"
echo "****************************************"
while read -r subdomain; do
    arachni https://$subdomain --output-json="${OUTPUT_DIR}/${subdomain}_arachni_results.json"
done < "${OUTPUT_DIR}/${DOMAIN}-${TIMESTAMP}-recon.txt"

echo ""
echo "****************************************"
echo "25. OWASP ZAP Scan"
echo "****************************************"
while read -r subdomain; do
    zap-cli -u https://$subdomain -o "${OUTPUT_DIR}/${subdomain}_zap_results.txt"
done < "${OUTPUT_DIR}/${DOMAIN}-${TIMESTAMP}-recon.txt"

echo ""
echo "****************************************"
echo "26. Grype Scan (for container vulnerabilities)"
echo "****************************************"
while read -r subdomain; do
    grype $subdomain -o "${OUTPUT_DIR}/${subdomain}_grype_results.txt"
done < "${OUTPUT_DIR}/${DOMAIN}-${TIMESTAMP}-recon.txt"

echo ""
echo "****************************************"
echo "27. HTTP Probe with httprobe"
echo "****************************************"
while read -r subdomain; do
    httprobe -p https: -p http: -o "${OUTPUT_DIR}/${subdomain}_httprobe_results.txt"
done < "${OUTPUT_DIR}/${DOMAIN}-${TIMESTAMP}-recon.txt"

echo ""
echo "****************************************"
echo "28. WAF Detection with wafw00f"
echo "****************************************"
while read -r subdomain; do
    wafw00f $subdomain -o "${OUTPUT_DIR}/${subdomain}_wafw00f_results.txt"
done < "${OUTPUT_DIR}/${DOMAIN}-${TIMESTAMP}-recon.txt"

echo ""
echo "****************************************"
echo "29. DNS Enumeration with dnsx"
echo "****************************************"
while read -r subdomain; do
    dnsx -d $subdomain -o "${OUTPUT_DIR}/${subdomain}_dnsx_results.txt"
done < "${OUTPUT_DIR}/${DOMAIN}-${TIMESTAMP}-recon.txt"

echo ""
echo "****************************************"
echo "30. DNS Recon with dnsrecon"
echo "****************************************"
while read -r subdomain; do
    dnsrecon -d $subdomain -o "${OUTPUT_DIR}/${subdomain}_dnsrecon_results.txt"
done < "${OUTPUT_DIR}/${DOMAIN}-${TIMESTAMP}-recon.txt"

echo ""
echo "****************************************"
echo "31. Subdomain Enumeration with shuffledns"
echo "****************************************"
while read -r subdomain; do
    shuffledns -d $subdomain -o "${OUTPUT_DIR}/${subdomain}_shuffledns_results.txt"
done < "${OUTPUT_DIR}/${DOMAIN}-${TIMESTAMP}-recon.txt"

echo ""
echo "****************************************"
echo "32. The Harvester for information gathering"
echo "****************************************"
while read -r subdomain; do
    theharvester -d $subdomain -b all -o "${OUTPUT_DIR}/${subdomain}_theharvester_results.txt"
done < "${OUTPUT_DIR}/${DOMAIN}-${TIMESTAMP}-recon.txt"

echo ""
echo "****************************************"
echo "33. Recon-ng for information gathering"
echo "****************************************"
while read -r subdomain; do
    recon-ng -m recon/domains-hosts/brute_hosts -o ${subdomain} -o "${OUTPUT_DIR}/${subdomain}_recon-ng_results.txt"
done < "${OUTPUT_DIR}/${DOMAIN}-${TIMESTAMP}-recon.txt"

echo ""
echo "****************************************"
echo "34. AlienVault for information gathering"
echo "****************************************"
while read -r subdomain; do
    # Requires AlienVault and configuration
    # Example: alienvault --domain $subdomain -o "${OUTPUT_DIR}/${subdomain}_alienvault_results.txt"
done < "${OUTPUT_DIR}/${DOMAIN}-${TIMESTAMP}-recon.txt"

echo ""
echo "****************************************"
echo "35. BinaryEdge for information gathering"
echo "****************************************"
while read -r subdomain; do
    # Requires BinaryEdge and configuration
    # Example: binaryedge -d $subdomain -o "${OUTPUT_DIR}/${subdomain}_binaryedge_results.txt"
done < "${OUTPUT_DIR}/${DOMAIN}-${TIMESTAMP}-recon.txt"

echo ""
echo "****************************************"
echo "36. Censys for information gathering"
echo "****************************************"
while read -r subdomain; do
    censys search "dns.domain: $subdomain" -o "${OUTPUT_DIR}/${subdomain}_censys_results.txt"
done < "${OUTPUT_DIR}/${DOMAIN}-${TIMESTAMP}-recon.txt"

echo ""
echo "****************************************"
echo "37. ZoomEye for information gathering"
echo "****************************************"
while read -r subdomain; do
    # Requires ZoomEye and configuration
    # Example: zoomeye search $subdomain -o "${OUTPUT_DIR}/${subdomain}_zoomeye_results.txt"
done < "${OUTPUT_DIR}/${DOMAIN}-${TIMESTAMP}-recon.txt"

echo "Scanning completed. Results saved to $OUTPUT_FILE"
