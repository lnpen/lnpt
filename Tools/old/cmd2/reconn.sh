#!/bin/bash

# Define the required tools
REQUIRED_TOOLS=(
    "nmap" "masscan" "nuclei" "ffuf" "gobuster" "dirsearch" "sqlmap" "xsstrike"
    "nikto" "wpscan" "whatweb" "wappalyzer" "sublist3r" "httpx" "shodan" "censys"
    "chaos" "feroxbuster" "gospider" "burpsuite" "acuenvetix" "openvas" "aqua" 
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
OUTPUT_DIR="./recon_results"
mkdir -p "$OUTPUT_DIR"

# Define the output file
OUTPUT_FILE="$OUTPUT_DIR/${DOMAIN}-${TIMESTAMP}-recon.txt"

# Define Seclists path
SECLISTS_DIR="/usr/share/seclists/SecLists-master"
WORDLIST_DIR="${SECLISTS_DIR}/Discovery/DNS"

# Start reconnaissance
{
    echo ""
    echo "****************************************"
    echo "1. WHOIS Lookup"
    echo "****************************************"
    whois $DOMAIN

    echo ""
    echo "****************************************"
    echo "2. Reverse IP Lookup"
    echo "****************************************"
    reverseip -d $DOMAIN

    echo ""
    echo "****************************************"
    echo "3. DNS Enumeration with dnsenum"
    echo "****************************************"
    dnsenum $DOMAIN

    echo ""
    echo "****************************************"
    echo "4. DNS Enumeration with dnsrecon"
    echo "****************************************"
    dnsrecon -d $DOMAIN

    echo ""
    echo "****************************************"
    echo "5. Subdomain Enumeration with sublist3r"
    echo "****************************************"
    sublist3r -d $DOMAIN -o subdomains.txt

    echo ""
    echo "****************************************"
    echo "6. Subdomain Enumeration with subfinder"
    echo "****************************************"
    subfinder -d $DOMAIN -o subdomains_subfinder.txt

    echo ""
    echo "****************************************"
    echo "7. Subdomain Enumeration with assetfinder"
    echo "****************************************"
    assetfinder --subs-only $DOMAIN > subdomains_assetfinder.txt

    echo ""
    echo "****************************************"
    echo "8. DNS Brute Forcing with dnsx"
    echo "****************************************"
    dnsx -d $DOMAIN -wl ${WORDLIST_DIR}/dns-common.txt -o dnsx_results.txt

    echo ""
    echo "****************************************"
    echo "9. DNS Brute Forcing with shuffledns"
    echo "****************************************"
    shuffledns -d $DOMAIN -w ${WORDLIST_DIR}/dns-common.txt -o shuffledns_results.txt

    echo ""
    echo "****************************************"
    echo "10. HTTP/HTTPS Probing with httprobe"
    echo "****************************************"
    httprobe -p https -p http -s $DOMAIN -o httprobe_results.txt

    echo ""
    echo "****************************************"
    echo "11. Checking WAF with wafw00f"
    echo "****************************************"
    wafw00f $DOMAIN

    echo ""
    echo "****************************************"
    echo "12. Web Server Fingerprinting with whatweb"
    echo "****************************************"
    whatweb -v $DOMAIN

    echo ""
    echo "****************************************"
    echo "13. Technology Stack Identification with wappalyzer"
    echo "****************************************"
    wappalyzer -u https://$DOMAIN

    echo ""
    echo "****************************************"
    echo "14. Web Server Configuration with nmap"
    echo "****************************************"
    nmap --script http-config -p80,443 $DOMAIN

    echo ""
    echo "****************************************"
    echo "15. SSL/TLS Configuration with testssl.sh"
    echo "****************************************"
    testssl.sh $DOMAIN

    echo ""
    echo "****************************************"
    echo "16. Finding Subdomains with theHarvester"
    echo "****************************************"
    theHarvester -d $DOMAIN -b google -l 500 -f theharvester_results.txt

    echo ""
    echo "****************************************"
    echo "17. Censys Search"
    echo "****************************************"
    censys search --query "$DOMAIN"

    echo ""
    echo "****************************************"
    echo "18. Shodan Search"
    echo "****************************************"
    shodan host $DOMAIN

    echo ""
    echo "****************************************"
    echo "19. Alienvault Search"
    echo "****************************************"
    alienvault-search $DOMAIN

    echo ""
    echo "****************************************"
    echo "20. BinaryEdge Search"
    echo "****************************************"
    binaryedge search --domain $DOMAIN

    echo ""
    echo "****************************************"
    echo "21. ZoomEye Search"
    echo "****************************************"
    zoomeye search --domain $DOMAIN

    echo ""
    echo "****************************************"
    echo "22. Chaos Search"
    echo "****************************************"
    chaos search --domain $DOMAIN

    echo ""
    echo "****************************************"
    echo "23. Shodan API Query"
    echo "****************************************"
    shodan host $DOMAIN > shodan_results.txt

    echo ""
    echo "****************************************"
    echo "24. Port Scanning with nmap"
    echo "****************************************"
    nmap -p- $DOMAIN

    echo ""
    echo "****************************************"
    echo "25. Subdomain Enumeration with recon-ng"
    echo "****************************************"
    recon-ng -r $DOMAIN

    echo ""
    echo "****************************************"
    echo "26. HTTP Methods Enumeration with http-methods"
    echo "****************************************"
    http-methods -u https://$DOMAIN

    echo ""
    echo "****************************************"
    echo "27. API Endpoint Discovery with gospider"
    echo "****************************************"
    gospider -S https://$DOMAIN -o gospider_results.txt

    echo ""
    echo "****************************************"
    echo "28. Web Server Analysis with nikto"
    echo "****************************************"
    nikto -h https://$DOMAIN

    echo ""
    echo "****************************************"
    echo "29. Content Discovery with feroxbuster"
    echo "****************************************"
    feroxbuster -u https://$DOMAIN -w ${WORDLIST_DIR}/common.txt

    echo ""
    echo "****************************************"
    echo "30. Directory and File Enumeration with dirsearch"
    echo "****************************************"
    dirsearch -u https://$DOMAIN -w ${WORDLIST_DIR}/common.txt

    echo ""
    echo "****************************************"
    echo "31. Open Redirect Testing with ffuf"
    echo "****************************************"
    ffuf -u https://$DOMAIN/FUZZ -w ${WORDLIST_DIR}/open_redirects.txt

    echo ""
    echo "****************************************"
    echo "32. Subdomain Takeover Testing with subjack"
    echo "****************************************"
    subjack -w subdomains.txt -t 20 -o subjack_results.txt

    echo ""
    echo "****************************************"
    echo "33. XSS Testing with xsstrike"
    echo "****************************************"
    xsstrike -u https://$DOMAIN

    echo ""
    echo "****************************************"
    echo "34. API Testing with postman"
    echo "****************************************"
    # Manual step: Use Postman to test API endpoints

    echo ""
    echo "****************************************"
    echo "35. Web Application Scanning with burpsuite"
    echo "****************************************"
    # Manual step: Use Burp Suite for comprehensive scanning

    echo ""
    echo "****************************************"
    echo "36. Enumeration with theHarvester"
    echo "****************************************"
    theHarvester -d $DOMAIN -b all -l 500 -f theharvester_all_results.txt

    echo ""
    echo "****************************************"
    echo "37. Open Port Scanning with masscan"
    echo "****************************************"
    masscan -p1-65535 $DOMAIN

    echo ""
    echo "****************************************"
    echo "38. Subdomain Enumeration with Assetfinder"
    echo "****************************************"
    assetfinder --subs-only $DOMAIN

    echo ""
    echo "****************************************"
    echo "39. Network Mapping with nmap"
    echo "****************************************"
    nmap -sP $DOMAIN

    echo ""
    echo "****************************************"
    echo "40. Detailed HTTP Analysis with httpx"
    echo "****************************************"
    httpx -l subdomains.txt -o httpx_results.txt

    echo ""
    echo "****************************************"
    echo "41. Scan for Web Vulnerabilities with wpscan"
    echo "****************************************"
    wpscan --url https://$DOMAIN --enumerate p,t

    echo ""
    echo "****************************************"
    echo "42. Vulnerability Scanning with openvas"
    echo "****************************************"
    openvas -u https://$DOMAIN

    echo ""
    echo "****************************************"
    echo "43. Docker Image Scanning with trivy"
    echo "****************************************"
    trivy image $DOMAIN

    echo ""
    echo "****************************************"
    echo "44. Docker Bench Security with docker-bench"
    echo "****************************************"
    docker-bench-security

    echo ""
    echo "****************************************"
    echo "45. Grype Vulnerability Scan"
    echo "****************************************"
    grype $DOMAIN

    echo ""
    echo "****************************************"
    echo "46. File Upload Testing with ffuf"
    echo "****************************************"
    ffuf -u https://$DOMAIN/upload.php -w ${WORDLIST_DIR}/filenames.txt -X POST -d 'file=FUZZ'

    echo ""
    echo "****************************************"
    echo "47. Cross-Site Scripting Testing with xsstrike"
    echo "****************************************"
    xsstrike -u https://$DOMAIN --forms

    echo ""
    echo "****************************************"
    echo "48. Detailed Scanning with zap"
    echo "****************************************"
    zap-cli quick-scan --start-url https://$DOMAIN

} | tee -a "$OUTPUT_FILE"
