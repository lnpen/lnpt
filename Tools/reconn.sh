#!/bin/bash

# Define paths and variables
DOMAIN=$1
SECLISTS_DIR="/usr/share/seclists"
OUTPUT_DIR="./recon_results"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
OUTPUT_FILE="${OUTPUT_DIR}/${DOMAIN}-${TIMESTAMP}-recon.txt"

# Create output directory if it doesn't exist
mkdir -p "$OUTPUT_DIR"

# Function to check if a tool is installed
check_tool() {
    command -v "$1" >/dev/null 2>&1
}

# List of required tools
REQUIRED_TOOLS=(
    "sublist3r" "crtsh" "theHarvester" "dnsrecon" "findomain" "shuffledns"
    "hunter" "waybackurls" "github-search" "censys" "shodan" "securitytrails"
    "robtex" "certspotter" "wappalyzer" "dig" "curl" "openssl" "assetfinder"
    "knockpy" "goog-hack" "dns-cache-snooping" "anubis" "urlscan.io" "otx"
    "sslyze" "csrf_poc" "jwt_tool" "feroxbuster" "http-methods" "dirsearch"
    "ffuf" "nuclei" "sqlmap" "xsstrike" "corsy" "ssrfmap" "clickjacking"
    "xsscrapy" "payloads" "webanalyzer" "recon-ng" "alienvault" "binaryedge"
    "zoomeye" "chaos" "burpsuite" "acuenvetix" "openvas" "aqua" "trivy"
    "docker-bench" "grype" "masscan" "nikto" "wpscan" "whatweb" "httprobe"
    "gospider" "subfinder" "amass" "crt.sh" "passive-dns" "dnsenum" "whois"
    "reverseip" "httpx" "wpscan" "zap-cli" "arachni" "vulnscan" "webscan"
)

# Check for missing tools
UNINSTALLED_TOOLS=()
for tool in "${REQUIRED_TOOLS[@]}"; do
    if ! check_tool "$tool"; then
        UNINSTALLED_TOOLS+=("$tool")
    fi
done

# Exit if any required tool is missing
if [ ${#UNINSTALLED_TOOLS[@]} -ne 0 ]; then
    echo "The following tools are missing: ${UNINSTALLED_TOOLS[@]}"
    exit 1
fi

# Run reconnaissance commands and save results
{
    echo "Running reconnaissance for $DOMAIN"

    # Subdomain enumeration
    sublist3r -d $DOMAIN -o "${OUTPUT_DIR}/sublist3r_results.txt"
    crtsh -d $DOMAIN -o "${OUTPUT_DIR}/crtsh_results.txt"
    theHarvester -d $DOMAIN -b google -l 500 -o "${OUTPUT_DIR}/theharvester_results.txt"
    dnsrecon -d $DOMAIN -t std -o "${OUTPUT_DIR}/dnsrecon_results.txt"
    findomain -d $DOMAIN -o "${OUTPUT_DIR}/findomain_results.txt"
    shuffledns -d $DOMAIN -list subdomains.txt -r resolvers.txt -o "${OUTPUT_DIR}/shuffledns_results.txt"
    hunter -d $DOMAIN -o "${OUTPUT_DIR}/hunter_results.txt"
    waybackurls $DOMAIN | tee "${OUTPUT_DIR}/waybackurls_results.txt"
    github-search -d $DOMAIN -o "${OUTPUT_DIR}/github_search_results.txt"
    censys search "dns.domain: $DOMAIN" -o "${OUTPUT_DIR}/censys_results.txt"
    shodan domain $DOMAIN -o "${OUTPUT_DIR}/shodan_results.txt"
    securitytrails -d $DOMAIN -o "${OUTPUT_DIR}/securitytrails_results.txt"
    robtex -d $DOMAIN -o "${OUTPUT_DIR}/robtex_results.txt"
    certspotter -d $DOMAIN -o "${OUTPUT_DIR}/certspotter_results.txt"
    wappalyzer -u https://$DOMAIN -o "${OUTPUT_DIR}/wappalyzer_results.txt"

    # Additional enumeration and probing
    dig any $DOMAIN +short
    curl -I https://$DOMAIN
    openssl s_client -connect $DOMAIN:443 -showcerts
    assetfinder --subs-only $DOMAIN -o "${OUTPUT_DIR}/assetfinder_results.txt"
    knockpy $DOMAIN -o "${OUTPUT_DIR}/knockpy_results.txt"
    goog-hack -d $DOMAIN -o "${OUTPUT_DIR}/goog_hack_results.txt"
    dns-cache-snooping -d $DOMAIN -o "${OUTPUT_DIR}/dns_cache_snooping_results.txt"
    anubis -d $DOMAIN -o "${OUTPUT_DIR}/anubis_results.txt"
    urlscan.io -d $DOMAIN -o "${OUTPUT_DIR}/urlscan_results.txt"
    otx -d $DOMAIN -o "${OUTPUT_DIR}/otx_results.txt"
    sslyze --regular $DOMAIN
    csrf_poc -u https://$DOMAIN -o "${OUTPUT_DIR}/csrf_poc_results.txt"
    jwt_tool -i https://$DOMAIN -o "${OUTPUT_DIR}/jwt_tool_results.txt"
    feroxbuster -u https://$DOMAIN -w wordlist.txt -o "${OUTPUT_DIR}/feroxbuster_results.txt"
    http-methods -u https://$DOMAIN -o "${OUTPUT_DIR}/http_methods_test_results.txt"
    dirsearch -u https://$DOMAIN -w wordlist.txt -o "${OUTPUT_DIR}/dirsearch_results.txt"
    ffuf -u https://$DOMAIN/FUZZ -w payloads/response.txt -o "${OUTPUT_DIR}/ffuf_results.txt"
    nuclei -t subdomain-discovery -u https://$DOMAIN -o "${OUTPUT_DIR}/nuclei_results.txt"
    sqlmap -u https://$DOMAIN --batch --crawl=5 -o "${OUTPUT_DIR}/sqlmap_results.txt"
    xsstrike -u https://$DOMAIN -o "${OUTPUT_DIR}/xsstrike_results.txt"
    corsy -u https://$DOMAIN -o "${OUTPUT_DIR}/corsy_results.txt"
    ssrfmap -u https://$DOMAIN -o "${OUTPUT_DIR}/ssrfmap_results.txt"
    clickjacking -u https://$DOMAIN -o "${OUTPUT_DIR}/clickjacking_results.txt"
    xsscrapy -u https://$DOMAIN -o "${OUTPUT_DIR}/xsscrapy_results.txt"
    payloads -u https://$DOMAIN -o "${OUTPUT_DIR}/payloads_results.txt"
    webanalyzer -u https://$DOMAIN -o "${OUTPUT_DIR}/webanalyzer_results.txt"
    
    # Additional scans and checks
    whois $DOMAIN
    reverseip -d $DOMAIN
    dnsenum $DOMAIN
    dnsrecon -d $DOMAIN
    subfinder -d $DOMAIN -o "${OUTPUT_DIR}/subdomains_subfinder.txt"
    assetfinder --subs-only $DOMAIN > "${OUTPUT_DIR}/subdomains_assetfinder.txt"
    dnsx -d $DOMAIN -wl ${SECLISTS_DIR}/Discovery/DNS/dns-common.txt -o "${OUTPUT_DIR}/dnsx_results.txt"
    shuffledns -d $DOMAIN -w ${SECLISTS_DIR}/Discovery/DNS/dns-common.txt -o "${OUTPUT_DIR}/shuffledns_results.txt"
    httprobe -p https -p http -s $DOMAIN -o "${OUTPUT_DIR}/httprobe_results.txt"
    wafw00f $DOMAIN
    whatweb -v $DOMAIN
    wappalyzer -u https://$DOMAIN
    nmap --script http-config -p80,443 $DOMAIN
    testssl.sh $DOMAIN
    
    # Advanced subdomain enumeration
    theHarvester -d $DOMAIN -b google -l 500 -f "${OUTPUT_DIR}/theharvester_results.txt"
    censys search --query "$DOMAIN"
    shodan host $DOMAIN
    alienvault-search $DOMAIN
    binaryedge search --domain $DOMAIN
    zoomeye search --domain $DOMAIN
    chaos search --domain $DOMAIN
    shodan host $DOMAIN > "${OUTPUT_DIR}/shodan_results.txt"
    nmap -p- $DOMAIN
    recon-ng -r $DOMAIN
    http-methods -u https://$DOMAIN
    gospider -S https://$DOMAIN -o "${OUTPUT_DIR}/gospider_results.txt"
    nikto -h https://$DOMAIN
    feroxbuster -u https://$DOMAIN -w ${SECLISTS_DIR}/Discovery/Web-Content/common.txt
    dirsearch -u https://$DOMAIN -w ${SECLISTS_DIR}/Discovery/Web-Content/common.txt
    ffuf -u https://$DOMAIN/FUZZ -w ${SECLISTS_DIR}/Discovery/Web-Content/open_redirects.txt
    xsstrike -u https://$DOMAIN
    theHarvester -d $DOMAIN -b all -l 500 -f "${OUTPUT_DIR}/theharvester_all_results.txt"
    masscan -p1-65535 $DOMAIN
    assetfinder --subs-only $DOMAIN
    nmap -sP $DOMAIN
    httpx -l subdomains.txt -o "${OUTPUT_DIR}/httpx_results.txt"
    wpscan --url https://$DOMAIN --enumerate p,t
    openvas -u https://$DOMAIN
    trivy image $DOMAIN
    docker-bench-security
    grype $DOMAIN
    aquasec -d $DOMAIN
} 2>&1 | tee "$OUTPUT_FILE"

echo "Reconnaissance results saved to $OUTPUT_FILE"
