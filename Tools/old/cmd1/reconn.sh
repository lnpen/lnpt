#!/bin/bash

# Define the required tools
REQUIRED_TOOLS=(
    "whois" "reverseip" "dnsenum" "sublist3r" "subfinder" "amass" "crtsh" "theHarvester" 
    "dnsrecon" "findomain" "shuffledns" "hunter" "waybackurls" "github-search" "censys" 
    "shodan" "securitytrails" "robtex" "certspotter" "wappalyzer" "dig" "curl" "openssl" 
    "assetfinder" "knockpy" "goog-hack" "anubis" "urlscan" "otx" "subjack" "sslyze" 
    "http-methods" "gospider" "csrf_poc" "jwt_tool" "feroxbuster" "http-methods" "dirsearch" 
    "nmap" "masscan" "httpx" "ffuf" "nuclei" "gobuster" "sqlmap" "xsstrike" "corsy" 
    "ssrfmap" "clickjacking" "xsscrapy" "payloads" "webanalyzer" "dnsx" "dnsutils" "subzy"
    "ctfr" "dnslookup" "dossier" "httprobe" "gobuster" "xdomain" "urlcrazy" "subdomainizer"
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
OUTPUT_FILE="$OUTPUT_DIR/${DOMAIN}-${TIMESTAMP}.txt"

# Start logging
exec > >(tee -a "$OUTPUT_FILE") 2>&1

echo "Starting deep reconnaissance on $DOMAIN..."

# WHOIS Lookup
echo "1. WHOIS Lookup"
whois $DOMAIN

# Reverse IP Lookup
echo "2. Reverse IP Lookup"
reverseip -d $DOMAIN

# DNS Enumeration with dnsenum
echo "3. DNS Enumeration with dnsenum"
dnsenum $DOMAIN

# Subdomain Enumeration with Sublist3r
echo "4. Subdomain Enumeration with Sublist3r"
sublist3r -d $DOMAIN -o sublist3r_results.txt

# Subdomain Enumeration with Subfinder
echo "5. Subdomain Enumeration with Subfinder"
subfinder -d $DOMAIN -o subfinder_results.txt

# Subdomain Enumeration with Amass
echo "6. Subdomain Enumeration with Amass"
amass enum -d $DOMAIN -o amass_results.txt

# Subdomain Enumeration with CRTSH
echo "7. Subdomain Enumeration with CRTSH"
crtsh -d $DOMAIN -o crtsh_results.txt

# Subdomain Enumeration with theHarvester
echo "8. Subdomain Enumeration with theHarvester"
theHarvester -d $DOMAIN -b google -l 500 -o theharvester_results.txt

# DNS Enumeration with dnsrecon
echo "9. DNS Enumeration with dnsrecon"
dnsrecon -d $DOMAIN -t std -o dnsrecon_results.txt

# DNS Enumeration with findomain
echo "10. DNS Enumeration with findomain"
findomain -d $DOMAIN -o findomain_results.txt

# DNS Enumeration with shuffledns
echo "11. DNS Enumeration with shuffledns"
shuffledns -d $DOMAIN -list subdomains.txt -r resolvers.txt -o shuffledns_results.txt

# Subdomain Enumeration with hunter
echo "12. Subdomain Enumeration with hunter"
hunter -d $DOMAIN -o hunter_results.txt

# Subdomain Enumeration with waybackurls
echo "13. Subdomain Enumeration with waybackurls"
waybackurls $DOMAIN | tee waybackurls_results.txt

# Subdomain Enumeration with github-search
echo "14. Subdomain Enumeration with github-search"
github-search -d $DOMAIN -o github_search_results.txt

# Subdomain Enumeration with censys
echo "15. Subdomain Enumeration with censys"
censys search "dns.domain: $DOMAIN" -o censys_results.txt

# Subdomain Enumeration with shodan
echo "16. Subdomain Enumeration with shodan"
shodan domain $DOMAIN -o shodan_results.txt

# Subdomain Enumeration with securitytrails
echo "17. Subdomain Enumeration with securitytrails"
securitytrails -d $DOMAIN -o securitytrails_results.txt

# Subdomain Enumeration with robtex
echo "18. Subdomain Enumeration with robtex"
robtex -d $DOMAIN -o robtex_results.txt

# Subdomain Enumeration with certspotter
echo "19. Subdomain Enumeration with certspotter"
certspotter -d $DOMAIN -o certspotter_results.txt

# Technology Stack Identification with Wappalyzer
echo "20. Technology Stack Identification with Wappalyzer"
wappalyzer -u https://$DOMAIN -o wappalyzer_results.txt

# DNS Resolution with dig
echo "21. DNS Resolution with dig"
dig any $DOMAIN +short

# HTTP Header Inspection with curl
echo "22. HTTP Header Inspection with curl"
curl -I https://$DOMAIN

# SSL/TLS Configuration with openssl
echo "23. SSL/TLS Configuration with openssl"
openssl s_client -connect $DOMAIN:443 -showcerts

# Asset Finder with assetfinder
echo "24. Asset Finder with assetfinder"
assetfinder --subs-only $DOMAIN -o assetfinder_results.txt

# Subdomain Enumeration with knockpy
echo "25. Subdomain Enumeration with knockpy"
knockpy $DOMAIN -o knockpy_results.txt

# Google Dorking with goog-hack
echo "26. Google Dorking with goog-hack"
goog-hack -d $DOMAIN -o goog_hack_results.txt

# DNS Cache Snooping with dns-cache-snooping
echo "27. DNS Cache Snooping with dns-cache-snooping"
dns-cache-snooping -d $DOMAIN -o dns_cache_snooping_results.txt

# Subdomain Enumeration with anubis
echo "28. Subdomain Enumeration with anubis"
anubis -d $DOMAIN -o anubis_results.txt

# URL Scan with urlscan
echo "29. URL Scan with urlscan"
urlscan.io -d $DOMAIN -o urlscan_results.txt

# Open Source Intelligence with otx
echo "30. Open Source Intelligence with otx"
otx -d $DOMAIN -o otx_results.txt

# Subdomain Takeover Testing with subjack
echo "31. Subdomain Takeover Testing with subjack"
subjack -w subdomains.txt -t 20 -o subjack_results.txt

# SSL/TLS Testing with sslyze
echo "32. SSL/TLS Testing with sslyze"
sslyze --regular $DOMAIN

# HTTP Methods Enumeration with http-methods
echo "33. HTTP Methods Enumeration with http-methods"
http-methods -u https://$DOMAIN -o http_methods_results.txt

# Open Redirect Testing with gospider
echo "34. Open Redirect Testing with gospider"
gospider -S https://$DOMAIN -o gospider_results.txt

# CSRF Testing with csrf_poc
echo "35. CSRF Testing with csrf_poc"
csrf_poc -u https://$DOMAIN -o csrf_poc_results.txt

# JWT Token Testing with jwt_tool
echo "36. JWT Token Testing with jwt_tool"
jwt_tool -i https://$DOMAIN -o jwt_tool_results.txt

# Directory and File Enumeration with feroxbuster
echo "37. Directory and File Enumeration with feroxbuster"
feroxbuster -u https://$DOMAIN -w wordlist.txt -o feroxbuster_results.txt

# HTTP Methods Testing with http-methods
echo "38. HTTP Methods Testing with http-methods"
http-methods -u https://$DOMAIN -o http_methods_test_results.txt

# Directory Enumeration with dirsearch
echo "39. Directory Enumeration with dirsearch"
dirsearch -u https://$DOMAIN -w wordlist.txt -o dirsearch_results.txt

# HTTP Responses Testing with ffuf
echo "40. HTTP Responses Testing with ffuf"
ffuf -u https://$DOMAIN/FUZZ -w payloads/response.txt -o ffuf_results.txt

# Subdomain Enumeration with nuclei
echo "41. Subdomain Enumeration with nuclei"
nuclei -t subdomain-discovery -u https://$DOMAIN -o nuclei_results.txt

# SQL Injection Testing with sqlmap
echo "42. SQL Injection Testing with sqlmap"
sqlmap -u https://$DOMAIN --batch --crawl=5 -o sqlmap_results.txt

# Cross-Site Scripting (XSS) Testing with xsstrike
echo "43. Cross-Site Scripting (XSS) Testing with xsstrike"
xsstrike -u https://$DOMAIN -o xsstrike_results.txt

# CORS Misconfiguration Testing with corsy
echo "44. CORS Misconfiguration Testing with corsy"
corsy -u https://$DOMAIN -o corsy_results.txt

# Server-Side Request Forgery (SSRF) Testing with ssrfmap
echo "45. Server-Side Request Forgery (SSRF) Testing with ssrfmap"
ssrfmap -u https://$DOMAIN -o ssrfmap_results.txt

# Clickjacking Testing with clickjacking
echo "46. Clickjacking Testing with clickjacking"
clickjacking -u https://$DOMAIN -o clickjacking_results.txt

# XSS Detection with xsscrapy
echo "47. XSS Detection with xsscrapy"
xsscrapy -u https://$DOMAIN -o xsscrapy_results.txt

# Payloads Testing with payloads
echo "48. Payloads Testing with payloads"
payloads -u https://$DOMAIN -o payloads_results.txt

# Web Analysis with webanalyzer
echo "49. Web Analysis with webanalyzer"
webanalyzer -u https://$DOMAIN -o webanalyzer_results.txt

echo "Reconnaissance completed. Results saved to $OUTPUT_FILE"
