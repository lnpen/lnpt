#!/bin/bash

# Set the domain and timestamp for file naming
DOMAIN="example.com"  # Change this to your target domain
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
OUTPUT_DIR="./scan_results"
mkdir -p "$OUTPUT_DIR"

# Define the output file
OUTPUT_FILE="$OUTPUT_DIR/${DOMAIN}-${TIMESTAMP}-scan.txt"

# Define Seclists path
SECLISTS_DIR="/usr/share/seclists/SecLists-master"
WORDLIST_DIR="${SECLISTS_DIR}/Discovery/Web-Content"

# Start scanning
{
    echo ""
    echo "****************************************"
    echo "1. Port Scanning with nmap"
    echo "****************************************"
    nmap -p- $DOMAIN -oN nmap_full_scan.txt

    echo ""
    echo "****************************************"
    echo "2. Service Version Detection with nmap"
    echo "****************************************"
    nmap -sV $DOMAIN -oN nmap_service_version.txt

    echo ""
    echo "****************************************"
    echo "3. Aggressive Scan with nmap"
    echo "****************************************"
    nmap -A $DOMAIN -oN nmap_aggressive_scan.txt

    echo ""
    echo "****************************************"
    echo "4. Open Ports Scan with masscan"
    echo "****************************************"
    masscan -p1-65535 $DOMAIN -oG masscan_open_ports.txt

    echo ""
    echo "****************************************"
    echo "5. Vulnerability Scanning with nuclei"
    echo "****************************************"
    nuclei -target $DOMAIN -t /path/to/nuclei-templates/ -o nuclei_results.txt

    echo ""
    echo "****************************************"
    echo "6. Directory Bruteforce with gobuster"
    echo "****************************************"
    gobuster dir -u https://$DOMAIN -w ${WORDLIST_DIR}/common.txt -o gobuster_results.txt

    echo ""
    echo "****************************************"
    echo "7. Directory Bruteforce with dirsearch"
    echo "****************************************"
    dirsearch -u https://$DOMAIN -w ${WORDLIST_DIR}/common.txt -o dirsearch_results.txt

    echo ""
    echo "****************************************"
    echo "8. Content Discovery with ffuf"
    echo "****************************************"
    ffuf -u https://$DOMAIN/FUZZ -w ${WORDLIST_DIR}/common.txt -o ffuf_results.txt

    echo ""
    echo "****************************************"
    echo "9. SQL Injection Testing with sqlmap"
    echo "****************************************"
    sqlmap -u https://$DOMAIN --batch --crawl=2 -o sqlmap_results.txt

    echo ""
    echo "****************************************"
    echo "10. XSS Testing with xsstrike"
    echo "****************************************"
    xsstrike -u https://$DOMAIN --forms -o xsstrike_results.txt

    echo ""
    echo "****************************************"
    echo "11. Web Application Scanning with nikto"
    echo "****************************************"
    nikto -h https://$DOMAIN -o nikto_results.txt

    echo ""
    echo "****************************************"
    echo "12. Wordlist Brute Force with feroxbuster"
    echo "****************************************"
    feroxbuster -u https://$DOMAIN -w ${WORDLIST_DIR}/common.txt -o feroxbuster_results.txt

    echo ""
    echo "****************************************"
    echo "13. Web Application Scanning with zap"
    echo "****************************************"
    zap-cli quick-scan --start-url https://$DOMAIN -o zap_results.txt

    echo ""
    echo "****************************************"
    echo "14. Docker Image Vulnerability Scan with trivy"
    echo "****************************************"
    trivy image $DOMAIN -o trivy_results.txt

    echo ""
    echo "****************************************"
    echo "15. Content Discovery with dirsearch"
    echo "****************************************"
    dirsearch -u https://$DOMAIN -w ${WORDLIST_DIR}/big.txt -o dirsearch_large_results.txt

    echo ""
    echo "****************************************"
    echo "16. Docker Bench Security Scan"
    echo "****************************************"
    docker-bench-security > docker_bench_results.txt

    echo ""
    echo "****************************************"
    echo "17. Cross-Site Scripting Testing with ffuf"
    echo "****************************************"
    ffuf -u https://$DOMAIN/FUZZ -w ${WORDLIST_DIR}/xss.txt -o ffuf_xss_results.txt

    echo ""
    echo "****************************************"
    echo "18. Advanced Port Scanning with nmap"
    echo "****************************************"
    nmap -sS -sU -T4 $DOMAIN -oN nmap_advanced_scan.txt

    echo ""
    echo "****************************************"
    echo "19. Brute Force Scan with gobuster"
    echo "****************************************"
    gobuster dir -u https://$DOMAIN -w ${WORDLIST_DIR}/large.txt -o gobuster_large_results.txt

    echo ""
    echo "****************************************"
    echo "20. Cross-Site Scripting Testing with xsstrike"
    echo "****************************************"
    xsstrike -u https://$DOMAIN --crawl -o xsstrike_crawl_results.txt

    echo ""
    echo "****************************************"
    echo "21. Directory Enumeration with ffuf"
    echo "****************************************"
    ffuf -u https://$DOMAIN/FUZZ -w ${WORDLIST_DIR}/directories.txt -o ffuf_directories_results.txt

    echo ""
    echo "****************************************"
    echo "22. Detailed Scanning with nuclei"
    echo "****************************************"
    nuclei -target $DOMAIN -t /path/to/nuclei-templates/ -o nuclei_detailed_results.txt

    echo ""
    echo "****************************************"
    echo "23. Port Scanning with masscan"
    echo "****************************************"
    masscan -p1-65535 $DOMAIN -oG masscan_results.txt

    echo ""
    echo "****************************************"
    echo "24. DNS Enumeration with dnsrecon"
    echo "****************************************"
    dnsrecon -d $DOMAIN -a -o dnsrecon_results.txt

    echo ""
    echo "****************************************"
    echo "25. Open Redirect Testing with ffuf"
    echo "****************************************"
    ffuf -u https://$DOMAIN/FUZZ -w ${WORDLIST_DIR}/open_redirects.txt -o ffuf_open_redirects_results.txt

    echo ""
    echo "****************************************"
    echo "26. Server Banner Grabbing with nmap"
    echo "****************************************"
    nmap -sV --script=banner $DOMAIN -oN nmap_banner_grabbing.txt

    echo ""
    echo "****************************************"
    echo "27. Vulnerability Scanning with openvas"
    echo "****************************************"
    openvas -u https://$DOMAIN -o openvas_results.txt

    echo ""
    echo "****************************************"
    echo "28. API Endpoint Testing with postman"
    echo "****************************************"
    # Manual step: Use Postman to test API endpoints

    echo ""
    echo "****************************************"
    echo "29. Web Application Security Testing with burpsuite"
    echo "****************************************"
    # Manual step: Use Burp Suite for comprehensive scanning

    echo ""
    echo "****************************************"
    echo "30. HTTP Methods Testing with http-methods"
    echo "****************************************"
    http-methods -u https://$DOMAIN -o http_methods_results.txt

    echo ""
    echo "****************************************"
    echo "31. Subdomain Takeover Testing with subjack"
    echo "****************************************"
    subjack -w subdomains.txt -t 20 -o subjack_results.txt

    echo ""
    echo "****************************************"
    echo "32. API Testing with zap"
    echo "****************************************"
    zap-cli quick-scan --start-url https://$DOMAIN -o zap_api_results.txt

} | tee -a "$OUTPUT_FILE"
