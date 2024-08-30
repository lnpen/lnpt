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
    nmap -sV $DOMAIN -oN nmap_service_version.txt
    nmap -A $DOMAIN -oN nmap_aggressive_scan.txt
    nmap -p 80,443,22,21,3389 $DOMAIN -oN nmap_common_ports.txt
    nmap -p 1-65535 -T4 $DOMAIN -oN nmap_all_ports.txt

    echo ""
    echo "****************************************"
    echo "2. Open Ports Scan with masscan"
    echo "****************************************"
    masscan -p1-65535 $DOMAIN -oG masscan_full_ports.txt
    masscan -p80,443,21,22 $DOMAIN -oG masscan_common_ports.txt
    masscan -p1-1024 $DOMAIN -oG masscan_top_ports.txt

    echo ""
    echo "****************************************"
    echo "3. Vulnerability Scanning with nuclei"
    echo "****************************************"
    nuclei -target $DOMAIN -t /path/to/nuclei-templates/ -o nuclei_results.txt
    nuclei -target $DOMAIN -t /path/to/nuclei-templates/vulnerabilities/ -o nuclei_vulns_results.txt
    nuclei -target $DOMAIN -t /path/to/nuclei-templates/subdomain-takeover/ -o nuclei_subdomain_takeover_results.txt

    echo ""
    echo "****************************************"
    echo "4. Directory Brute Force with gobuster"
    echo "****************************************"
    gobuster dir -u https://$DOMAIN -w ${WORDLIST_DIR}/common.txt -o gobuster_common.txt
    gobuster dir -u https://$DOMAIN -w ${WORDLIST_DIR}/big.txt -o gobuster_big.txt
    gobuster dir -u https://$DOMAIN -w ${WORDLIST_DIR}/bigger.txt -o gobuster_bigger.txt
    gobuster dir -u https://$DOMAIN -w ${WORDLIST_DIR}/directories.txt -o gobuster_directories.txt

    echo ""
    echo "****************************************"
    echo "5. Directory Brute Force with dirsearch"
    echo "****************************************"
    dirsearch -u https://$DOMAIN -w ${WORDLIST_DIR}/common.txt -o dirsearch_common.txt
    dirsearch -u https://$DOMAIN -w ${WORDLIST_DIR}/big.txt -o dirsearch_big.txt
    dirsearch -u https://$DOMAIN -w ${WORDLIST_DIR}/bigger.txt -o dirsearch_bigger.txt
    dirsearch -u https://$DOMAIN -w ${WORDLIST_DIR}/directories.txt -o dirsearch_directories.txt

    echo ""
    echo "****************************************"
    echo "6. Content Discovery with ffuf"
    echo "****************************************"
    ffuf -u https://$DOMAIN/FUZZ -w ${WORDLIST_DIR}/common.txt -o ffuf_common.txt
    ffuf -u https://$DOMAIN/FUZZ -w ${WORDLIST_DIR}/big.txt -o ffuf_big.txt
    ffuf -u https://$DOMAIN/FUZZ -w ${WORDLIST_DIR}/bigger.txt -o ffuf_bigger.txt
    ffuf -u https://$DOMAIN/FUZZ -w ${WORDLIST_DIR}/directories.txt -o ffuf_directories.txt

    echo ""
    echo "****************************************"
    echo "7. SQL Injection Testing with sqlmap"
    echo "****************************************"
    sqlmap -u https://$DOMAIN --batch --crawl=3 -o sqlmap_results.txt
    sqlmap -u https://$DOMAIN --batch --dbs -o sqlmap_dbms_results.txt
    sqlmap -u https://$DOMAIN --batch --tables -o sqlmap_tables_results.txt

    echo ""
    echo "****************************************"
    echo "8. XSS Testing with xsser"
    echo "****************************************"
    xsser -u https://$DOMAIN -o xsser_results.txt
    xsser -u https://$DOMAIN --search -o xsser_search_results.txt
    xsser -u https://$DOMAIN --test -o xsser_test_results.txt

    echo ""
    echo "****************************************"
    echo "9. Server Banner Grabbing with nmap"
    echo "****************************************"
    nmap -sV --script=banner $DOMAIN -oN nmap_banner_grabbing.txt

    echo ""
    echo "****************************************"
    echo "10. Web Application Firewall Testing with wafw00f"
    echo "****************************************"
    wafw00f $DOMAIN -o wafw00f_results.txt
    wafw00f $DOMAIN --identify -o wafw00f_identify_results.txt

} | tee -a "$OUTPUT_FILE"
