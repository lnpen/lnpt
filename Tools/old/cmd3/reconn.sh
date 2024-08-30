#!/bin/bash

# Set the domain and timestamp for file naming
DOMAIN="example.com"  # Change this to your target domain
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
OUTPUT_DIR="./recon_results"
mkdir -p "$OUTPUT_DIR"

# Define the output file
OUTPUT_FILE="$OUTPUT_DIR/${DOMAIN}-${TIMESTAMP}-recon.txt"

# Define Seclists path
SECLISTS_DIR="/usr/share/seclists/SecLists-master"
WORDLIST_DIR="${SECLISTS_DIR}/Discovery/Web-Content"

# Start reconnaissance
{
    echo ""
    echo "****************************************"
    echo "1. Subdomain Enumeration with sublist3r"
    echo "****************************************"
    sublist3r -d $DOMAIN -o subdomains.txt

    echo ""
    echo "****************************************"
    echo "2. DNS Enumeration with dnsrecon"
    echo "****************************************"
    dnsrecon -d $DOMAIN -a -o dnsrecon_results.txt

    echo ""
    echo "****************************************"
    echo "3. Subdomain Brute Force with gobuster"
    echo "****************************************"
    gobuster dns -d $DOMAIN -w ${SECLISTS_DIR}/Discovery/DNS/subdomains-top1million-5000.txt -o gobuster_dns_results.txt

    echo ""
    echo "****************************************"
    echo "4. Subdomain Enumeration with amass"
    echo "****************************************"
    amass enum -d $DOMAIN -o amass_results.txt

    echo ""
    echo "****************************************"
    echo "5. Reverse DNS Enumeration with theHarvester"
    echo "****************************************"
    theHarvester -d $DOMAIN -b dns -l 100 -o theharvester_results.txt

    echo ""
    echo "****************************************"
    echo "6. Subdomain Brute Force with ffuf"
    echo "****************************************"
    ffuf -u https://$DOMAIN -w ${SECLISTS_DIR}/Discovery/DNS/subdomains-top1million-5000.txt -H "Host: FUZZ.$DOMAIN" -o ffuf_subdomains_results.txt

    echo ""
    echo "****************************************"
    echo "7. DNS Zone Transfer with dnsrecon"
    echo "****************************************"
    dnsrecon -d $DOMAIN -t axfr -o dns_zone_transfer.txt

    echo ""
    echo "****************************************"
    echo "8. WHOIS Information Gathering"
    echo "****************************************"
    whois $DOMAIN -o whois_results.txt

    echo ""
    echo "****************************************"
    echo "9. IP Geolocation with ipinfo"
    echo "****************************************"
    ipinfo $DOMAIN -o ipinfo_results.txt

    echo ""
    echo "****************************************"
    echo "10. Directory Brute Force with dirb"
    echo "****************************************"
    dirb https://$DOMAIN -w ${WORDLIST_DIR}/common.txt -o dirb_results.txt

    echo ""
    echo "****************************************"
    echo "11. Subdomain Enumeration with subfinder"
    echo "****************************************"
    subfinder -d $DOMAIN -o subfinder_results.txt

    echo ""
    echo "****************************************"
    echo "12. Subdomain Takeover Testing with subjack"
    echo "****************************************"
    subjack -w subdomains.txt -t 20 -o subjack_results.txt

} | tee -a "$OUTPUT_FILE"
