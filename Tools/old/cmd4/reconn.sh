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
    sublist3r -d $DOMAIN -o subdomains_sublist3r.txt

    echo ""
    echo "****************************************"
    echo "2. DNS Enumeration with dnsrecon"
    echo "****************************************"
    dnsrecon -d $DOMAIN -a -o dnsrecon_all.txt
    dnsrecon -d $DOMAIN -t axfr -o dnsrecon_axfr.txt
    dnsrecon -d $DOMAIN -t brt -o dnsrecon_brute.txt

    echo ""
    echo "****************************************"
    echo "3. Subdomain Brute Force with gobuster"
    echo "****************************************"
    gobuster dns -d $DOMAIN -w ${SECLISTS_DIR}/Discovery/DNS/subdomains-top1million-5000.txt -o gobuster_dns_5000.txt
    gobuster dns -d $DOMAIN -w ${SECLISTS_DIR}/Discovery/DNS/subdomains-top1million-10000.txt -o gobuster_dns_10000.txt
    gobuster dns -d $DOMAIN -w ${SECLISTS_DIR}/Discovery/DNS/subdomains-top1million-20000.txt -o gobuster_dns_20000.txt

    echo ""
    echo "****************************************"
    echo "4. Subdomain Enumeration with amass"
    echo "****************************************"
    amass enum -d $DOMAIN -o amass_all.txt
    amass enum -d $DOMAIN -o amass_brute.txt -brute
    amass enum -d $DOMAIN -o amass_active.txt -active

    echo ""
    echo "****************************************"
    echo "5. Reverse DNS Enumeration with theHarvester"
    echo "****************************************"
    theHarvester -d $DOMAIN -b dns -l 100 -o theharvester_dns.txt
    theHarvester -d $DOMAIN -b google -l 100 -o theharvester_google.txt
    theHarvester -d $DOMAIN -b bing -l 100 -o theharvester_bing.txt

    echo ""
    echo "****************************************"
    echo "6. Subdomain Brute Force with ffuf"
    echo "****************************************"
    ffuf -u https://$DOMAIN -w ${SECLISTS_DIR}/Discovery/DNS/subdomains-top1million-5000.txt -H "Host: FUZZ.$DOMAIN" -o ffuf_dns_5000.txt
    ffuf -u https://$DOMAIN -w ${SECLISTS_DIR}/Discovery/DNS/subdomains-top1million-10000.txt -H "Host: FUZZ.$DOMAIN" -o ffuf_dns_10000.txt
    ffuf -u https://$DOMAIN -w ${SECLISTS_DIR}/Discovery/DNS/subdomains-top1million-20000.txt -H "Host: FUZZ.$DOMAIN" -o ffuf_dns_20000.txt

    echo ""
    echo "****************************************"
    echo "7. WHOIS Information Gathering"
    echo "****************************************"
    whois $DOMAIN -o whois_results.txt
    whois $DOMAIN | grep 'Registrant' -o >> whois_results_filtered.txt

    echo ""
    echo "****************************************"
    echo "8. IP Geolocation with ipinfo"
    echo "****************************************"
    ipinfo $DOMAIN -o ipinfo_results.txt
    ipinfo -d $DOMAIN -o ipinfo_detailed_results.txt

    echo ""
    echo "****************************************"
    echo "9. Directory Brute Force with dirb"
    echo "****************************************"
    dirb https://$DOMAIN -w ${WORDLIST_DIR}/common.txt -o dirb_common_results.txt
    dirb https://$DOMAIN -w ${WORDLIST_DIR}/big.txt -o dirb_big_results.txt
    dirb https://$DOMAIN -w ${WORDLIST_DIR}/bigger.txt -o dirb_bigger_results.txt

    echo ""
    echo "****************************************"
    echo "10. Subdomain Enumeration with subfinder"
    echo "****************************************"
    subfinder -d $DOMAIN -o subfinder_results.txt
    subfinder -d $DOMAIN -o subfinder_active.txt -active
    subfinder -d $DOMAIN -o subfinder_passive.txt -passive

    echo ""
    echo "****************************************"
    echo "11. Subdomain Takeover Testing with subjack"
    echo "****************************************"
    subjack -w subdomains_sublist3r.txt -t 20 -o subjack_results.txt
    subjack -w subfinder_results.txt -t 20 -o subjack_subfinder.txt

} | tee -a "$OUTPUT_FILE"
