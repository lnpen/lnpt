#!/bin/bash

# Mount the directory if not already mounted
if ! mountpoint -q /mnt/jp; then
    sudo mount /dev/nvme0n1p7 /mnt/jp
else
    echo "/mnt/jp is already mounted."
fi

# Define the domain and paths
DOMAIN="example.com"  # Default domain
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
OUTPUT_DIR="./results"
RECON_COMMANDS=("WHOIS Lookup" "Reverse IP Lookup" "DNS Enumeration" "Subdomain Enumeration with Sublist3r" "Subdomain Enumeration with Amass" "DNS Brute Force with dnsmap" "Web Technology Fingerprinting with WhatWeb" "Technology Stack Detection with Wappalyzer" "SSL/TLS Configuration Testing" "Directory Brute Force with Gobuster" "Directory Brute Force with Dirbuster" "Open Redirect Testing with Gospider" "Parameter Enumeration with FFUF" "HTTP Method Enumeration with HTTP-Methods" "Subdomain Takeover Testing with Subjack" "CORS Testing with Corsy" "SSRF Testing with SSRFMap" "Clickjacking Testing" "XSS and SQL Injection Testing with XSStrike" "JWT Manipulation Testing with JWT_Tool" "Brute Force Testing with Hydra" "API Testing with Postman" "File Upload Vulnerability Testing with Burp Suite" "Content Security Policy Testing with CSP-Scan" "Sensitive Data Exposure Testing with Feroxbuster" "SQL Injection Testing with SQLMap")
SCAN_COMMANDS=("Comprehensive Port Scanning with Nmap" "Open Ports Scanning with Masscan" "Vulnerability Scanning with Nuclei" "XSS and SQL Injection Scanning with XSStrike" "Brute Force Testing with Hydra" "API Testing with Postman" "File Upload Vulnerability Testing with Burp Suite")

# Function to display choices and change directory
navigate() {
    local current_dir="$1"

    while true; do
        clear
        echo "Current Directory: $current_dir"
        echo ""
        echo "0) Exit"
        echo "P) Previous Directory"
        echo "A) Lab Directory"
        echo "B) Tools Directory"
        echo "C) ZX Directory"
        echo "D) Hackerone"
        echo "E) Zomato Bug Bounty"
        echo "F) Bug Bounty Notes"
        echo ""

        dirs=("$current_dir"/*/)
        
        # Display the directories
        for idx in "${!dirs[@]}"; do
            dir_name=$(basename "${dirs[$idx]}")
            echo "$((idx + 1)) $dir_name"
        done

        echo ""
        read -p "Choose an Option: " choice

        case "${choice,,}" in
            "0")
                echo "Exiting..."
                cd "$current_dir" || { echo "Failed to change directory to $current_dir"; exit 1; }
                break
                ;;
            "p")
                current_dir=$(dirname "$current_dir")
                ;;
            "a")
                current_dir="/mnt/jp/work/labs"
                ;;
            "b")
                current_dir="/mnt/jp/work/tools"
                ;;
            "c")
                current_dir="/mnt/jp/work/labs/docs/zx-insights"
                ;;
            *)
                if [[ "$choice" =~ ^[0-9]+$ ]] && [ "$choice" -ge 1 ] && [ "$choice" -le "${#dirs[@]}" ]; then
                    current_dir="${dirs[$((choice-1))]}"
                else
                    echo "Invalid option. Try again."
                fi
                ;;
        esac
    done

    echo "$current_dir"
}

# Function to create domain directory if it does not exist
create_domain_directory() {
    if [ ! -d "$DOMAIN" ]; then
        mkdir "$DOMAIN"
        echo "Created directory for domain: $DOMAIN"
    fi
    cd "$DOMAIN"
}

# Function to run reconnaissance commands
run_recon_commands() {
    echo "Running Reconnaissance Commands..."
    for i in "${!RECON_COMMANDS[@]}"; do
        echo ""
        echo "****************************************"
        echo "$((i+1)). ${RECON_COMMANDS[i]}"
        echo "****************************************"
        # Placeholder for actual command execution
    done
    echo "Options:"
    echo "1. Run All Commands"
    echo "2. Run Specific Command"
    echo "3. Run Multiple Commands"
    echo "4. Back to Main Menu"
    read -p "Select an option: " option
    case $option in
        1)
            for i in "${!RECON_COMMANDS[@]}"; do
                echo "Running command: ${RECON_COMMANDS[i]}"
                # Add actual command execution here
            done
            ;;
        2)
            read -p "Enter command number to run: " cmd_num
            echo "Running command: ${RECON_COMMANDS[cmd_num-1]}"
            # Add actual command execution here
            ;;
        3)
            read -p "Enter range of commands to run (e.g., 1-5): " range
            IFS='-' read -r start end <<< "$range"
            for i in $(seq "$start" "$end"); do
                echo "Running command: ${RECON_COMMANDS[i-1]}"
                # Add actual command execution here
            done
            ;;
        4)
            return
            ;;
        *)
            echo "Invalid option."
            ;;
    esac
}

# Function to run scanning commands
run_scan_commands() {
    echo "Running Scanning Commands..."
    for i in "${!SCAN_COMMANDS[@]}"; do
        echo ""
        echo "****************************************"
        echo "$((i+1)). ${SCAN_COMMANDS[i]}"
        echo "****************************************"
        # Placeholder for actual command execution
    done
    echo "Options:"
    echo "1. Run All Commands"
    echo "2. Run Specific Command"
    echo "3. Run Multiple Commands"
    echo "4. Back to Main Menu"
    read -p "Select an option: " option
    case $option in
        1)
            for i in "${!SCAN_COMMANDS[@]}"; do
                echo "Running command: ${SCAN_COMMANDS[i]}"
                # Add actual command execution here
            done
            ;;
        2)
            read -p "Enter command number to run: " cmd_num
            echo "Running command: ${SCAN_COMMANDS[cmd_num-1]}"
            # Add actual command execution here
            ;;
        3)
            read -p "Enter range of commands to run (e.g., 1-5): " range
            IFS='-' read -r start end <<< "$range"
            for i in $(seq "$start" "$end"); do
                echo "Running command: ${SCAN_COMMANDS[i-1]}"
                # Add actual command execution here
            done
            ;;
        4)
            return
            ;;
        *)
            echo "Invalid option."
            ;;
    esac
}

# Function to switch to cmd mode
cmd_mode() {
    local mode="$1"
    while true; do
        clear
        echo "Mode: $mode"
        echo "Current Directory: $(pwd)"
        echo ""
        echo "Select Phase:"
        echo "1. Reconnaissance"
        echo "2. Scanning"
        echo "0. Back to Main Menu"
        read -p "Select an option: " phase
        case $phase in
            1)
                create_domain_directory
                run_recon_commands
                ;;
            2)
                create_domain_directory
                run_scan_commands
                ;;
            0)
                break
                ;;
            *)
                echo "Invalid option."
                ;;
        esac
    done
}

# Function to switch to directory mode
dir_mode() {
    local current_dir="$1"
    navigate "$current_dir"
}

# Main menu loop
while true; do
    clear
    echo "Welcome to MetaSploit-like Tool"
    echo ""
    echo "Select Mode:"
    echo "1. CMD Mode"
    echo "2. DIR Mode"
    echo "0. Exit"
    read -p "Select an option: " mode
    case $mode in
        1)
            cmd_mode "Command Mode"
            ;;
        2)
            dir_mode "/mnt/jp/work"
            ;;
        0)
            echo "Exiting..."
            exit 0
            ;;
        *)
            echo "Invalid option."
            ;;
    esac
done
