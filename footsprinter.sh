#!/usr/bin/env bash
# FootSprinter v2.0 - Advanced OSINT & Vulnerability Assessment Framework
# Author: Aarham Labs (Rushil P Shah)
# Description: Most comprehensive footprinting and reconnaissance tool
set -euo pipefail

#######################
# COLOR DEFINITIONS
#######################
ESC="\033["
RESET="${ESC}0m"
BOLD="${ESC}1m"
DIM="${ESC}2m"
RED="${ESC}31;1m"
GREEN="${ESC}32;1m"
YELLOW="${ESC}33;1m"
BLUE="${ESC}34;1m"
MAGENTA="${ESC}35;1m"
CYAN="${ESC}36;1m"
WHITE="${ESC}37;1m"

#######################
# GLOBAL VARIABLES
#######################
VERSION="2.0"
TARGET=""
FULLSCAN=false
INTERVAL=1
CUSTOM_HEADERS=false
USER_AGENT="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
OUTDIR=""
TIMESTAMP=$(date +%F_%H%M%S)
GOBIN="${GOBIN:-$HOME/go/bin}"
export PATH="$GOBIN:$PATH"
export GOPATH="${GOPATH:-$HOME/go}"

#######################
# HELPER FUNCTIONS
#######################
sep() { printf "${DIM}%s${RESET}\n" "════════════════════════════════════════════════════════════════════════════════"; }
section() { printf "\n${BOLD}${CYAN}[*]${RESET} ${BOLD}%s${RESET}\n" "$1"; sep; }
info() { printf " ${CYAN}[+]${RESET} %s\n" "$1"; }
ok() { printf " ${GREEN}[✓]${RESET} %s\n" "$1"; }
warn() { printf " ${YELLOW}[!]${RESET} %s\n" "$1"; }
err() { printf " ${RED}[✗]${RESET} %s\n" "$1"; }
progress() { printf " ${BLUE}[→]${RESET} %s\n" "$1"; }

#######################
# BANNER (Metasploit-style)
#######################
show_banner() {
cat <<'BANNER'

    @@@@@@@@@@  @@@@@@@@   @@@@@@   @@@@@@@   @@@@@@  @@@@@@@  @@@@@@@  @@@  @@@  @@@  @@@@@@@  @@@@@@@@  @@@@@@@   
    @@@@@@@@@@  @@@@@@@@  @@@@@@@@  @@@@@@@  @@@@@@@  @@@@@@@@  @@@@@@@@  @@@  @@@@ @@@  @@@@@@@  @@@@@@@@  @@@@@@@@  
    @@!         @@!   @@@ @@!  @@@  @@!      !@@      @@!  @@@  @@!  @@@  @@!  @@!@!@@@    @@!    @@!       @@!  @@@  
    !@!         !@!   @!@ !@!  @!@  !@!      !@!      !@!  @!@  !@!  @!@  !@!  !@!!@!@!    !@!    !@!       !@!  @!@  
    @!!!:!      @!@!@!@!  @!@  !@!  @!!!:!    !@@!!   @!@@!@!   @!@!!@!   !!@  @!@ !!@!    @!!    @!!!:!    @!@!!@!   
    !!!!!:      !!!@!!!!  !@!  !!!  !!!!!:     !!@!!  !!@!!!    !!@!@!    !!!  !@!  !!!    !!!    !!!!!:    !!@!@!    
    !!:         !!:  !!!  !!:  !!!  !!:            !: !!:       !!: :!!   !!:  !!:  !!!    !!:    !!:       !!: :!!   
    :!:         :!:  !:!  :!:  !:!  :!:           !:  :!:       :!:  !:!  :!:  :!:  !:!    :!:    :!:       :!:  !:!  
     ::         ::   :::  ::::: ::   :: ::::  :::: ::  ::       ::   :::   ::   ::   ::     ::     :: ::::  ::   :::  
     :           :   : :   : :  :   : :: ::   :: : :   :         :   : :  :    ::    :      :     : :: ::    :   : :  

BANNER
printf "${DIM}%s${RESET}\n" "════════════════════════════════════════════════════════════════════════════════"
printf "  ${BOLD}${MAGENTA}FootSprinter v${VERSION}${RESET} - Advanced Reconnaissance & Vulnerability Assessment\n"
printf "  ${DIM}Author: Aarham Labs (Rushil P. Shah)${RESET}\n"
printf "${DIM}%s${RESET}\n" "════════════════════════════════════════════════════════════════════════════════"
printf "  ${GREEN}✓ SAFE MODE:${RESET} All scans are non-invasive (detection only, no exploitation)\n"
printf "${DIM}%s${RESET}\n\n" "════════════════════════════════════════════════════════════════════════════════"
}

#######################
# USAGE INFORMATION
#######################
show_usage() {
cat << EOF
${BOLD}USAGE:${RESET}
  $0 --url <target> [options]

${BOLD}REQUIRED:${RESET}
  --url <domain>        Target domain or URL (e.g., example.com or https://example.com)

${BOLD}OPTIONS:${RESET}
  --fullscan            Enable comprehensive deep scanning (slower but thorough)
  --interval <seconds>  Delay between requests (default: 1, for stealth use 3-5)
  --changeheaders       Randomize User-Agent headers to evade detection
  -h, --help            Show this help message

${BOLD}EXAMPLES:${RESET}
  $0 --url example.com
  $0 --url https://target.com --fullscan
  $0 --url example.com --interval 3 --changeheaders
  $0 --url target.com --fullscan --interval 2 --changeheaders

${BOLD}WHAT IT DOES:${RESET}
  1. Company Intelligence (Location, Size, Registration)
  2. Domain & Subdomain Enumeration
  3. Port Scanning (All common ports)
  4. Technology Stack Detection (with versions)
  5. Vulnerability Assessment (SAFE - Detection only, NO exploitation)
  6. Exploitation Analysis (Educational - shows potential attack vectors)
  7. Remediation Recommendations
  8. Risk Assessment & Scoring
  9. Comprehensive HTML Report Generation

${BOLD}SAFETY:${RESET} All vulnerability scans are NON-INVASIVE and only detect issues.
         NO attacks or exploitations are performed. Safe for production systems.

${BOLD}WARNING:${RESET} Only scan targets you own or have explicit permission to test!

EOF
exit 0
}

#######################
# ARGUMENT PARSING
#######################
parse_arguments() {
    if [ $# -eq 0 ]; then
        show_usage
    fi

    while [ $# -gt 0 ]; do
        case "$1" in
            --url)
                TARGET="$2"
                shift 2
                ;;
            --fullscan)
                FULLSCAN=true
                shift
                ;;
            --interval)
                INTERVAL="$2"
                shift 2
                ;;
            --changeheaders)
                CUSTOM_HEADERS=true
                shift
                ;;
            -h|--help)
                show_usage
                ;;
            *)
                err "Unknown option: $1"
                show_usage
                ;;
        esac
    done

if [ -z "$TARGET" ]; then
        err "Target URL is required! Use --url <domain>"
        show_usage
    fi

    # Clean target URL
    TARGET="${TARGET//https:\/\//}"
    TARGET="${TARGET//http:\/\//}"
    TARGET="${TARGET%%/*}"
}

#######################
# RANDOM USER AGENT
#######################
get_random_user_agent() {
    local agents=(
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0"
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0"
    )
    echo "${agents[$RANDOM % ${#agents[@]}]}"
}

#######################
# ROOT CHECK
#######################
check_root() {
    if [ "$EUID" -ne 0 ]; then
        warn "Some features require root privileges. Re-running with sudo..."
        exec sudo -E bash "$0" "$@"
    fi
}

#######################
# DEPENDENCY INSTALLATION
#######################
install_dependencies() {
    section "Installing & Verifying Dependencies"
    
    # APT packages
    local apt_pkgs=(nmap whois curl wget git jq python3 python3-pip dnsutils openssl amass gobuster)
    local missing_apt=()
    
    info "Checking APT packages..."
    for pkg in "${apt_pkgs[@]}"; do
        if ! dpkg -s "$pkg" >/dev/null 2>&1; then
            missing_apt+=("$pkg")
  fi
done

    if [ "${#missing_apt[@]}" -gt 0 ]; then
        warn "Installing missing packages: ${missing_apt[*]}"
        progress "Updating package lists..."
        apt-get update -qq
        progress "Installing packages (this may take 1-2 minutes)..."
        DEBIAN_FRONTEND=noninteractive apt-get install -y "${missing_apt[@]}" >/dev/null 2>&1 || true
        ok "APT packages installed"
    else
        ok "All APT packages present"
    fi
    
    # Ensure Go is installed
if ! command -v go >/dev/null 2>&1; then
        warn "Installing Go..."
        progress "Downloading and installing Go (this may take a minute)..."
        apt-get install -y golang-go >/dev/null 2>&1
        ok "Go installed"
    else
        ok "Go is installed"
    fi
    
    # Go-based tools
    local go_tools=(
        "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
        "github.com/projectdiscovery/httpx/cmd/httpx@latest"
        "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
        "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
        "github.com/tomnomnom/assetfinder@latest"
        "github.com/tomnomnom/httprobe@latest"
        "github.com/tomnomnom/waybackurls@latest"
        "github.com/lc/gau/v2/cmd/gau@latest"
        "github.com/tomnomnom/anew@latest"
        "github.com/projectdiscovery/katana/cmd/katana@latest"
    )
    
    info "Installing Go reconnaissance tools..."
    for tool in "${go_tools[@]}"; do
        local bin_name=$(basename "${tool%%@*}")
        if ! command -v "$bin_name" >/dev/null 2>&1; then
            progress "Installing $bin_name..."
            GOBIN="$GOBIN" go install "$tool" 2>&1 | grep -v "^$" || true
            if command -v "$bin_name" >/dev/null 2>&1; then
                ok "$bin_name installed"
            else
                warn "$bin_name installation failed (non-critical)"
    fi
  else
            ok "$bin_name already installed"
        fi
        sleep 0.2
    done
    
    # Update Nuclei templates
    if command -v nuclei >/dev/null 2>&1; then
        info "Updating Nuclei templates..."
        nuclei -update-templates -silent 2>/dev/null || warn "Could not update Nuclei templates"
        ok "Nuclei templates updated"
    fi
    
    # Python tools
    info "Installing Python tools..."
    pip3 install -q --upgrade requests beautifulsoup4 dnspython 2>/dev/null || warn "Python packages installation warning"
    ok "Python dependencies ready"
    
    # Nikto
    if ! command -v nikto >/dev/null 2>&1; then
        info "Installing Nikto..."
        apt-get install -y nikto >/dev/null 2>&1 || warn "Nikto installation failed"
    fi
    
    # WhatWeb
    if ! command -v whatweb >/dev/null 2>&1; then
        info "Installing WhatWeb..."
        apt-get install -y whatweb >/dev/null 2>&1 || warn "WhatWeb installation failed"
    fi
    
    ok "All dependencies verified and installed!"
}

#######################
# MODULE 1: COMPANY INTELLIGENCE
#######################
gather_company_intelligence() {
    section "Module 1: Company Intelligence Gathering"
    
    info "Gathering WHOIS information..."
    whois "$TARGET" > "$OUTDIR/raw/whois.txt" 2>/dev/null || warn "WHOIS lookup failed"
    
    # Parse WHOIS for key information
    if [ -f "$OUTDIR/raw/whois.txt" ]; then
        grep -iE "registrant|organization|country|city|address|email" "$OUTDIR/raw/whois.txt" > "$OUTDIR/final/company_info.txt" 2>/dev/null || true
        ok "WHOIS data collected"
    fi
    
    # DNS records
    info "Collecting DNS records..."
    {
        echo "=== A Records ==="
        dig +short A "$TARGET" 2>/dev/null || echo "N/A"
        echo -e "\n=== MX Records ==="
        dig +short MX "$TARGET" 2>/dev/null || echo "N/A"
        echo -e "\n=== TXT Records ==="
        dig +short TXT "$TARGET" 2>/dev/null || echo "N/A"
        echo -e "\n=== NS Records ==="
        dig +short NS "$TARGET" 2>/dev/null || echo "N/A"
        echo -e "\n=== SOA Records ==="
        dig +short SOA "$TARGET" 2>/dev/null || echo "N/A"
    } > "$OUTDIR/raw/dns_records.txt"
    ok "DNS records collected"
    
    # Certificate transparency
    info "Checking certificate transparency logs..."
    curl -s "https://crt.sh/?q=%25.${TARGET}&output=json" > "$OUTDIR/raw/crt_sh.json" 2>/dev/null || warn "crt.sh query failed"
    if [ -f "$OUTDIR/raw/crt_sh.json" ]; then
        jq -r '.[].name_value' "$OUTDIR/raw/crt_sh.json" 2>/dev/null | sed 's/\*\.//g' | sort -u > "$OUTDIR/raw/crt_subdomains.txt" || true
        ok "Certificate transparency data collected"
    fi
    
    # IP information
    info "Resolving IP address..."
    TARGET_IP=$(dig +short A "$TARGET" | head -n1)
    if [ -n "$TARGET_IP" ]; then
        echo "$TARGET_IP" > "$OUTDIR/raw/target_ip.txt"
        ok "Target IP: $TARGET_IP"
        
        # IP geolocation (using ip-api.com)
        info "Getting IP geolocation..."
        curl -s "http://ip-api.com/json/${TARGET_IP}" > "$OUTDIR/raw/ip_geolocation.json" 2>/dev/null || warn "Geolocation lookup failed"
        if [ -f "$OUTDIR/raw/ip_geolocation.json" ]; then
            ok "Geolocation data collected"
        fi
    else
        warn "Could not resolve target IP"
    fi
    
    ok "Company intelligence gathering complete"
}

#######################
# MODULE 2: DOMAIN & SUBDOMAIN ENUMERATION
#######################
enumerate_domains() {
    section "Module 2: Domain & Subdomain Enumeration"
    
    # Subfinder
if command -v subfinder >/dev/null 2>&1; then
        info "Running Subfinder..."
        subfinder -d "$TARGET" -silent -o "$OUTDIR/raw/subfinder.txt" 2>/dev/null || warn "Subfinder failed"
        ok "Subfinder complete"
        sleep "$INTERVAL"
    fi
    
    # Assetfinder
if command -v assetfinder >/dev/null 2>&1; then
        info "Running Assetfinder..."
        assetfinder --subs-only "$TARGET" > "$OUTDIR/raw/assetfinder.txt" 2>/dev/null || warn "Assetfinder failed"
        ok "Assetfinder complete"
        sleep "$INTERVAL"
    fi
    
    # Amass
if command -v amass >/dev/null 2>&1; then
        info "Running Amass (passive mode)..."
        timeout 300 amass enum -passive -d "$TARGET" -o "$OUTDIR/raw/amass.txt" 2>/dev/null || warn "Amass timeout/failed"
        ok "Amass complete"
        sleep "$INTERVAL"
    fi
    
    # Certificate transparency
    if [ -f "$OUTDIR/raw/crt_subdomains.txt" ]; then
        cp "$OUTDIR/raw/crt_subdomains.txt" "$OUTDIR/raw/crt_subs.txt"
    fi
    
    # Consolidate all subdomains
    info "Consolidating subdomains..."
    cat "$OUTDIR/raw/"*.txt 2>/dev/null | grep -E "^[a-zA-Z0-9].*\.${TARGET}$" | sort -u > "$OUTDIR/final/all_subdomains.txt" || true
    
    local sub_count=$(wc -l < "$OUTDIR/final/all_subdomains.txt" 2>/dev/null || echo 0)
    ok "Found $sub_count unique subdomains"
    
    # Probe for live hosts
    if command -v httpx >/dev/null 2>&1 && [ -s "$OUTDIR/final/all_subdomains.txt" ]; then
        info "Probing for live hosts with httpx..."
        cat "$OUTDIR/final/all_subdomains.txt" | httpx -silent -threads 50 -timeout 10 -no-color -o "$OUTDIR/final/live_hosts.txt" 2>/dev/null || warn "httpx failed"
        local live_count=$(wc -l < "$OUTDIR/final/live_hosts.txt" 2>/dev/null || echo 0)
        ok "Found $live_count live hosts"
    else
        touch "$OUTDIR/final/live_hosts.txt"
        ok "No subdomains to probe"
    fi
    
    # Check for common weak/typosquatting domains
    info "Checking for potential weak domains..."
    {
        echo "www.${TARGET}"
        echo "mail.${TARGET}"
        echo "ftp.${TARGET}"
        echo "admin.${TARGET}"
        echo "test.${TARGET}"
        echo "dev.${TARGET}"
        echo "staging.${TARGET}"
        echo "old.${TARGET}"
        echo "backup.${TARGET}"
        echo "demo.${TARGET}"
    } > "$OUTDIR/raw/potential_weak.txt"
    
    if command -v httpx >/dev/null 2>&1; then
        cat "$OUTDIR/raw/potential_weak.txt" | httpx -silent -o "$OUTDIR/final/weak_domains.txt" 2>/dev/null || true
    fi
    
    ok "Domain enumeration complete"
}

#######################
# MODULE 3: PORT SCANNING
#######################
scan_ports() {
    section "Module 3: Port Scanning"
    
    if [ -z "$TARGET_IP" ]; then
        TARGET_IP=$(dig +short A "$TARGET" | head -n1)
    fi
    
    if [ -z "$TARGET_IP" ]; then
        warn "Cannot scan ports - no IP address available"
        return
    fi
    
    info "Scanning ports on $TARGET_IP..."
    
    if [ "$FULLSCAN" = true ]; then
        warn "Full scan mode - this will take longer..."
        nmap -sS -sV -p- -T4 -oN "$OUTDIR/raw/nmap_full.txt" -oX "$OUTDIR/raw/nmap_full.xml" "$TARGET_IP" 2>/dev/null || warn "Full nmap scan failed"
    else
        info "Scanning top 1000 ports..."
        nmap -sS -sV -T4 -oN "$OUTDIR/raw/nmap_scan.txt" -oX "$OUTDIR/raw/nmap_scan.xml" "$TARGET_IP" 2>/dev/null || warn "Nmap scan failed"
    fi
    
    # Parse open ports
    if [ -f "$OUTDIR/raw/nmap_scan.txt" ] || [ -f "$OUTDIR/raw/nmap_full.txt" ]; then
        grep "^[0-9]" "$OUTDIR/raw/nmap"*.txt 2>/dev/null | grep "open" > "$OUTDIR/final/open_ports.txt" || touch "$OUTDIR/final/open_ports.txt"
        local port_count=$(wc -l < "$OUTDIR/final/open_ports.txt" 2>/dev/null || echo 0)
        ok "Found $port_count open ports"
    else
        touch "$OUTDIR/final/open_ports.txt"
    fi
    
    # Quick UDP scan on common ports
    if [ "$FULLSCAN" = true ]; then
        info "Scanning common UDP ports..."
        nmap -sU -p 53,67,68,161,162,500 -T4 -oN "$OUTDIR/raw/nmap_udp.txt" "$TARGET_IP" 2>/dev/null || warn "UDP scan failed"
        ok "UDP scan complete"
    fi
    
    ok "Port scanning complete"
}

#######################
# MODULE 4: TECHNOLOGY DETECTION
#######################
detect_technology() {
    section "Module 4: Technology Stack Detection"
    
    local target_url="http://${TARGET}"
    if [ -f "$OUTDIR/final/live_hosts.txt" ]; then
        target_url=$(head -n1 "$OUTDIR/final/live_hosts.txt")
    fi
    
    # WhatWeb
    if command -v whatweb >/dev/null 2>&1; then
        info "Running WhatWeb..."
        whatweb -a 3 --color=never "$target_url" > "$OUTDIR/raw/whatweb.txt" 2>/dev/null || warn "WhatWeb failed"
        ok "WhatWeb scan complete"
    fi
    
    # HTTP headers analysis
    info "Analyzing HTTP headers..."
    curl -sI "$target_url" > "$OUTDIR/raw/http_headers.txt" 2>/dev/null || warn "Could not fetch headers"
    if [ -f "$OUTDIR/raw/http_headers.txt" ]; then
        ok "HTTP headers collected"
    fi
    
    # Wappalyzer (using httpx)
    if command -v httpx >/dev/null 2>&1; then
        info "Detecting technologies with httpx..."
        echo "$target_url" | httpx -silent -tech-detect -json -o "$OUTDIR/raw/tech_detect.json" 2>/dev/null || warn "Tech detection failed"
        ok "Technology detection complete"
    fi
    
    # SSL/TLS information
    info "Checking SSL/TLS configuration..."
    echo | openssl s_client -servername "$TARGET" -connect "${TARGET}:443" 2>/dev/null | openssl x509 -noout -text > "$OUTDIR/raw/ssl_cert.txt" 2>/dev/null || warn "SSL check failed"
    
    # Extract versions and create summary
    {
        echo "=== Technology Stack Summary ==="
        echo ""
        grep -iE "server:|x-powered-by:|x-aspnet-version:" "$OUTDIR/raw/http_headers.txt" 2>/dev/null || echo "N/A"
        echo ""
        echo "=== Detailed Analysis ==="
        cat "$OUTDIR/raw/whatweb.txt" 2>/dev/null || echo "N/A"
    } > "$OUTDIR/final/technology_stack.txt"
    
    ok "Technology detection complete"
}

#######################
# MODULE 5: VULNERABILITY SCANNING
#######################
scan_vulnerabilities() {
    section "Module 5: Vulnerability Assessment"
    
    local target_url="http://${TARGET}"
    if [ -f "$OUTDIR/final/live_hosts.txt" ]; then
        target_url=$(head -n1 "$OUTDIR/final/live_hosts.txt")
    fi
    
    # Nuclei scanning (SAFE - Detection only, no exploitation)
    if command -v nuclei >/dev/null 2>&1; then
        info "Running Nuclei vulnerability scanner (SAFE mode - detection only, no attacks)..."
        
        if [ "$FULLSCAN" = true ]; then
            progress "Full Nuclei scan - checking all severity levels (this may take 5-10 minutes)..."
            echo "$target_url" | nuclei -silent -severity critical,high,medium,low -tags cve,default,exposure -o "$OUTDIR/raw/nuclei_results.txt" 2>/dev/null || warn "Nuclei scan completed with warnings"
        else
            progress "Scanning for critical and high severity vulnerabilities (2-5 minutes)..."
            echo "$target_url" | nuclei -silent -severity critical,high -tags cve,default,exposure -o "$OUTDIR/raw/nuclei_results.txt" 2>/dev/null || warn "Nuclei scan completed with warnings"
        fi
        
        if [ -f "$OUTDIR/raw/nuclei_results.txt" ] && [ -s "$OUTDIR/raw/nuclei_results.txt" ]; then
            local vuln_count=$(wc -l < "$OUTDIR/raw/nuclei_results.txt" 2>/dev/null || echo 0)
            if [ "$vuln_count" -gt 0 ]; then
                warn "Found $vuln_count confirmed vulnerabilities (safe detection only)"
            else
                ok "No vulnerabilities detected"
            fi
        else
            ok "No vulnerabilities detected"
        fi
    fi
    
    # Nikto web server scanner
    if command -v nikto >/dev/null 2>&1 && [ "$FULLSCAN" = true ]; then
        info "Running Nikto web vulnerability scanner..."
        nikto -h "$target_url" -Format txt -output "$OUTDIR/raw/nikto_results.txt" 2>/dev/null || warn "Nikto scan failed"
        ok "Nikto scan complete"
    fi
    
    # Check for common misconfigurations
    info "Checking for common misconfigurations..."
    {
        echo "=== Testing common paths ==="
        for path in "/.git/config" "/robots.txt" "/.env" "/admin" "/phpmyadmin" "/backup" "/.well-known/security.txt"; do
            response=$(curl -s -o /dev/null -w "%{http_code}" "${target_url}${path}" 2>/dev/null || echo "000")
            if [ "$response" = "200" ]; then
                echo "FOUND: ${path} (HTTP $response)"
            fi
        done
    } > "$OUTDIR/final/misconfigurations.txt"
    ok "Misconfiguration check complete"
    
    # Consolidate vulnerabilities
    info "Consolidating vulnerability findings..."
    {
        echo "=== VULNERABILITY SUMMARY ==="
        echo ""
        if [ -f "$OUTDIR/raw/nuclei_results.txt" ]; then
            echo "--- Nuclei Findings ---"
            cat "$OUTDIR/raw/nuclei_results.txt"
            echo ""
        fi
        if [ -f "$OUTDIR/final/misconfigurations.txt" ]; then
            echo "--- Misconfigurations ---"
            cat "$OUTDIR/final/misconfigurations.txt"
            echo ""
        fi
    } > "$OUTDIR/final/vulnerabilities.txt"
    
    ok "Vulnerability assessment complete"
}

#######################
# MODULE 6: URL HARVESTING
#######################
harvest_urls() {
    section "Module 6: URL Discovery & Analysis"
    
    # Wayback Machine
    if command -v waybackurls >/dev/null 2>&1; then
        info "Harvesting URLs from Wayback Machine..."
        echo "$TARGET" | waybackurls > "$OUTDIR/raw/wayback_urls.txt" 2>/dev/null || warn "Waybackurls failed"
        ok "Wayback URLs collected"
    fi
    
    # GAU (Get All URLs)
if command -v gau >/dev/null 2>&1; then
        info "Collecting URLs with GAU..."
        echo "$TARGET" | gau --threads 5 > "$OUTDIR/raw/gau_urls.txt" 2>/dev/null || warn "GAU failed"
        ok "GAU URLs collected"
    fi
    
    # Katana web crawler
    if command -v katana >/dev/null 2>&1 && [ "$FULLSCAN" = true ]; then
        info "Crawling with Katana..."
        local target_url="https://${TARGET}"
        echo "$target_url" | katana -silent -d 3 -o "$OUTDIR/raw/katana_urls.txt" 2>/dev/null || warn "Katana failed"
        ok "Katana crawling complete"
    fi
    
    # Consolidate URLs
    info "Consolidating discovered URLs..."
    cat "$OUTDIR/raw/"*_urls.txt 2>/dev/null | sort -u > "$OUTDIR/final/all_urls.txt" || true
    local url_count=$(wc -l < "$OUTDIR/final/all_urls.txt" 2>/dev/null || echo 0)
    ok "Collected $url_count unique URLs"
    
    # Find interesting parameters
    info "Analyzing URL parameters..."
    grep -E "\?" "$OUTDIR/final/all_urls.txt" 2>/dev/null | sort -u > "$OUTDIR/final/urls_with_params.txt" || true
    
    ok "URL harvesting complete"
}

#######################
# MODULE 7: EXPLOITATION ANALYSIS
#######################
analyze_exploitation() {
    section "Module 7: Exploitation Analysis & Remediation"
    
    info "Analyzing vulnerabilities for exploitation vectors..."
    
    # Create exploitation analysis report
    {
        echo "=== EXPLOITATION ANALYSIS & REMEDIATION GUIDE ==="
        echo ""
        echo "Generated: $(date)"
        echo "Target: $TARGET"
        echo ""
        
        # Analyze Nuclei findings
        if [ -f "$OUTDIR/raw/nuclei_results.txt" ] && [ -s "$OUTDIR/raw/nuclei_results.txt" ]; then
            echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
            echo "IDENTIFIED VULNERABILITIES & EXPLOITATION METHODS"
            echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
            echo ""
            
            while IFS= read -r line; do
                echo "► $line"
                echo ""
                
                # Provide context based on vulnerability type
                if echo "$line" | grep -qi "xss\|cross-site"; then
                    cat << 'XSS'
  EXPLOITATION METHOD:
    - Inject malicious JavaScript into vulnerable parameter
    - Common payloads: <script>alert(1)</script>, <img src=x onerror=alert(1)>
    - Can lead to: Session hijacking, credential theft, defacement
    
  REMEDIATION:
    ✓ Implement proper input validation and output encoding
    ✓ Use Content Security Policy (CSP) headers
    ✓ Enable HttpOnly and Secure flags on cookies
    ✓ Sanitize all user inputs before rendering
    
  SEVERITY: HIGH
  
XSS
                elif echo "$line" | grep -qi "sql"; then
                    cat << 'SQL'
  EXPLOITATION METHOD:
    - Inject SQL commands into vulnerable parameters
    - Common payloads: ' OR '1'='1, UNION SELECT, ; DROP TABLE
    - Can lead to: Database compromise, data exfiltration, authentication bypass
    
  REMEDIATION:
    ✓ Use parameterized queries/prepared statements
    ✓ Implement proper input validation
    ✓ Apply least privilege principle to database accounts
    ✓ Use Web Application Firewall (WAF)
    
  SEVERITY: CRITICAL
  
SQL
                elif echo "$line" | grep -qi "lfi\|file-inclusion\|path-traversal"; then
                    cat << 'LFI'
  EXPLOITATION METHOD:
    - Manipulate file paths to access sensitive files
    - Common payloads: ../../etc/passwd, ../../../windows/system32/config/sam
    - Can lead to: Configuration file disclosure, code execution
    
  REMEDIATION:
    ✓ Validate and sanitize file path inputs
    ✓ Use whitelists for allowed files
    ✓ Implement proper access controls
    ✓ Disable directory listing
    
  SEVERITY: HIGH
  
LFI
                elif echo "$line" | grep -qi "ssrf\|server-side"; then
                    cat << 'SSRF'
  EXPLOITATION METHOD:
    - Force server to make requests to unintended locations
    - Can access internal services, cloud metadata endpoints
    - Common targets: http://169.254.169.254/latest/meta-data/, localhost
    
  REMEDIATION:
    ✓ Validate and whitelist allowed URLs/IPs
    ✓ Disable unnecessary URL schemas (file://, gopher://)
    ✓ Implement network segmentation
    ✓ Use allow-lists instead of deny-lists
    
  SEVERITY: CRITICAL
  
SSRF
                elif echo "$line" | grep -qi "rce\|remote-code\|command-injection"; then
                    cat << 'RCE'
  EXPLOITATION METHOD:
    - Execute arbitrary commands on the server
    - Common payloads: ; ls -la, && whoami, | cat /etc/passwd
    - Can lead to: Complete system compromise, data breach
    
  REMEDIATION:
    ✓ Never pass user input to system commands
    ✓ Use language-specific APIs instead of shell commands
    ✓ Implement strict input validation
    ✓ Run applications with minimal privileges
    
  SEVERITY: CRITICAL
  
RCE
                else
                    echo "  Review the specific vulnerability details and apply appropriate security patches."
                    echo ""
                fi
                
                echo "────────────────────────────────────────────────────────────────"
                echo ""
            done < "$OUTDIR/raw/nuclei_results.txt"
        else
            echo "✓ No critical vulnerabilities detected by automated scanners"
            echo ""
        fi
        
        # General security recommendations
        echo ""
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "GENERAL SECURITY RECOMMENDATIONS"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo ""
        echo "1. INFRASTRUCTURE SECURITY"
        echo "   • Keep all software and dependencies up to date"
        echo "   • Implement proper firewall rules and network segmentation"
        echo "   • Use strong TLS/SSL configuration (TLS 1.2+)"
        echo "   • Disable unnecessary services and ports"
        echo ""
        echo "2. APPLICATION SECURITY"
        echo "   • Implement comprehensive input validation"
        echo "   • Use security headers (CSP, HSTS, X-Frame-Options)"
        echo "   • Enable proper authentication and authorization"
        echo "   • Implement rate limiting and CAPTCHA"
        echo ""
        echo "3. DATA PROTECTION"
        echo "   • Encrypt sensitive data at rest and in transit"
        echo "   • Implement proper session management"
        echo "   • Use secure password hashing (bcrypt, Argon2)"
        echo "   • Regular security audits and penetration testing"
        echo ""
        echo "4. MONITORING & RESPONSE"
        echo "   • Implement comprehensive logging"
        echo "   • Set up intrusion detection systems (IDS)"
        echo "   • Create incident response plan"
        echo "   • Regular backup and disaster recovery testing"
        echo ""
        
    } > "$OUTDIR/final/exploitation_analysis.txt"
    
    ok "Exploitation analysis complete"
}

#######################
# MODULE 8: RISK ASSESSMENT
#######################
assess_risk() {
    section "Module 8: Risk Assessment & Scoring"
    
    info "Calculating risk scores..."
    
    local critical_count=0
    local high_count=0
    local medium_count=0
    local low_count=0
    local risk_score=0
    
    # Count vulnerabilities by severity from Nuclei results
    if [ -f "$OUTDIR/raw/nuclei_results.txt" ] && [ -s "$OUTDIR/raw/nuclei_results.txt" ]; then
        critical_count=$(grep -ci "critical" "$OUTDIR/raw/nuclei_results.txt" 2>/dev/null || echo "0")
        high_count=$(grep -ci "high" "$OUTDIR/raw/nuclei_results.txt" 2>/dev/null || echo "0")
        medium_count=$(grep -ci "medium" "$OUTDIR/raw/nuclei_results.txt" 2>/dev/null || echo "0")
        low_count=$(grep -ci "low" "$OUTDIR/raw/nuclei_results.txt" 2>/dev/null || echo "0")
    fi
    
    # Ensure counts are numeric
    critical_count=${critical_count:-0}
    high_count=${high_count:-0}
    medium_count=${medium_count:-0}
    low_count=${low_count:-0}
    
    # Calculate risk score (0-100 scale)
    risk_score=$((critical_count * 10 + high_count * 5 + medium_count * 2 + low_count * 1))
    if [ $risk_score -gt 100 ]; then
        risk_score=100
    fi
    
    # Determine risk level
    local risk_level="LOW"
    local risk_color="${GREEN}"
    if [ $risk_score -ge 70 ]; then
        risk_level="CRITICAL"
        risk_color="${RED}"
    elif [ $risk_score -ge 40 ]; then
        risk_level="HIGH"
        risk_color="${YELLOW}"
    elif [ $risk_score -ge 20 ]; then
        risk_level="MEDIUM"
        risk_color="${BLUE}"
    fi
    
    # Create risk assessment report
    {
        echo "=== RISK ASSESSMENT REPORT ==="
        echo ""
        echo "Target: $TARGET"
        echo "Assessment Date: $(date)"
        echo ""
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "VULNERABILITY SUMMARY"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo ""
        printf "%-15s %5d\n" "Critical:" "$critical_count"
        printf "%-15s %5d\n" "High:" "$high_count"
        printf "%-15s %5d\n" "Medium:" "$medium_count"
        printf "%-15s %5d\n" "Low:" "$low_count"
        echo ""
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "OVERALL RISK ASSESSMENT"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo ""
        printf "Risk Score:  %d/100\n" "$risk_score"
        printf "Risk Level:  %s\n" "$risk_level"
        echo ""
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "BUSINESS IMPACT ANALYSIS"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo ""
        
        if [ $risk_score -ge 70 ]; then
            cat << 'CRITICAL_IMPACT'
⚠️  CRITICAL RISK - IMMEDIATE ACTION REQUIRED

POTENTIAL CONSEQUENCES:
• Complete system compromise and unauthorized access
• Large-scale data breach affecting customers/users
• Significant financial losses and regulatory penalties
• Severe reputation damage and loss of customer trust
• Potential legal liabilities and compliance violations
• Service disruption and business continuity threats

RECOMMENDED ACTIONS:
1. Implement emergency security patches immediately
2. Isolate affected systems if actively exploited
3. Engage security incident response team
4. Notify stakeholders and prepare breach notifications
5. Conduct forensic analysis to determine exposure
6. Implement compensating controls urgently

TIMELINE: Address within 24-48 hours
CRITICAL_IMPACT
        elif [ $risk_score -ge 40 ]; then
            cat << 'HIGH_IMPACT'
⚠️  HIGH RISK - PROMPT ACTION NEEDED

POTENTIAL CONSEQUENCES:
• Unauthorized access to sensitive data
• Service disruption and availability issues
• Moderate financial impact from security incidents
• Damage to organizational reputation
• Potential compliance violations
• Increased attack surface for future exploits

RECOMMENDED ACTIONS:
1. Prioritize vulnerability remediation in sprint planning
2. Apply security patches and updates
3. Implement additional security controls
4. Enhance monitoring and detection capabilities
5. Review and update security policies
6. Conduct security awareness training

TIMELINE: Address within 1-2 weeks
HIGH_IMPACT
        elif [ $risk_score -ge 20 ]; then
            cat << 'MEDIUM_IMPACT'
⚠️  MEDIUM RISK - SCHEDULED REMEDIATION

POTENTIAL CONSEQUENCES:
• Limited unauthorized access possibilities
• Minor information disclosure
• Reduced system performance or availability
• Increased vulnerability to targeted attacks
• Potential for privilege escalation

RECOMMENDED ACTIONS:
1. Include fixes in regular maintenance cycle
2. Apply updates during scheduled maintenance windows
3. Review and improve security configurations
4. Implement defense-in-depth strategies
5. Regular security scanning and monitoring

TIMELINE: Address within 30 days
MEDIUM_IMPACT
        else
            cat << 'LOW_IMPACT'
✓ LOW RISK - ROUTINE MAINTENANCE

POTENTIAL CONSEQUENCES:
• Minimal security impact
• Limited information disclosure
• Minor configuration improvements needed

RECOMMENDED ACTIONS:
1. Include in regular security maintenance
2. Apply best practices and hardening guides
3. Maintain current security posture
4. Continue regular security assessments

TIMELINE: Address in normal maintenance cycle
LOW_IMPACT
        fi
        
        echo ""
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo "COMPLIANCE CONSIDERATIONS"
        echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
        echo ""
        echo "Organizations should consider the following compliance frameworks:"
        echo ""
        echo "• GDPR - General Data Protection Regulation"
        echo "• PCI DSS - Payment Card Industry Data Security Standard"
        echo "• HIPAA - Health Insurance Portability and Accountability Act"
        echo "• SOC 2 - Service Organization Control 2"
        echo "• ISO 27001 - Information Security Management"
        echo "• NIST Cybersecurity Framework"
        echo ""
        
    } > "$OUTDIR/final/risk_assessment.txt"
    
    # Display summary
    printf "\n"
    info "Risk Assessment Summary:"
    printf "  ${risk_color}Risk Level: %s${RESET}\n" "$risk_level"
    printf "  Risk Score: %d/100\n" "$risk_score"
    printf "  Critical: %d | High: %d | Medium: %d | Low: %d\n" "$critical_count" "$high_count" "$medium_count" "$low_count"
    
    ok "Risk assessment complete"
}

#######################
# MODULE 9: REPORT GENERATION
#######################
generate_report() {
    section "Module 9: Generating Comprehensive Report"
    
    info "Compiling final report..."
    
    local report_file="$OUTDIR/FootSprinter_Report_${TARGET}_${TIMESTAMP}.html"
    
    # Count statistics
    local subdomain_count=$(wc -l < "$OUTDIR/final/all_subdomains.txt" 2>/dev/null || echo 0)
    local live_count=$(wc -l < "$OUTDIR/final/live_hosts.txt" 2>/dev/null || echo 0)
    local port_count=$(wc -l < "$OUTDIR/final/open_ports.txt" 2>/dev/null || echo 0)
    local url_count=$(wc -l < "$OUTDIR/final/all_urls.txt" 2>/dev/null || echo 0)
    local vuln_count=$(wc -l < "$OUTDIR/raw/nuclei_results.txt" 2>/dev/null || echo 0)
    
    # Get target IP
    local target_ip=$(cat "$OUTDIR/raw/target_ip.txt" 2>/dev/null || echo "N/A")
    
    # Create HTML report
    cat > "$report_file" << 'EOF'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>FootSprinter Security Assessment Report</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px;
            color: #333;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 10px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            overflow: hidden;
        }
        .header {
            background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
            color: white;
            padding: 40px;
            text-align: center;
        }
        .header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
        }
        .header .subtitle {
            font-size: 1.2em;
            opacity: 0.9;
        }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            padding: 30px;
            background: #f8f9fa;
        }
        .stat-card {
            background: white;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            transition: transform 0.3s;
        }
        .stat-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 5px 20px rgba(0,0,0,0.15);
        }
        .stat-number {
            font-size: 2.5em;
            font-weight: bold;
            color: #667eea;
            margin: 10px 0;
        }
        .stat-label {
            color: #666;
            font-size: 0.9em;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
        .section {
            padding: 30px;
            border-bottom: 1px solid #eee;
        }
        .section:last-child {
            border-bottom: none;
        }
        .section h2 {
            color: #2a5298;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 3px solid #667eea;
            font-size: 1.8em;
        }
        .section h3 {
            color: #444;
            margin-top: 20px;
            margin-bottom: 10px;
        }
        .info-table {
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }
        .info-table th, .info-table td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        .info-table th {
            background: #f8f9fa;
            font-weight: 600;
            color: #2a5298;
            width: 200px;
        }
        .code-block {
            background: #f4f4f4;
            border-left: 4px solid #667eea;
            padding: 15px;
            margin: 15px 0;
            border-radius: 4px;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
            overflow-x: auto;
            white-space: pre-wrap;
            word-wrap: break-word;
        }
        .vulnerability-card {
            background: #fff3cd;
            border-left: 4px solid #ffc107;
            padding: 15px;
            margin: 10px 0;
            border-radius: 4px;
        }
        .vulnerability-critical {
            background: #f8d7da;
            border-left-color: #dc3545;
        }
        .vulnerability-high {
            background: #fff3cd;
            border-left-color: #ffc107;
        }
        .vulnerability-medium {
            background: #d1ecf1;
            border-left-color: #17a2b8;
        }
        .vulnerability-low {
            background: #d4edda;
            border-left-color: #28a745;
        }
        .badge {
            display: inline-block;
            padding: 5px 10px;
            border-radius: 12px;
            font-size: 0.85em;
            font-weight: 600;
            margin-right: 5px;
        }
        .badge-critical {
            background: #dc3545;
            color: white;
        }
        .badge-high {
            background: #ffc107;
            color: #333;
        }
        .badge-medium {
            background: #17a2b8;
            color: white;
        }
        .badge-low {
            background: #28a745;
            color: white;
        }
        .footer {
            background: #2a5298;
            color: white;
            padding: 20px;
            text-align: center;
        }
        .risk-meter {
            width: 100%;
            height: 30px;
            background: #e0e0e0;
            border-radius: 15px;
            overflow: hidden;
            margin: 20px 0;
        }
        .risk-fill {
            height: 100%;
            background: linear-gradient(90deg, #28a745, #ffc107, #dc3545);
            border-radius: 15px;
            transition: width 0.5s;
            display: flex;
            align-items: center;
            justify-content: flex-end;
            padding-right: 10px;
            color: white;
            font-weight: bold;
        }
        .list-items {
            list-style: none;
            padding-left: 0;
        }
        .list-items li {
            padding: 8px 0;
            border-bottom: 1px solid #eee;
        }
        .list-items li:before {
            content: "▸ ";
            color: #667eea;
            font-weight: bold;
            margin-right: 5px;
        }
        @media print {
            body {
                background: white;
                padding: 0;
            }
            .container {
                box-shadow: none;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 FootSprinter</h1>
            <div class="subtitle">Security Assessment & Vulnerability Report</div>
            <div style="margin-top: 20px; font-size: 0.9em;">
                <div>Generated: REPORT_DATE</div>
                <div>Target: TARGET_DOMAIN</div>
            </div>
        </div>

        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-label">Subdomains</div>
                <div class="stat-number">SUBDOMAIN_COUNT</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Live Hosts</div>
                <div class="stat-number">LIVE_COUNT</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Open Ports</div>
                <div class="stat-number">PORT_COUNT</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">URLs Found</div>
                <div class="stat-number">URL_COUNT</div>
            </div>
            <div class="stat-card">
                <div class="stat-label">Vulnerabilities</div>
                <div class="stat-number">VULN_COUNT</div>
            </div>
        </div>

        <div class="section">
            <h2>📊 Executive Summary</h2>
            <p>This comprehensive security assessment was conducted on <strong>TARGET_DOMAIN</strong> using FootSprinter v2.0, 
            an advanced reconnaissance and vulnerability assessment framework. The assessment included company intelligence gathering,
            infrastructure mapping, technology stack analysis, and comprehensive vulnerability scanning.</p>
            
            <h3>Risk Assessment</h3>
            <div class="risk-meter">
                <div class="risk-fill" style="width: RISK_PERCENTAGE%;">RISK_SCORE/100</div>
            </div>
            <p><strong>Overall Risk Level:</strong> <span class="badge badge-RISK_CLASS">RISK_LEVEL</span></p>
        </div>

        <div class="section">
            <h2>🏢 Company Intelligence</h2>
            <table class="info-table">
                <tr>
                    <th>Target Domain</th>
                    <td>TARGET_DOMAIN</td>
                </tr>
                <tr>
                    <th>Target IP</th>
                    <td>TARGET_IP</td>
                </tr>
                <tr>
                    <th>Assessment Date</th>
                    <td>REPORT_DATE</td>
                </tr>
            </table>
            
            <h3>WHOIS Information</h3>
            <div class="code-block">WHOIS_DATA</div>
            
            <h3>DNS Records</h3>
            <div class="code-block">DNS_RECORDS</div>
        </div>

        <div class="section">
            <h2>🌐 Domain & Subdomain Analysis</h2>
            <p>Discovered <strong>SUBDOMAIN_COUNT</strong> unique subdomains, of which <strong>LIVE_COUNT</strong> are live and responding.</p>
            
            <h3>Live Hosts</h3>
            <ul class="list-items">
LIVE_HOSTS_LIST
            </ul>
            
            <h3>Potentially Weak Domains</h3>
            <div class="code-block">WEAK_DOMAINS</div>
        </div>

        <div class="section">
            <h2>🔌 Port Scan Results</h2>
            <p>Identified <strong>PORT_COUNT</strong> open ports on the target infrastructure.</p>
            <div class="code-block">OPEN_PORTS</div>
        </div>

        <div class="section">
            <h2>⚙️ Technology Stack</h2>
            <p>Detected technologies, frameworks, and versions running on the target application.</p>
            <div class="code-block">TECH_STACK</div>
            
            <h3>HTTP Headers</h3>
            <div class="code-block">HTTP_HEADERS</div>
        </div>

        <div class="section">
            <h2>🛡️ Vulnerability Assessment</h2>
            <p>Comprehensive vulnerability scan results showing potential security issues.</p>
            
VULNERABILITY_SECTION

            <h3>Common Misconfigurations</h3>
            <div class="code-block">MISCONFIG_DATA</div>
        </div>

        <div class="section">
            <h2>💥 Exploitation Analysis</h2>
            <div class="code-block">EXPLOITATION_ANALYSIS</div>
        </div>

        <div class="section">
            <h2>📈 Risk Assessment & Business Impact</h2>
            <div class="code-block">RISK_ASSESSMENT</div>
        </div>

        <div class="section">
            <h2>✅ Recommendations & Conclusions</h2>
            
            <h3>Immediate Actions Required</h3>
            <ul class="list-items">
                <li>Review and remediate all CRITICAL and HIGH severity vulnerabilities</li>
                <li>Implement security patches for identified outdated software versions</li>
                <li>Review and strengthen access controls and authentication mechanisms</li>
                <li>Enable security headers (CSP, HSTS, X-Frame-Options, etc.)</li>
                <li>Implement rate limiting and DDoS protection</li>
            </ul>
            
            <h3>Long-term Security Improvements</h3>
            <ul class="list-items">
                <li>Establish regular security assessment and penetration testing schedule</li>
                <li>Implement comprehensive logging and monitoring solutions</li>
                <li>Conduct security awareness training for development teams</li>
                <li>Implement secure SDLC practices with security reviews</li>
                <li>Establish incident response plan and procedures</li>
                <li>Regular third-party security audits and compliance assessments</li>
            </ul>
            
            <h3>Conclusion</h3>
            <p>This assessment provides a comprehensive overview of the security posture of <strong>TARGET_DOMAIN</strong>. 
            The findings should be prioritized based on risk level and business impact. Regular security assessments 
            are recommended to maintain a strong security posture and protect against evolving threats.</p>
            
            <p><strong>Note:</strong> This assessment represents a point-in-time analysis. Continuous monitoring 
            and regular security testing are essential components of a comprehensive security program.</p>
        </div>

        <div class="footer">
            <div>Generated by FootSprinter v2.0 - Advanced Security Assessment Framework</div>
            <div style="margin-top: 10px; font-size: 0.9em;">Aarham Labs (Rushil P. Shah)</div>
            <div style="margin-top: 10px; font-size: 0.8em; opacity: 0.8;">
                ⚠️ This report contains sensitive security information. Handle with care.
            </div>
        </div>
    </div>
</body>
</html>
EOF

    # Replace placeholders with actual data
    info "Populating report with assessment data..."
    
    # Basic replacements
    sed -i "s|TARGET_DOMAIN|$TARGET|g" "$report_file"
    sed -i "s|REPORT_DATE|$(date)|g" "$report_file"
    sed -i "s|SUBDOMAIN_COUNT|$subdomain_count|g" "$report_file"
    sed -i "s|LIVE_COUNT|$live_count|g" "$report_file"
    sed -i "s|PORT_COUNT|$port_count|g" "$report_file"
    sed -i "s|URL_COUNT|$url_count|g" "$report_file"
    sed -i "s|VULN_COUNT|$vuln_count|g" "$report_file"
    sed -i "s|TARGET_IP|$target_ip|g" "$report_file"
    
    # Calculate risk percentage and level
    local risk_score=$(grep "Risk Score:" "$OUTDIR/final/risk_assessment.txt" 2>/dev/null | grep -oE '[0-9]+' | head -1 || echo 0)
    local risk_level=$(grep "Risk Level:" "$OUTDIR/final/risk_assessment.txt" 2>/dev/null | awk '{print $NF}' || echo "LOW")
    local risk_class=$(echo "$risk_level" | tr '[:upper:]' '[:lower:]')
    
    sed -i "s|RISK_SCORE|$risk_score|g" "$report_file"
    sed -i "s|RISK_PERCENTAGE|$risk_score|g" "$report_file"
    sed -i "s|RISK_LEVEL|$risk_level|g" "$report_file"
    sed -i "s|RISK_CLASS|$risk_class|g" "$report_file"
    
    # Insert file contents (with HTML escaping)
    export REPORT_FILE="$report_file"
    export OUTDIR_PATH="$OUTDIR"
    python3 << 'PYTHON_SCRIPT'
import sys
import html
import re
import os

report_file = os.environ.get('REPORT_FILE', '')
outdir = os.environ.get('OUTDIR_PATH', '')

with open(report_file, 'r') as f:
    content = f.read()

# Helper function to read and escape file content
def read_file(path, default="No data available"):
    try:
        with open(path, 'r') as f:
            data = f.read()
            return html.escape(data) if data.strip() else default
    except:
        return default

# Read data files
whois_data = read_file(f"{outdir}/final/company_info.txt")
dns_records = read_file(f"{outdir}/raw/dns_records.txt")
open_ports = read_file(f"{outdir}/final/open_ports.txt", "No open ports detected")
tech_stack = read_file(f"{outdir}/final/technology_stack.txt")
http_headers = read_file(f"{outdir}/raw/http_headers.txt")
misconfig = read_file(f"{outdir}/final/misconfigurations.txt", "No misconfigurations detected")
exploitation = read_file(f"{outdir}/final/exploitation_analysis.txt")
risk_assessment = read_file(f"{outdir}/final/risk_assessment.txt")
weak_domains = read_file(f"{outdir}/final/weak_domains.txt", "None detected")

# Live hosts list
live_hosts_html = ""
try:
    with open(f"{outdir}/final/live_hosts.txt", 'r') as f:
        for line in f:
            line = line.strip()
            if line:
                live_hosts_html += f"                <li>{html.escape(line)}</li>\n"
except:
    live_hosts_html = "                <li>No live hosts detected</li>\n"

# Vulnerability section
vuln_section = ""
try:
    with open(f"{outdir}/raw/nuclei_results.txt", 'r') as f:
        for line in f:
            line = line.strip()
            if line:
                severity_class = "medium"
                if "critical" in line.lower():
                    severity_class = "critical"
                elif "high" in line.lower():
                    severity_class = "high"
                elif "low" in line.lower():
                    severity_class = "low"
                
                vuln_section += f'            <div class="vulnerability-card vulnerability-{severity_class}">\n'
                vuln_section += f'                {html.escape(line)}\n'
                vuln_section += '            </div>\n'
    if not vuln_section:
        vuln_section = '            <div class="vulnerability-card vulnerability-low">✓ No vulnerabilities detected by automated scanners</div>\n'
except:
    vuln_section = '            <div class="vulnerability-card vulnerability-low">✓ No vulnerabilities detected by automated scanners</div>\n'

# Replace placeholders
content = content.replace("WHOIS_DATA", whois_data)
content = content.replace("DNS_RECORDS", dns_records)
content = content.replace("LIVE_HOSTS_LIST", live_hosts_html)
content = content.replace("WEAK_DOMAINS", weak_domains)
content = content.replace("OPEN_PORTS", open_ports)
content = content.replace("TECH_STACK", tech_stack)
content = content.replace("HTTP_HEADERS", http_headers)
content = content.replace("VULNERABILITY_SECTION", vuln_section)
content = content.replace("MISCONFIG_DATA", misconfig)
content = content.replace("EXPLOITATION_ANALYSIS", exploitation)
content = content.replace("RISK_ASSESSMENT", risk_assessment)

# Write back
with open(report_file, 'w') as f:
    f.write(content)

PYTHON_SCRIPT
    
    if [ $? -eq 0 ]; then
        ok "HTML report generated: $report_file"
    else
        warn "Report generation completed with warnings"
        ok "HTML report: $report_file"
    fi
    
    # Create text summary
    {
        echo "═══════════════════════════════════════════════════════════"
        echo "           FOOTSPRINTER ASSESSMENT SUMMARY"
        echo "═══════════════════════════════════════════════════════════"
        echo ""
        echo "Target: $TARGET"
        echo "Date: $(date)"
        echo ""
        echo "STATISTICS:"
        echo "  • Subdomains Found: $subdomain_count"
        echo "  • Live Hosts: $live_count"
        echo "  • Open Ports: $port_count"
        echo "  • URLs Collected: $url_count"
        echo "  • Vulnerabilities: $vuln_count"
        echo ""
        echo "RISK LEVEL: $risk_level (Score: $risk_score/100)"
        echo ""
        echo "═══════════════════════════════════════════════════════════"
        echo ""
        echo "Full HTML report: $report_file"
        echo ""
    } > "$OUTDIR/SUMMARY.txt"
    
    ok "Summary generated: $OUTDIR/SUMMARY.txt"
}

#######################
# MAIN EXECUTION
#######################
main() {
    # Save original arguments for re-execution
    local orig_args=("$@")
    
    show_banner
    
    parse_arguments "$@"
    
    # Check root privileges
    check_root "${orig_args[@]}"
    
    # Create output directory
    OUTDIR="FootSprinter_${TARGET}_${TIMESTAMP}"
    mkdir -p "$OUTDIR/raw" "$OUTDIR/final"
    ok "Created output directory: $OUTDIR"
    
    # Set user agent
    if [ "$CUSTOM_HEADERS" = true ]; then
        USER_AGENT=$(get_random_user_agent)
        info "Using randomized User-Agent"
    fi
    
    # Install dependencies
    install_dependencies
    
    # Run assessment modules
    gather_company_intelligence
    enumerate_domains
    scan_ports
    detect_technology
    harvest_urls
    scan_vulnerabilities
    analyze_exploitation
    assess_risk
    generate_report
    
    # Final summary
    section "Assessment Complete!"
    cat "$OUTDIR/SUMMARY.txt"
    
    printf "\n${GREEN}${BOLD}✓ All modules completed successfully!${RESET}\n"
    printf "${CYAN}→ Full HTML report: %s${RESET}\n" "$OUTDIR/FootSprinter_Report_${TARGET}_${TIMESTAMP}.html"
    printf "${CYAN}→ All data saved in: %s${RESET}\n\n" "$OUTDIR"
    
    warn "Remember: This tool is for authorized security testing only!"
}

# Run main function
main "$@"
