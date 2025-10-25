#!/usr/bin/env bash
# FootSprinter - One-shot OSINT/footprinting for Kali (Improved UI)
# Author: Aarham Labs (Rushil P Shah)
# Usage: ./FootSprinter.sh
set -euo pipefail

#######################
# Colors & helpers
#######################
ESC="\033["
RESET="${ESC}0m"
BOLD="${ESC}1m"
DIM="${ESC}2m"
UNDER="${ESC}4m"

# Colors
RED="${ESC}31;1m"
GREEN="${ESC}32;1m"
YELLOW="${ESC}33;1m"
BLUE="${ESC}34;1m"
MAGENTA="${ESC}35;1m"
CYAN="${ESC}36;1m"
WHITE="${ESC}37;1m"

# small helpers
sep() { printf "${DIM}%s${RESET}\n" "────────────────────────────────────────────────────────────────────────"; }
section() { printf "\n${BOLD}${BLUE}==> %s${RESET}\n" "$1"; sep; }
info(){ printf " ${CYAN}[+]${RESET} %s\n" "$1"; }
ok(){ printf " ${GREEN}[✓]${RESET} %s\n" "$1"; }
warn(){ printf " ${YELLOW}[!]${RESET} %s\n" "$1"; }
err(){ printf " ${RED}[-]${RESET} %s\n" "$1"; }

#######################
# PATH / Go settings
#######################
GOBIN="${GOBIN:-$HOME/go/bin}"
export PATH="$GOBIN:$PATH"
export GOPATH="${GOPATH:-$HOME/go}"

#######################
# Fancy ASCII banner (large, high-contrast)
#######################
cat <<'BANNER'

███████╗ ██████╗  ██████╗████████╗███████╗██████╗ ███╗   ███╗███████╗████████╗
██╔════╝██╔═══██╗██╔════╝╚══██╔══╝██╔════╝██╔══██╗████╗ ████║██╔════╝╚══██╔══╝
█████╗  ██║   ██║██║  ███╗  ██║   █████╗  ██████╔╝██╔████╔██║█████╗     ██║   
██╔══╝  ██║   ██║██║   ██║  ██║   ██╔══╝  ██╔══██╗██║╚██╔╝██║██╔══╝     ██║   
██║     ╚██████╔╝╚██████╔╝  ██║   ███████╗██║  ██║██║ ╚═╝ ██║███████╗   ██║   
╚═╝      ╚═════╝  ╚═════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝╚══════╝   ╚═╝   

   ███████╗ ██████╗ ██████╗ ███████╗███████╗██████╗ ████████╗██████╗ 
   ██╔════╝██╔════╝██╔═══██╗██╔════╝██╔════╝██╔══██╗╚══██╔══╝██╔══██╗
   ███████╗██║     ██║   ██║█████╗  ███████╗██████╔╝   ██║   ██████╔╝
   ╚════██║██║     ██║   ██║██╔══╝  ╚════██║██╔═══╝    ██║   ██╔══██╗
   ███████║╚██████╗╚██████╔╝███████╗███████║██║        ██║   ██║  ██║
   ╚══════╝ ╚═════╝ ╚═════╝ ╚══════╝╚══════╝╚═╝        ╚═╝   ╚═╝  ╚═╝

                FootSprinter — OSINT Footprinting Toolkit
                 Author: Aarham Labs (Rushil P. Shah)
BANNER

sep
printf " %s\n" "${BOLD}${MAGENTA}Quick note:${RESET} This script performs passive collection and light probing only."
printf " %s\n" "Have authorization from the target owner before proceeding."
sep

# Ensure script runs as root (re-run with sudo preserving environment)
if [ "$EUID" -ne 0 ]; then
  warn "This script needs sudo privileges. Re-running with sudo..."
  exec sudo -E bash "$0" "$@"
fi

#######################
# Prompt for target domain
#######################
echo ""
read -rp "Enter target domain (e.g. basrahgas.com): " TARGET
TARGET="${TARGET//https:\/\//}"
TARGET="${TARGET//http:\/\//}"
TARGET="${TARGET%%/}"
if [ -z "$TARGET" ]; then
  err "No target provided. Exiting."
  exit 1
fi

OUTDIR="FootSprinter_${TARGET}_$(date +%F_%H%M%S)"
mkdir -p "$OUTDIR/raw" "$OUTDIR/final"
ok "Outputs will be saved to: ${OUTDIR}"

#######################
# Tools to ensure installed
#######################
APT_PKGS=(amass gobuster git jq python3-pip curl openssl)
GO_TOOLS=(
  "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
  "github.com/tomnomnom/assetfinder@latest"
  "github.com/tomnomnom/waybackurls@latest"
  "github.com/lc/gau/v2/cmd/gau@latest"
  "github.com/tomnomnom/gf@latest"
  "github.com/tomnomnom/httprobe@latest"
  "github.com/projectdiscovery/httpx/cmd/httpx@latest"
  "github.com/tomnomnom/anew@latest"
)

section "Environment check & tool installation"
info "Checking required apt packages..."
MISSING=()
for p in "${APT_PKGS[@]}"; do
  if ! dpkg -s "$p" >/dev/null 2>&1; then
    MISSING+=("$p")
  fi
done

if [ "${#MISSING[@]}" -gt 0 ]; then
  warn "Missing packages detected: ${MISSING[*]}"
  info "Installing missing packages (apt-get update may run)..."
  apt-get update -y >/dev/null
  DEBIAN_FRONTEND=noninteractive apt-get install -y "${MISSING[@]}" >/dev/null
  ok "Apt packages installed."
else
  ok "All apt packages are present."
fi

# Ensure go exists
if ! command -v go >/dev/null 2>&1; then
  warn "Go not found. Installing golang-go..."
  apt-get install -y golang-go >/dev/null
  ok "Go installed."
fi

info "Installing Go-based reconnaissance tools (if missing)..."
for mod in "${GO_TOOLS[@]}"; do
  BIN="$(basename "${mod%%@*}")"
  case "$BIN" in
    subfinder) BIN=subfinder ;;
    assetfinder) BIN=assetfinder ;;
    waybackurls) BIN=waybackurls ;;
    gau) BIN=gau ;;
    gf) BIN=gf ;;
    httprobe) BIN=httprobe ;;
    httpx) BIN=httpx ;;
    anew) BIN=anew ;;
  esac

  if ! command -v "$BIN" >/dev/null 2>&1; then
    info "Installing $BIN..."
    /usr/bin/env bash -lc "GOBIN=${GOBIN} GOPATH=${GOPATH} go install ${mod}" >/dev/null 2>&1 || warn "go install for $BIN failed"
    if command -v "$BIN" >/dev/null 2>&1; then
      ok "$BIN installed."
    else
      warn "Could not install $BIN; continue and skip if absent."
    fi
  else
    ok "$BIN already installed."
  fi
done

# gf patterns
if [ ! -d "$HOME/.gf" ]; then
  info "Installing gf patterns..."
  git clone --depth 1 https://github.com/1ndianl33t/Gf-Patterns.git /tmp/gf-patterns >/dev/null 2>&1 || true
  mkdir -p "$HOME/.gf"
  cp /tmp/gf-patterns/*.json "$HOME/.gf/" 2>/dev/null || true
  ok "GF patterns copied to $HOME/.gf"
else
  ok "GF patterns present."
fi

#######################
# Run the pipeline
#######################
section "Starting FootSprinter pipeline for: ${TARGET}"
info "Step 1 — Certificate transparency (crt.sh)"
curl -s "https://crt.sh/?q=%25.${TARGET}&output=json" > "$OUTDIR/raw/crt_sh.json" || true
jq -r '.[].name_value' "$OUTDIR/raw/crt_sh.json" 2>/dev/null | sed 's/\*\.//g' | sort -u > "$OUTDIR/raw/crt_subs.txt" || true
ok "crt.sh results -> $OUTDIR/raw/crt_subs.txt"

info "Step 2 — Passive subdomain discovery: assetfinder & subfinder"
if command -v assetfinder >/dev/null 2>&1; then
  assetfinder "$TARGET" | sort -u > "$OUTDIR/raw/assetfinder.txt" || true
  ok "assetfinder -> $OUTDIR/raw/assetfinder.txt"
else
  warn "assetfinder not found; skipping."
fi

if command -v subfinder >/dev/null 2>&1; then
  subfinder -d "$TARGET" -silent -o "$OUTDIR/raw/subfinder.txt" || true
  ok "subfinder -> $OUTDIR/raw/subfinder.txt"
else
  warn "subfinder not found; skipping."
fi

info "Step 3 — Amass passive enumeration"
if command -v amass >/dev/null 2>&1; then
  amass enum -passive -d "$TARGET" -o "$OUTDIR/raw/amass_passive.txt" || true
  ok "amass -> $OUTDIR/raw/amass_passive.txt"
else
  warn "amass not found; skipping."
fi

info "Step 4 — Consolidate subdomains"
cat "$OUTDIR/raw/"*.txt 2>/dev/null | sed 's/\*\.//g' | sort -u | sed '/^$/d' > "$OUTDIR/final/all_subs.txt" || true
ok "Consolidated -> $OUTDIR/final/all_subs.txt (count: $(wc -l < "$OUTDIR/final/all_subs.txt" 2>/dev/null || echo 0))"

info "Step 5 — Probe live hosts (httpx / httprobe fallback)"
if command -v httpx >/dev/null 2>&1 && [ -s "$OUTDIR/final/all_subs.txt" ]; then
  cat "$OUTDIR/final/all_subs.txt" | httpx -silent -threads 30 -ports 80,443,8080,8443 -o "$OUTDIR/final/live_hosts.txt" || true
  ok "httpx -> $OUTDIR/final/live_hosts.txt"
elif command -v httprobe >/dev/null 2>&1 && [ -s "$OUTDIR/final/all_subs.txt" ]; then
  cat "$OUTDIR/final/all_subs.txt" | httprobe -c 50 | sed 's|http://||;s|https://||' | sort -u > "$OUTDIR/final/live_hosts.txt" || true
  ok "httprobe -> $OUTDIR/final/live_hosts.txt"
else
  warn "No probe tool found or no subdomains present; skipping live probe."
fi

info "Step 6 — Harvest URLs (waybackurls & gau)"
if command -v waybackurls >/dev/null 2>&1 && [ -s "$OUTDIR/final/all_subs.txt" ]; then
  while read -r host; do
    waybackurls "$host" || true
  done < "$OUTDIR/final/all_subs.txt" > "$OUTDIR/raw/wayback_urls.txt" || true
  ok "waybackurls -> $OUTDIR/raw/wayback_urls.txt"
else
  warn "waybackurls not available or no subs; skipping."
fi

if command -v gau >/dev/null 2>&1; then
  gau "$TARGET" 2>/dev/null > "$OUTDIR/raw/gau_urls.txt" || true
  ok "gau -> $OUTDIR/raw/gau_urls.txt"
else
  warn "gau not found; skipping."
fi

cat "$OUTDIR/raw/wayback_urls.txt" "$OUTDIR/raw/gau_urls.txt" 2>/dev/null | sort -u > "$OUTDIR/final/all_urls.txt" || true
ok "Harvested URLs consolidated -> $OUTDIR/final/all_urls.txt (count: $(wc -l < "$OUTDIR/final/all_urls.txt" 2>/dev/null || echo 0))"

info "Step 7 — GF filtering (xss, sqli, lfi, interesting)"
if command -v gf >/dev/null 2>&1 && [ -s "$OUTDIR/final/all_urls.txt" ]; then
  gf xss < "$OUTDIR/final/all_urls.txt" | sort -u > "$OUTDIR/final/xss_urls.txt" || true
  gf sqli < "$OUTDIR/final/all_urls.txt" | sort -u > "$OUTDIR/final/sqli_urls.txt" || true
  gf lfi < "$OUTDIR/final/all_urls.txt" | sort -u > "$OUTDIR/final/lfi_urls.txt" || true
  gf interesting < "$OUTDIR/final/all_urls.txt" | sort -u > "$OUTDIR/final/interesting_urls.txt" || true
  ok "GF pattern filtering complete."
else
  warn "gf not installed or no URLs; skipping GF filtering."
fi

info "Step 8 — Screenshotting (gowitness)"
if command -v gowitness >/dev/null 2>&1 && [ -s "$OUTDIR/final/live_hosts.txt" ]; then
  gowitness file -f "$OUTDIR/final/live_hosts.txt" --disable-har -P "$OUTDIR/final/gowitness" || true
  ok "Screenshots saved -> $OUTDIR/final/gowitness/"
else
  warn "gowitness not available or no live hosts; skipping screenshots."
fi

info "Step 9 — SSL certificate dump for live hosts"
if [ -s "$OUTDIR/final/live_hosts.txt" ]; then
  cut -d/ -f3 "$OUTDIR/final/live_hosts.txt" | sed 's/:.*//' | sort -u | while read -r host; do
    {
      echo "---- $host ----"
      echo | openssl s_client -servername "$host" -connect "${host}:443" 2>/dev/null | openssl x509 -noout -text 2>/dev/null || true
    } >> "$OUTDIR/raw/ssl_certs.txt"
  done
  ok "SSL certificate info -> $OUTDIR/raw/ssl_certs.txt"
else
  warn "No live hosts to query for SSL certs."
fi

#######################
# Final summary
#######################
section "Run Complete — Summary & Next steps"
SUBS_COUNT=$(wc -l < "$OUTDIR/final/all_subs.txt" 2>/dev/null || echo 0)
LIVE_COUNT=$(wc -l < "$OUTDIR/final/live_hosts.txt" 2>/dev/null || echo 0)
URLS_COUNT=$(wc -l < "$OUTDIR/final/all_urls.txt" 2>/dev/null || echo 0)
INT_COUNT=$(wc -l < "$OUTDIR/final/interesting_urls.txt" 2>/dev/null || echo 0)

printf "  %s %s\n" "${BOLD}Target:${RESET}" "${TARGET}"
printf "  %s %s\n" "Subdomains found:" "${SUBS_COUNT}"
printf "  %s %s\n" "Live hosts:" "${LIVE_COUNT}"
printf "  %s %s\n" "Harvested URLs:" "${URLS_COUNT}"
printf "  %s %s\n" "GF interesting:" "${INT_COUNT}"
sep

printf "${BOLD}Key output files:${RESET}\n"
printf "  • %s\n" "$OUTDIR/final/all_subs.txt"
printf "  • %s\n" "$OUTDIR/final/live_hosts.txt"
printf "  • %s\n" "$OUTDIR/final/all_urls.txt"
printf "  • %s\n" "$OUTDIR/final/interesting_urls.txt"
printf "  • %s\n" "$OUTDIR/raw/crt_sh.json"
printf "  • %s\n" "$OUTDIR/raw/ssl_certs.txt"
sep

printf "${YELLOW}Next recommended actions:${RESET}\n"
printf "  • Import %s into Burp / your proxy for manual testing.\n" "$OUTDIR/final/all_urls.txt"
printf "  • Review %s for likely admin/login panels.\n" "$OUTDIR/final/live_hosts.txt"
printf "  • Validate GF matches before reporting (reduce false positives).\n"
printf "  • If needed, run non-destructive nuclei templates (consent required).\n"
sep

printf "${GREEN}FootSprinter finished — outputs are in: %s${RESET}\n" "$OUTDIR"
exit 0
