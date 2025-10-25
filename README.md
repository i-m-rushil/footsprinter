# FootSprinter 🔍

**FootSprinter** is a comprehensive OSINT (Open Source Intelligence) footprinting toolkit designed for Kali Linux. It automates passive reconnaissance and information gathering for security research and penetration testing.

## 🎯 Features

- **Certificate Transparency**: Discovers subdomains via crt.sh
- **Subdomain Enumeration**: Uses multiple tools (assetfinder, subfinder, amass)
- **Live Host Detection**: Probes discovered subdomains with httpx/httprobe
- **URL Harvesting**: Collects historical URLs from Wayback Machine and other sources
- **Intelligent Filtering**: Uses GF patterns to identify potential vulnerabilities (XSS, SQLi, LFI)
- **SSL Certificate Analysis**: Dumps SSL certificate information
- **Screenshots**: Optional website screenshotting with gowitness
- **Beautiful CLI Interface**: Color-coded output with ASCII art banner

## 📋 Requirements

- Kali Linux or Debian-based system
- Root/sudo privileges
- Internet connection

### Tools Installed Automatically

**APT Packages:**
- amass, gobuster, git, jq, python3-pip, curl, openssl

**Go-based Tools:**
- subfinder, assetfinder, waybackurls, gau, gf, httprobe, httpx, anew

## 🚀 Usage

```bash
# Make the script executable
chmod +x footsprinter.sh

# Run the script (will auto-request sudo if needed)
./footsprinter.sh
```

When prompted, enter the target domain (e.g., `example.com`).

## 📂 Output Structure

```
FootSprinter_[domain]_[timestamp]/
├── raw/
│   ├── crt_sh.json           # Certificate transparency results
│   ├── crt_subs.txt          # Subdomains from crt.sh
│   ├── assetfinder.txt       # Assetfinder results
│   ├── subfinder.txt         # Subfinder results
│   ├── amass_passive.txt     # Amass passive scan
│   ├── wayback_urls.txt      # Wayback Machine URLs
│   ├── gau_urls.txt          # GetAllUrls results
│   └── ssl_certs.txt         # SSL certificate dumps
└── final/
    ├── all_subs.txt          # All discovered subdomains
    ├── live_hosts.txt        # Live/responding hosts
    ├── all_urls.txt          # All harvested URLs
    ├── xss_urls.txt          # Potential XSS endpoints
    ├── sqli_urls.txt         # Potential SQLi endpoints
    ├── lfi_urls.txt          # Potential LFI endpoints
    ├── interesting_urls.txt  # Other interesting URLs
    └── gowitness/            # Screenshots (if enabled)
```

## 🔒 Legal Notice

**⚠️ IMPORTANT:** This tool is for authorized security testing and research only. Always ensure you have explicit permission from the target domain owner before running FootSprinter. Unauthorized scanning may be illegal in your jurisdiction.

## 🎨 Author

**Aarham Labs** (Rushil P. Shah)

## 🛠️ Next Steps After Running

1. Import `all_urls.txt` into Burp Suite or your preferred proxy
2. Review `live_hosts.txt` for admin/login panels
3. Validate GF matches to reduce false positives
4. Consider running non-destructive nuclei templates (with consent)

## 📝 License

This project is open source. Use responsibly and ethically.

## 🤝 Contributing

Contributions, issues, and feature requests are welcome!

---

**Disclaimer:** The author is not responsible for misuse or damage caused by this tool. Use at your own risk.

