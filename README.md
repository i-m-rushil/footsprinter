# FootSprinter v2.0 🔍

<p align="center">
  <img src="https://img.shields.io/badge/Version-2.0-blue.svg" alt="Version 2.0">
  <img src="https://img.shields.io/badge/Platform-Kali%20Linux-purple.svg" alt="Platform">
  <img src="https://img.shields.io/badge/License-MIT-green.svg" alt="License">
  <img src="https://img.shields.io/badge/Maintained-Yes-success.svg" alt="Maintained">
</p>

**FootSprinter v2.0** is the most comprehensive OSINT (Open Source Intelligence) footprinting and vulnerability assessment framework designed for security professionals. It combines multiple reconnaissance techniques with automated vulnerability scanning to provide a complete security posture analysis.

## 🚀 Key Features

### 1. **Company Intelligence Gathering**
- WHOIS information extraction
- DNS record enumeration (A, MX, TXT, NS, SOA)
- Certificate transparency analysis
- IP geolocation and hosting information
- Organization details and registration data

### 2. **Advanced Domain Enumeration**
- Multi-tool subdomain discovery (Subfinder, Assetfinder, Amass)
- Certificate transparency mining
- Live host detection with httpx
- Weak domain identification
- Test/staging/development environment discovery

### 3. **Comprehensive Port Scanning**
- Full TCP port scanning with service detection
- UDP scanning for common services
- Banner grabbing and version identification
- XML export for integration with other tools

### 4. **Technology Stack Detection**
- Web technology fingerprinting
- Version identification for frameworks and servers
- HTTP security headers analysis
- SSL/TLS configuration assessment
- CMS and plugin detection

### 5. **Vulnerability Assessment**
- Nuclei template-based scanning (3000+ templates)
- Nikto web server vulnerability detection
- Common misconfiguration checks
- Exposed sensitive files detection
- Security best practices validation

### 6. **Exploitation Analysis**
- Detailed exploitation vectors for each vulnerability
- Proof-of-concept examples
- Attack scenario descriptions
- Severity classification

### 7. **Remediation Recommendations**
- Step-by-step patching guides
- Security best practices
- Configuration hardening tips
- Framework-specific fixes

### 8. **Risk Assessment & Scoring**
- Automated risk scoring (0-100 scale)
- Business impact analysis
- CVSS-aligned severity ratings
- Compliance considerations (GDPR, PCI DSS, HIPAA, SOC 2)

### 9. **Professional Reporting**
- Beautiful HTML report with interactive elements
- Executive summary with statistics
- Detailed findings with evidence
- Prioritized remediation roadmap
- Easy to share with stakeholders

## 📋 Requirements

- **Operating System**: Kali Linux, Debian, or Ubuntu
- **Privileges**: Root/sudo access required
- **Internet Connection**: Required for tool installation and scanning
- **Disk Space**: ~2GB for tools and dependencies

## 🛠️ Installation

FootSprinter automatically installs all dependencies on first run, but you can also install manually:

```bash
# Clone the repository
git clone https://github.com/i-m-rushil/footsprinter.git
cd footsprinter

# Make executable
chmod +x footsprinter.sh

# Run (will auto-install dependencies)
sudo ./footsprinter.sh --url target.com
```

### Manual Dependency Installation

```bash
# APT packages
sudo apt update
sudo apt install -y nmap whois curl wget git jq python3 python3-pip \
                    dnsutils openssl amass gobuster nikto whatweb

# Go-based tools (installed automatically by script)
# - subfinder, httpx, nuclei, naabu, assetfinder, httprobe
# - waybackurls, gau, anew, katana
```

## 📖 Usage

### Basic Usage

```bash
# Simple scan
sudo ./footsprinter.sh --url example.com

# Full comprehensive scan
sudo ./footsprinter.sh --url example.com --fullscan

# Stealth scan with delays
sudo ./footsprinter.sh --url target.com --interval 3 --changeheaders

# All options combined
sudo ./footsprinter.sh --url target.com --fullscan --interval 2 --changeheaders
```

### Command-Line Parameters

| Parameter | Description | Default |
|-----------|-------------|---------|
| `--url <domain>` | Target domain or URL (REQUIRED) | - |
| `--fullscan` | Enable deep comprehensive scanning | false |
| `--interval <seconds>` | Delay between requests (stealth mode) | 1 |
| `--changeheaders` | Randomize User-Agent headers | false |
| `-h, --help` | Show usage information | - |

### Examples

**Basic reconnaissance:**
```bash
sudo ./footsprinter.sh --url example.com
```

**Full security assessment:**
```bash
sudo ./footsprinter.sh --url target.com --fullscan
```

**Stealth mode (slower, harder to detect):**
```bash
sudo ./footsprinter.sh --url target.com --interval 5 --changeheaders
```

## 📂 Output Structure

```
FootSprinter_example.com_2025-10-25_120000/
├── raw/                                    # Raw tool outputs
│   ├── whois.txt                          # WHOIS data
│   ├── dns_records.txt                    # DNS information
│   ├── crt_sh.json                        # Certificate transparency
│   ├── subfinder.txt                      # Subfinder results
│   ├── assetfinder.txt                    # Assetfinder results
│   ├── amass.txt                          # Amass results
│   ├── nmap_scan.txt                      # Nmap output
│   ├── whatweb.txt                        # Technology detection
│   ├── nuclei_results.txt                 # Vulnerability findings
│   ├── nikto_results.txt                  # Nikto scan results
│   ├── wayback_urls.txt                   # Historical URLs
│   └── ...
├── final/                                 # Processed results
│   ├── company_info.txt                   # Company intelligence
│   ├── all_subdomains.txt                 # All discovered subdomains
│   ├── live_hosts.txt                     # Live responding hosts
│   ├── weak_domains.txt                   # Potentially weak domains
│   ├── open_ports.txt                     # Open ports summary
│   ├── technology_stack.txt               # Tech stack summary
│   ├── vulnerabilities.txt                # Vulnerability summary
│   ├── exploitation_analysis.txt          # Exploitation guide
│   ├── risk_assessment.txt                # Risk analysis
│   └── ...
├── FootSprinter_Report_example.com_[timestamp].html  # Main HTML report
└── SUMMARY.txt                            # Quick text summary
```

## 🎯 What Makes FootSprinter Unique?

### 1. **All-in-One Solution**
Unlike other tools that focus on a single aspect, FootSprinter provides complete coverage from reconnaissance to risk assessment.

### 2. **Professional Reporting**
Generate presentation-ready HTML reports that can be shared directly with management and stakeholders.

### 3. **Automated Dependency Management**
No more manual tool installation. FootSprinter installs and configures everything automatically.

### 4. **Intelligent Analysis**
Beyond just finding vulnerabilities, FootSprinter provides exploitation analysis, remediation guides, and business impact assessment.

### 5. **Compliance Focused**
Risk assessments include compliance considerations for GDPR, PCI DSS, HIPAA, and other frameworks.

### 6. **Continuous Updates**
Nuclei templates are automatically updated, ensuring you have the latest vulnerability checks.

## 🔒 Legal Notice & Ethics

**⚠️ CRITICAL WARNING:**

This tool is designed for **authorized security testing only**. You must have **explicit written permission** from the target organization before running FootSprinter.

**Illegal use includes:**
- Scanning systems you don't own or control
- Testing without proper authorization
- Using findings for malicious purposes
- Accessing systems without permission

**Legal consequences:**
- Criminal charges under Computer Fraud and Abuse Act (CFAA)
- Civil liability and lawsuits
- Professional license revocation
- Imprisonment and fines

**Use FootSprinter responsibly:**
- ✅ Your own systems and infrastructure
- ✅ Client systems with signed agreements
- ✅ Bug bounty programs with defined scope
- ✅ Authorized penetration testing engagements

## 📊 Sample Report

The generated HTML report includes:

- 📈 Executive dashboard with key metrics
- 🏢 Company and infrastructure intelligence
- 🌐 Complete domain/subdomain mapping
- 🔌 Port scan results with service identification
- ⚙️ Technology stack with version information
- 🛡️ Vulnerability findings with severity ratings
- 💥 Exploitation vectors and attack scenarios
- 🔧 Detailed remediation recommendations
- 📉 Risk scoring and business impact analysis
- ✅ Compliance considerations

## 🎨 Banner Design

FootSprinter v2.0 features a professional ASCII art banner similar to Metasploit, providing a distinctive and recognizable interface.

## 🔧 Tools Integrated

FootSprinter leverages the following industry-standard tools:

**Subdomain Enumeration:**
- Subfinder (ProjectDiscovery)
- Assetfinder (Tomnomnom)
- Amass (OWASP)

**HTTP Analysis:**
- httpx (ProjectDiscovery)
- httprobe (Tomnomnom)
- WhatWeb

**Vulnerability Scanning:**
- Nuclei (ProjectDiscovery) - 3000+ templates
- Nikto
- Nmap with NSE scripts

**URL Discovery:**
- Waybackurls (Tomnomnom)
- GAU (lc)
- Katana (ProjectDiscovery)

**Infrastructure:**
- Nmap - Network scanning
- WHOIS - Registration data
- OpenSSL - Certificate analysis

## 🤝 Contributing

Contributions are welcome! Here's how you can help:

1. **Report Bugs**: Open an issue with detailed reproduction steps
2. **Suggest Features**: Share your ideas for improvements
3. **Submit PRs**: Fork, create a feature branch, and submit a pull request
4. **Improve Documentation**: Help make the docs clearer
5. **Share Feedback**: Let us know how you're using FootSprinter

## 📝 Changelog

### Version 2.0 (Current)
- ✨ Complete rewrite with modular architecture
- ✨ Added command-line argument parsing
- ✨ Comprehensive HTML report generation
- ✨ Risk assessment and scoring system
- ✨ Exploitation analysis module
- ✨ Automated dependency installation
- ✨ Professional Metasploit-style banner
- ✨ Business impact analysis
- ✨ Compliance considerations

### Version 1.0
- Initial release with basic footprinting features

## 🎓 Learning Resources

To get the most out of FootSprinter, consider learning:

- **OSINT Techniques**: Open-source intelligence gathering
- **Network Security**: Port scanning and service enumeration
- **Web Application Security**: OWASP Top 10, vulnerability classes
- **Penetration Testing**: Ethical hacking methodology
- **Security Reporting**: Communicating findings effectively

## 📞 Support & Contact

- **Issues**: [GitHub Issues](https://github.com/i-m-rushil/footsprinter/issues)
- **Author**: Aarham Labs (Rushil P. Shah)
- **Updates**: Watch the repository for updates

## 📄 License

This project is open source and available under the MIT License.

## ⚠️ Disclaimer

The author and contributors are not responsible for misuse or damage caused by this tool. Use FootSprinter responsibly and ethically. This tool is provided "as is" without warranty of any kind.

**Remember**: With great power comes great responsibility. Use your skills to make the internet more secure, not less.

---

<p align="center">
  <strong>Made with ❤️ by security professionals, for security professionals</strong>
</p>

<p align="center">
  ⭐ Star this repository if you find it useful!
</p>
