# FootSprinter v2.0 - Quick Start Guide

## 🚀 Getting Started

### First Time Setup

```bash
# 1. Clone from GitHub
git clone https://github.com/i-m-rushil/footsprinter.git
cd footsprinter

# 2. Make executable
chmod +x footsprinter.sh

# 3. Run your first scan
sudo ./footsprinter.sh --url example.com
```

The script will automatically install all dependencies on the first run.

## 📖 Usage Examples

### Example 1: Basic Scan
Perfect for quick reconnaissance of a target.

```bash
sudo ./footsprinter.sh --url example.com
```

**What it does:**
- Company intelligence gathering
- Subdomain enumeration
- Live host detection
- Top 1000 port scan
- Technology detection
- Critical/High vulnerability scanning
- Generates HTML report

**Time:** ~5-10 minutes

---

### Example 2: Full Comprehensive Scan
Deep dive security assessment with all features enabled.

```bash
sudo ./footsprinter.sh --url target.com --fullscan
```

**What it does:**
- Everything from basic scan PLUS:
- Full 65535 port scan
- UDP port scanning
- All severity vulnerabilities (critical/high/medium/low)
- Nikto web server scan
- Katana web crawler
- Extensive Nuclei template scanning

**Time:** ~30-60 minutes (depending on target size)

---

### Example 3: Stealth Mode
Slower scanning with randomized headers to avoid detection.

```bash
sudo ./footsprinter.sh --url target.com --interval 3 --changeheaders
```

**What it does:**
- Adds 3-second delay between requests
- Randomizes User-Agent headers
- Harder to detect in logs
- Reduces load on target server

**Use when:**
- Target has rate limiting
- Want to avoid triggering IDS/IPS
- Need to be discrete
- Testing detection capabilities

---

### Example 4: Maximum Stealth
Ultimate stealth configuration for sensitive assessments.

```bash
sudo ./footsprinter.sh --url target.com --interval 5 --changeheaders
```

**Time:** Much slower but stealthier

---

### Example 5: Full Scan with Stealth
Comprehensive assessment with stealth features.

```bash
sudo ./footsprinter.sh --url target.com --fullscan --interval 2 --changeheaders
```

**Best for:**
- Professional penetration tests
- Authorized security assessments
- Comprehensive audits

---

## 🎯 Parameter Reference

### Required Parameter

**`--url <domain>`**
- The target domain or URL
- Examples: `example.com`, `https://example.com`, `subdomain.example.com`
- The script automatically strips protocol and trailing slashes

### Optional Parameters

**`--fullscan`**
- Enables comprehensive deep scanning
- Includes: Full port scan (all 65535 ports), UDP scanning, Nikto, all vulnerability severities
- Significantly increases scan time
- Recommended for thorough assessments

**`--interval <seconds>`**
- Delay between requests in seconds
- Default: 1 second
- Recommended values:
  - Normal: 1 (default)
  - Stealth: 3-5
  - Maximum stealth: 5+
- Higher values = slower but stealthier

**`--changeheaders`**
- Randomizes User-Agent headers
- Rotates between 5 different browser agents
- Helps avoid simple detection mechanisms
- Recommended for professional assessments

**`-h` or `--help`**
- Shows help message and usage examples
- Lists all available options

---

## 📊 Understanding the Output

### Output Directory Structure

After running a scan, you'll get a directory named:
```
FootSprinter_<target>_<date>_<time>/
```

### Key Files to Check

1. **`FootSprinter_Report_<target>_<timestamp>.html`**
   - Main comprehensive HTML report
   - Open in any web browser
   - Contains all findings with professional formatting
   - Share this with stakeholders

2. **`SUMMARY.txt`**
   - Quick text summary
   - Statistics overview
   - Risk level at a glance

3. **`final/vulnerabilities.txt`**
   - All discovered vulnerabilities
   - Quick reference for findings

4. **`final/risk_assessment.txt`**
   - Detailed risk analysis
   - Business impact assessment
   - Remediation priorities

### How to Read the HTML Report

The HTML report contains 9 main sections:

1. **Executive Summary** - Overview and key metrics
2. **Company Intelligence** - WHOIS, DNS, IP information
3. **Domain Analysis** - Subdomains and live hosts
4. **Port Scan Results** - Open ports and services
5. **Technology Stack** - Detected technologies and versions
6. **Vulnerability Assessment** - Security issues found
7. **Exploitation Analysis** - How vulnerabilities can be exploited
8. **Risk Assessment** - Business impact and severity
9. **Recommendations** - Remediation steps and conclusions

---

## 🛡️ Best Practices

### Before Scanning

1. **Get Authorization**
   - Written permission is mandatory
   - Define scope clearly
   - Understand legal boundaries

2. **Prepare Your Environment**
   - Use Kali Linux or Debian-based system
   - Ensure stable internet connection
   - Have sufficient disk space (~2GB)

3. **Choose Right Parameters**
   - Quick check? Use basic scan
   - Full assessment? Use --fullscan
   - Need stealth? Add --interval and --changeheaders

### During Scanning

1. **Monitor Progress**
   - Watch terminal output for errors
   - Check if tools are running correctly
   - Note any timeouts or failures

2. **Resource Awareness**
   - Full scans are intensive
   - May take significant time
   - Don't interrupt the process

### After Scanning

1. **Review Findings**
   - Start with HTML report
   - Check vulnerability section carefully
   - Verify false positives

2. **Prioritize Issues**
   - Focus on Critical and High first
   - Consider business impact
   - Plan remediation timeline

3. **Secure the Report**
   - Contains sensitive information
   - Don't share publicly
   - Encrypt if sending via email

---

## 🔧 Troubleshooting

### Problem: "Command not found"
**Solution:** Run with sudo and let script install dependencies
```bash
sudo ./footsprinter.sh --url target.com
```

### Problem: "Permission denied"
**Solution:** Make the script executable
```bash
chmod +x footsprinter.sh
```

### Problem: Tool installation fails
**Solution:** Manually update package lists
```bash
sudo apt update
sudo apt upgrade
```

### Problem: "Cannot resolve domain"
**Solution:** 
- Check domain spelling
- Verify domain exists
- Check your internet connection
- Try with different domain

### Problem: Scan is very slow
**Solution:**
- Remove --fullscan for quicker results
- Reduce --interval value
- Check internet connection speed
- Some targets are naturally slow to respond

### Problem: "Target IP not found"
**Solution:**
- Domain might not have A record
- Try with different subdomain
- Check if domain is active

### Problem: No vulnerabilities found
**Solution:**
- This could be good news! Target might be secure
- Try --fullscan for more thorough check
- Some vulnerabilities require manual testing
- Update Nuclei templates: `nuclei -update-templates`

---

## 📝 Common Scenarios

### Scenario 1: Bug Bounty Hunting
```bash
# Start with quick scan
sudo ./footsprinter.sh --url target.com

# If interesting findings, do full scan
sudo ./footsprinter.sh --url target.com --fullscan --interval 2
```

### Scenario 2: Client Penetration Test
```bash
# Comprehensive assessment with stealth
sudo ./footsprinter.sh --url client-domain.com --fullscan --interval 2 --changeheaders
```

### Scenario 3: Your Own Infrastructure Audit
```bash
# Fast and comprehensive
sudo ./footsprinter.sh --url mycompany.com --fullscan
```

### Scenario 4: Red Team Operation
```bash
# Maximum stealth
sudo ./footsprinter.sh --url target.com --interval 5 --changeheaders
```

---

## 💡 Pro Tips

1. **Run during off-hours** - Less likely to be noticed, less impact on target
2. **Save reports systematically** - Use date-based naming for tracking
3. **Compare scans over time** - Track security improvements
4. **Read the exploitation analysis** - Understand impact, not just vulnerabilities
5. **Don't rely solely on automation** - Manual testing catches what scanners miss
6. **Update regularly** - Keep FootSprinter and Nuclei templates updated
7. **Document everything** - Keep notes of your methodology and findings
8. **Respect rate limits** - Use --interval to avoid overwhelming targets
9. **Verify findings** - Check for false positives before reporting
10. **Learn continuously** - Research vulnerabilities you don't understand

---

## 🎓 Next Steps After Your First Scan

1. Open the HTML report in your browser
2. Review the Executive Summary
3. Check the vulnerability count
4. Read through each critical/high finding
5. Review the remediation recommendations
6. Understand the risk assessment
7. If needed, perform manual verification
8. Create your action plan
9. Start with highest priority issues
10. Re-scan after fixes to verify

---

## 📞 Need Help?

- Check README.md for detailed documentation
- Review this guide for common scenarios
- Open GitHub issue for bugs
- Review tool-specific documentation for advanced features

---

## ⚠️ Final Reminder

**Only scan systems you own or have explicit permission to test.**

Unauthorized scanning is illegal and unethical. Use FootSprinter responsibly.

---

**Happy Ethical Hacking! 🎯**

