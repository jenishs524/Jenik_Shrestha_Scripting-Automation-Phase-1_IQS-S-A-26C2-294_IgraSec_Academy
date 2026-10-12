# Advanced Network & Security Scanner (Python)

![Python](https://img.shields.io/badge/Python-3.8+-blue)
![License](https://img.shields.io/badge/License-MIT-yellow)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Mac%20%7C%20Windows-lightgrey)

# 📌 Tool Name
Advanced Network & Security Scanner

# 🎯 Objective
A comprehensive Python-based network reconnaissance and security scanning tool. It performs DNS lookups, port scanning, HTTP header analysis, SSL certificate validation, WHOIS queries, subdomain discovery, and traceroute operations. Designed for security professionals, penetration testers, and system administrators to assess network security posture.

# ✨ Features

| Feature | Description |
|---------|-------------|
| DNS Lookup | Resolve A records, reverse DNS, and multiple IPs |
| Port Scanner | Multi-threaded scanning of common ports |
| HTTP Header Analysis | Check security headers (HSTS, CSP, X-Frame-Options) |
| SSL Certificate Checker | Validate SSL/TLS certificates and cipher suites |
| WHOIS Lookup | Domain registration information |
| Subdomain Finder | Discover common subdomains |
| Traceroute | Network path analysis |
| Full Scan | Run all features at once |

# 📋 Requirements

- Python: 3.8 or higher
- Libraries: requests, dnspython
- System Tools: whois, traceroute

# 🚀 Installation

# 1. Install Python dependencies:
```
pip install requests dnspython
```

# 2. Install system tools (Linux):
```
sudo apt install whois traceroute
```

# 3. Make executable:
```
chmod +x tool.py
```

# 💡 How to Run

```bash
python3 tool.py [OPTION] TARGET
```

# 📤 Example Usage

```bash
# Full scan (all features)
python3 tool.py --all example.com

# DNS lookup only
python3 tool.py --dns example.com

# Port scan
python3 tool.py --ports example.com

# HTTP header analysis
python3 tool.py --headers https://example.com

# SSL certificate check
python3 tool.py --ssl example.com

# WHOIS lookup
python3 tool.py --whois example.com

# Subdomain finder
python3 tool.py --subdomains example.com

# Traceroute
python3 tool.py --traceroute example.com

# Show help
python3 tool.py --help
```

# 📤 Example Output

```
╔══════════════════════════════════════════════════════════════════════════╗
║                                                                          ║
║        ADVANCED NETWORK & SECURITY SCANNER - v2.0                        ║
║                                                                          ║
╚══════════════════════════════════════════════════════════════════════════╝

══════════════════════════════════════════════════════════════════════════
  DNS LOOKUP: example.com
══════════════════════════════════════════════════════════════════════════
    A Record (IPv4)     : 93.184.216.34
    IP Address          : 93.184.216.34
[✓] DNS lookup completed for example.com

══════════════════════════════════════════════════════════════════════════
  PORT SCAN: example.com
══════════════════════════════════════════════════════════════════════════
[*] Scanning 22 ports on example.com...
[✓] Port 80     OPEN  (HTTP)
[✓] Port 443    OPEN  (HTTPS)
[✓] Found 2 open ports in 3.45s
```

# 🧗 Challenges Faced

1. Threading Complexity - Managing concurrent port scans safely
2. Cross-Platform Compatibility - Handling different OS commands
3. Error Handling - Gracefully handling network failures
4. SSL Verification - Dealing with self-signed certificates
5. Performance - Optimizing scan speed with thread pools
6. Parsing WHOIS Output - Different formats across registrars

# 🔮 Future Improvements

- [ ] JSON/CSV export functionality
- [ ] CVE lookup for detected services
- [ ] Banner grabbing for open ports
- [ ] Web technology detection
- [ ] Vulnerability scanning integration
- [ ] Email report generation
- [ ] GUI interface with Tkinter
- [ ] API endpoint discovery
- [ ] Directory brute forcing
- [ ] SQL injection detection

# ⚠️ Disclaimer

This tool is intended for **authorized security testing only**. Use it only on systems you own or have explicit permission to test. Unauthorized scanning is illegal and unethical.

# 👤 Author

Jenik Shrestha
- Intern at IgraSec Academy
- Phase 1 Submission - S&A


## 🙏 Acknowledgments

- IgraSec Academy for the opportunity
- Python community for excellent libraries

---