# Advanced Linux Security Auditor (Bash)

![Bash](https://img.shields.io/badge/Bash-5.0+-green)
![Linux](https://img.shields.io/badge/Linux-Ubuntu%20%7C%20Debian%20%7C%20Kali-blue)
![License](https://img.shields.io/badge/License-MIT-yellow)

# 📌 Tool Name
**Advanced Linux Security Auditor**

# 🎯 Objective
A comprehensive Bash-based security auditing tool that performs automated security checks on Linux systems. It identifies common misconfigurations, weak permissions, vulnerable accounts, and potential security risks. Designed for system administrators, security analysts, and penetration testers to quickly assess system security posture.

# ✨ Features

- System Information Audit - OS details, kernel version, reboot status
- User Account Security - UID 0 accounts, empty passwords, login shells
- File Permission Audit - Critical file permissions, world-writable files
- Network Security Audit - Open ports, risky services, DNS configuration
- Firewall Status Check - UFW, iptables, firewalld detection
- Log Analysis - Failed logins, sudo command history
- Report Generation - Saves audit results to file
- Color-Coded Output - Easy to read results
- Comprehensive Help Menu - Clear usage instructions

# 📋 Requirements

- **OS:** Linux (Ubuntu, Debian, Kali, CentOS, etc.)
- **Shell:** Bash 4.0 or higher
- **Privileges:** Root/sudo recommended for full audit
- **Utilities:** Standard Linux tools (stat, awk, grep, ss, find)

# 🚀 How to Run

# 1. Make the script executable:
```bash
chmod +x tool.sh
```

# 2. Run the tool:
```bash
./tool.sh [OPTION]
```

## 💡 Example Usage

```bash
# Run full security audit
./tool.sh --all

# Audit user accounts only
./tool.sh --users

# Check firewall status
./tool.sh --firewall

# Audit file permissions
./tool.sh --permissions

# Network security audit
./tool.sh --network

# Generate full report to file
./tool.sh --report

# Show help menu
./tool.sh --help

# Show version
./tool.sh --version
```

# 📤 Example Output

```
╔══════════════════════════════════════════════════════════════════╗
║                                                                  ║
║        ADVANCED LINUX SECURITY AUDITOR - v1.0                    ║
║                                                                  ║
║        A comprehensive security auditing tool for Linux          ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝

════════════════════════════════════════════════════════════
  SYSTEM INFORMATION
════════════════════════════════════════════════════════════
Hostname:     kali
OS:           Kali GNU/Linux Rolling
Kernel:       6.1.0-kali5-amd64
Architecture: x86_64
Uptime:       up 2 hours, 15 minutes
[✓] No reboot required

════════════════════════════════════════════════════════════
  USER ACCOUNT SECURITY
════════════════════════════════════════════════════════════
[*] Checking for UID 0 accounts...
    UID 0 accounts: root
    [✓] Only root has UID 0
```

# 🧗 Challenges Faced

1. **Cross-Distribution Compatibility** - Different Linux distros have different commands and file paths
2. **Permission Handling** - Some checks require root privileges
3. **Log File Locations** - Auth logs vary between distros (`/var/log/auth.log` vs `/var/log/secure`)
4. **Parsing Command Output** - Handling different output formats consistently
5. **Error Handling** - Gracefully handling missing commands and files

# 🔮 Future Improvements

- [ ] Add JSON output format for automation
- [ ] Add CSV report generation
- [ ] Include CVE checking against installed packages
- [ ] Add SSH configuration audit
- [ ] Add password policy checking
- [ ] Add SUID/SGID file scanning
- [ ] Add cron job auditing
- [ ] Email report functionality
- [ ] Integration with vulnerability databases
- [ ] Multi-language support

# ⚠️ Disclaimer

This tool is intended for **authorized security testing only**. Use it only on systems you own or have explicit permission to test. Unauthorized use is illegal and unethical.

# 👤 Author

Jennik Shrestha
- Intern at IgraSec Academy
- Phase 1 Submission - S&A

## 🙏 Acknowledgments

- IgraSec Academy for the opportunity
- Open-source community for inspiration

---