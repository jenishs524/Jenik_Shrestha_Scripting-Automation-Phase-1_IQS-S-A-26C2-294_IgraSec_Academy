#!/bin/bash

################################################################################
#                                                                              #
#   ADVANCED LINUX SECURITY AUDITOR                                            #
#   Version: 1.0                                                               #
#   Author: [Your Name]                                                        #
#   Description: A comprehensive Linux security auditing tool that checks      #
#                system configurations, user accounts, file permissions,       #
#                network settings, and potential security issues.              #
#                                                                              #
################################################################################

# ==============================
# COLOR DEFINITIONS
# ==============================
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m' # No Color

# ==============================
# GLOBAL VARIABLES
# ==============================
SCRIPT_NAME=$(basename "$0")
VERSION="1.0"
REPORT_DIR="./reports"
TIMESTAMP=$(date +"%Y-%m-%d_%H-%M-%S")
REPORT_FILE="${REPORT_DIR}/security_audit_${TIMESTAMP}.txt"

# ==============================
# BANNER
# ==============================
show_banner() {
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════════════════════════════╗"
    echo "║                                                                  ║"
    echo "║        ADVANCED LINUX SECURITY AUDITOR - v${VERSION}                    ║"
    echo "║                                                                  ║"
    echo "║        A comprehensive security auditing tool for Linux          ║"
    echo "║                                                                  ║"
    echo "╚══════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# ==============================
# HELP MENU
# ==============================
show_help() {
    show_banner
    echo -e "${WHITE}USAGE:${NC}"
    echo "  ./${SCRIPT_NAME} [OPTIONS]"
    echo ""
    echo -e "${WHITE}OPTIONS:${NC}"
    echo -e "  ${GREEN}-a, --all${NC}           Run full security audit"
    echo -e "  ${GREEN}-s, --system${NC}        System information audit"
    echo -e "  ${GREEN}-u, --users${NC}         User account security audit"
    echo -e "  ${GREEN}-p, --permissions${NC}   File permission audit"
    echo -e "  ${GREEN}-n, --network${NC}       Network security audit"
    echo -e "  ${GREEN}-f, --firewall${NC}      Firewall status check"
    echo -e "  ${GREEN}-l, --logs${NC}          Log file analysis"
    echo -e "  ${GREEN}-r, --report${NC}        Generate full report file"
    echo -e "  ${GREEN}-v, --version${NC}       Show version"
    echo -e "  ${GREEN}-h, --help${NC}          Show this help menu"
    echo ""
    echo -e "${WHITE}EXAMPLES:${NC}"
    echo "  ./${SCRIPT_NAME} --all"
    echo "  ./${SCRIPT_NAME} --users"
    echo "  ./${SCRIPT_NAME} --report"
    echo ""
    echo -e "${WHITE}DESCRIPTION:${NC}"
    echo "  This tool performs security audits on Linux systems,"
    echo "  checking for common misconfigurations and vulnerabilities."
    echo ""
    echo -e "${YELLOW}⚠  WARNING: Use only on systems you own or have permission to test.${NC}"
    echo ""
}

# ==============================
# LOGGING FUNCTION
# ==============================
log_output() {
    if [ "$GENERATE_REPORT" = true ]; then
        echo "$1" >> "$REPORT_FILE"
    fi
}

# ==============================
# SECTION HEADER
# ==============================
section_header() {
    local title="$1"
    echo ""
    echo -e "${PURPLE}════════════════════════════════════════════════════════════${NC}"
    echo -e "${PURPLE}  $title${NC}"
    echo -e "${PURPLE}════════════════════════════════════════════════════════════${NC}"
    log_output ""
    log_output "================================================================"
    log_output "  $title"
    log_output "================================================================"
}

# ==============================
# SYSTEM INFORMATION AUDIT
# ==============================
audit_system() {
    section_header "SYSTEM INFORMATION"
    
    local hostname=$(hostname)
    local os=$(grep PRETTY_NAME /etc/os-release 2>/dev/null | cut -d'"' -f2)
    local kernel=$(uname -r)
    local arch=$(uname -m)
    local uptime=$(uptime -p)
    
    echo -e "${GREEN}Hostname:${NC}     $hostname"
    echo -e "${GREEN}OS:${NC}           $os"
    echo -e "${GREEN}Kernel:${NC}       $kernel"
    echo -e "${GREEN}Architecture:${NC} $arch"
    echo -e "${GREEN}Uptime:${NC}       $uptime"
    
    log_output "Hostname: $hostname"
    log_output "OS: $os"
    log_output "Kernel: $kernel"
    log_output "Architecture: $arch"
    log_output "Uptime: $uptime"
    
    # Check if system needs reboot
    if [ -f /var/run/reboot-required ]; then
        echo -e "${RED}[!] System requires reboot (security updates pending)${NC}"
        log_output "[!] System requires reboot"
    else
        echo -e "${GREEN}[✓] No reboot required${NC}"
        log_output "[✓] No reboot required"
    fi
}

# ==============================
# USER ACCOUNT AUDIT
# ==============================
audit_users() {
    section_header "USER ACCOUNT SECURITY"
    
    # Check for UID 0 accounts (root equivalent)
    echo -e "${WHITE}[*] Checking for UID 0 accounts...${NC}"
    local root_users=$(awk -F: '($3 == 0) {print $1}' /etc/passwd)
    echo "    UID 0 accounts: $root_users"
    log_output "UID 0 accounts: $root_users"
    
    if [ "$(echo "$root_users" | wc -l)" -gt 1 ]; then
        echo -e "${RED}    [!] WARNING: Multiple UID 0 accounts found!${NC}"
        log_output "[!] WARNING: Multiple UID 0 accounts found!"
    else
        echo -e "${GREEN}    [✓] Only root has UID 0${NC}"
        log_output "[✓] Only root has UID 0"
    fi
    
    # Check for users with empty passwords
    echo ""
    echo -e "${WHITE}[*] Checking for accounts without passwords...${NC}"
    local empty_pass=$(awk -F: '($2 == "") {print $1}' /etc/shadow 2>/dev/null)
    if [ -z "$empty_pass" ]; then
        echo -e "${GREEN}    [✓] No accounts with empty passwords${NC}"
        log_output "[✓] No accounts with empty passwords"
    else
        echo -e "${RED}    [!] Accounts with empty passwords: $empty_pass${NC}"
        log_output "[!] Accounts with empty passwords: $empty_pass"
    fi
    
    # Check for users with login shells
    echo ""
    echo -e "${WHITE}[*] Users with login shells:${NC}"
    local login_users=$(grep -v "/nologin\|/false" /etc/passwd | cut -d: -f1)
    echo "$login_users" | while read user; do
        echo "    - $user"
        log_output "    - $user"
    done
    
    # Currently logged in users
    echo ""
    echo -e "${WHITE}[*] Currently logged-in users:${NC}"
    who | while read line; do
        echo "    $line"
        log_output "    $line"
    done
}

# ==============================
# FILE PERMISSION AUDIT
# ==============================
audit_permissions() {
    section_header "FILE PERMISSION AUDIT"
    
    # Check critical files
    local critical_files=(
        "/etc/passwd:644"
        "/etc/shadow:640"
        "/etc/group:644"
        "/etc/gshadow:640"
        "/etc/ssh/sshd_config:600"
        "/boot/grub/grub.cfg:600"
    )
    
    echo -e "${WHITE}[*] Checking critical file permissions...${NC}"
    echo ""
    
    for entry in "${critical_files[@]}"; do
        local file="${entry%%:*}"
        local expected="${entry##*:}"
        
        if [ -f "$file" ]; then
            local actual=$(stat -c "%a" "$file" 2>/dev/null)
            if [ "$actual" = "$expected" ]; then
                echo -e "${GREEN}    [✓] $file ($actual)${NC}"
                log_output "[✓] $file ($actual)"
            else
                echo -e "${YELLOW}    [!] $file (actual: $actual, expected: $expected)${NC}"
                log_output "[!] $file (actual: $actual, expected: $expected)"
            fi
        else
            echo -e "${YELLOW}    [?] $file not found${NC}"
            log_output "[?] $file not found"
        fi
    done
    
    # Check for world-writable files in /etc
    echo ""
    echo -e "${WHITE}[*] World-writable files in /etc:${NC}"
    local ww_files=$(find /etc -type f -perm -o+w 2>/dev/null | head -5)
    if [ -z "$ww_files" ]; then
        echo -e "${GREEN}    [✓] None found${NC}"
        log_output "[✓] No world-writable files in /etc"
    else
        echo -e "${RED}    [!] Found:${NC}"
        echo "$ww_files" | while read f; do
            echo "        - $f"
            log_output "    - $f"
        done
    fi
}

# ==============================
# NETWORK SECURITY AUDIT
# ==============================
audit_network() {
    section_header "NETWORK SECURITY"
    
    # IP and Gateway
    echo -e "${GREEN}IP Address:${NC}     $(hostname -I 2>/dev/null || echo 'N/A')"
    echo -e "${GREEN}Gateway:${NC}        $(ip route 2>/dev/null | grep default | awk '{print $3}' || echo 'N/A')"
    echo -e "${GREEN}DNS Servers:${NC}    $(grep nameserver /etc/resolv.conf 2>/dev/null | awk '{print $2}' | tr '\n' ' ')"
    
    log_output "IP Address: $(hostname -I 2>/dev/null)"
    log_output "Gateway: $(ip route 2>/dev/null | grep default | awk '{print $3}')"
    log_output "DNS: $(grep nameserver /etc/resolv.conf 2>/dev/null | awk '{print $2}' | tr '\n' ' ')"
    
    # Listening ports
    echo ""
    echo -e "${WHITE}[*] Listening ports:${NC}"
    if command -v ss &> /dev/null; then
        ss -tuln 2>/dev/null | tail -n +2 | while read line; do
            echo "    $line"
            log_output "    $line"
        done
    else
        echo -e "${YELLOW}    [!] ss command not available${NC}"
        log_output "[!] ss command not available"
    fi
    
    # Check for dangerous open ports
    echo ""
    echo -e "${WHITE}[*] Checking for risky open ports...${NC}"
    local risky_ports=(23 21 3389 5900 111)
    for port in "${risky_ports[@]}"; do
        if ss -tuln 2>/dev/null | grep -q ":$port "; then
            echo -e "${RED}    [!] Port $port is open (risky)${NC}"
            log_output "[!] Port $port is open"
        fi
    done
}

# ==============================
# FIREWALL AUDIT
# ==============================
audit_firewall() {
    section_header "FIREWALL STATUS"
    
    # Check UFW
    if command -v ufw &> /dev/null; then
        local ufw_status=$(ufw status 2>/dev/null | head -1)
        if echo "$ufw_status" | grep -q "active"; then
            echo -e "${GREEN}[✓] UFW is active${NC}"
            log_output "[✓] UFW is active"
        else
            echo -e "${RED}[!] UFW is inactive${NC}"
            log_output "[!] UFW is inactive"
        fi
    else
        echo -e "${YELLOW}[?] UFW not installed${NC}"
        log_output "[?] UFW not installed"
    fi
    
    # Check iptables
    if command -v iptables &> /dev/null; then
        local iptables_rules=$(iptables -L 2>/dev/null | wc -l)
        if [ "$iptables_rules" -gt 8 ]; then
            echo -e "${GREEN}[✓] iptables has rules configured${NC}"
            log_output "[✓] iptables has rules"
        else
            echo -e "${YELLOW}[!] iptables has minimal rules${NC}"
            log_output "[!] iptables minimal rules"
        fi
    fi
    
    # Check firewalld
    if command -v firewall-cmd &> /dev/null; then
        if firewall-cmd --state 2>/dev/null | grep -q "running"; then
            echo -e "${GREEN}[✓] firewalld is running${NC}"
            log_output "[✓] firewalld is running"
        else
            echo -e "${RED}[!] firewalld is not running${NC}"
            log_output "[!] firewalld is not running"
        fi
    fi
}

# ==============================
# LOG ANALYSIS
# ==============================
audit_logs() {
    section_header "LOG FILE ANALYSIS"
    
    # Failed login attempts
    echo -e "${WHITE}[*] Recent failed login attempts:${NC}"
    local failed=$(grep "Failed password" /var/log/auth.log 2>/dev/null | tail -5)
    if [ -z "$failed" ]; then
        failed=$(grep "Failed password" /var/log/secure 2>/dev/null | tail -5)
    fi
    
    if [ -z "$failed" ]; then
        echo -e "${GREEN}    [✓] No failed login attempts found${NC}"
        log_output "[✓] No failed logins"
    else
        echo -e "${YELLOW}    Found failed attempts:${NC}"
        echo "$failed" | while read line; do
            echo "    $line"
            log_output "    $line"
        done
    fi
    
    # Recent sudo commands
    echo ""
    echo -e "${WHITE}[*] Recent sudo commands:${NC}"
    local sudo_cmds=$(grep "sudo:" /var/log/auth.log 2>/dev/null | tail -5)
    if [ -z "$sudo_cmds" ]; then
        echo -e "${YELLOW}    [?] No sudo logs found${NC}"
        log_output "[?] No sudo logs"
    else
        echo "$sudo_cmds" | while read line; do
            echo "    $line"
            log_output "    $line"
        done
    fi
}

# ==============================
# FULL AUDIT
# ==============================
audit_all() {
    show_banner
    echo -e "${YELLOW}[*] Starting full security audit...${NC}"
    echo -e "${YELLOW}[*] Time: $(date)${NC}"
    
    audit_system
    audit_users
    audit_permissions
    audit_network
    audit_firewall
    audit_logs
    
    section_header "AUDIT COMPLETE"
    echo -e "${GREEN}[✓] Full security audit finished${NC}"
    echo -e "${GREEN}[✓] Time: $(date)${NC}"
    
    if [ "$GENERATE_REPORT" = true ]; then
        echo ""
        echo -e "${GREEN}[✓] Report saved: $REPORT_FILE${NC}"
    fi
}

# ==============================
# MAIN FUNCTION
# ==============================
main() {
    # Check if no arguments
    if [ $# -eq 0 ]; then
        show_help
        exit 1
    fi
    
    # Parse arguments
    while [ $# -gt 0 ]; do
        case "$1" in
            -a|--all)
                audit_all
                shift
                ;;
            -s|--system)
                audit_system
                shift
                ;;
            -u|--users)
                audit_users
                shift
                ;;
            -p|--permissions)
                audit_permissions
                shift
                ;;
            -n|--network)
                audit_network
                shift
                ;;
            -f|--firewall)
                audit_firewall
                shift
                ;;
            -l|--logs)
                audit_logs
                shift
                ;;
            -r|--report)
                GENERATE_REPORT=true
                mkdir -p "$REPORT_DIR"
                audit_all
                shift
                ;;
            -v|--version)
                echo "Advanced Linux Security Auditor v${VERSION}"
                exit 0
                ;;
            -h|--help)
                show_help
                exit 0
                ;;
            *)
                echo -e "${RED}[!] Error: Unknown option '$1'${NC}"
                echo "Use --help for usage information"
                exit 1
                ;;
        esac
    done
}

# Run main
main "$@"