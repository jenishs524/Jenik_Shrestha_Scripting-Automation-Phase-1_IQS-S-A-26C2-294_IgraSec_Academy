#!/usr/bin/env python3
"""
================================================================================
 ADVANCED NETWORK & SECURITY SCANNER
 Version: 2.0
 Author: [Your Name]
 Description: A comprehensive Python tool for network reconnaissance,
              security scanning, and vulnerability assessment.
================================================================================
"""

import argparse
import socket
import sys
import os
import json
import ssl
import datetime
import subprocess
import re
import concurrent.futures
from urllib.parse import urlparse

# Try importing optional libraries
try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    import dns.resolver
    HAS_DNS = True
except ImportError:
    HAS_DNS = False

# ==============================================================================
# COLORS FOR TERMINAL OUTPUT
# ==============================================================================
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    END = '\033[0m'

# ==============================================================================
# BANNER
# ==============================================================================
def show_banner():
    """Display the tool banner"""
    banner = f"""
{Colors.CYAN}{Colors.BOLD}
╔══════════════════════════════════════════════════════════════════════════╗
║                                                                          ║
║        ADVANCED NETWORK & SECURITY SCANNER - v2.0                        ║
║                                                                          ║
║        A comprehensive Python tool for network reconnaissance,           ║
║        security scanning, and vulnerability assessment.                  ║
║                                                                          ║
╚══════════════════════════════════════════════════════════════════════════╝
{Colors.END}
"""
    print(banner)

# ==============================================================================
# HELPER FUNCTIONS
# ==============================================================================
def print_section(title):
    """Print a section header"""
    print(f"\n{Colors.PURPLE}{'═' * 70}{Colors.END}")
    print(f"{Colors.PURPLE}  {title}{Colors.END}")
    print(f"{Colors.PURPLE}{'═' * 70}{Colors.END}")

def print_success(msg):
    print(f"{Colors.GREEN}[✓] {msg}{Colors.END}")

def print_error(msg):
    print(f"{Colors.RED}[✗] {msg}{Colors.END}")

def print_info(msg):
    print(f"{Colors.BLUE}[*] {msg}{Colors.END}")

def print_warning(msg):
    print(f"{Colors.YELLOW}[!] {msg}{Colors.END}")

def print_result(label, value):
    print(f"{Colors.WHITE}    {label:<20}{Colors.END}: {Colors.CYAN}{value}{Colors.END}")

# ==============================================================================
# FEATURE 1: DNS LOOKUP
# ==============================================================================
def dns_lookup(domain):
    """Perform DNS lookup for a domain"""
    print_section(f"DNS LOOKUP: {domain}")
    
    try:
        # A Record
        try:
            ip = socket.gethostbyname(domain)
            print_result("A Record (IPv4)", ip)
        except socket.gaierror:
            print_error("Could not resolve A record")
        
        # All IPs
        try:
            ips = socket.gethostbyname_ex(domain)
            if ips[2]:
                for ip in ips[2]:
                    print_result("IP Address", ip)
        except:
            pass
        
        # Reverse lookup
        try:
            hostname = socket.gethostbyaddr(ip)
            print_result("Reverse DNS", hostname[0])
        except:
            pass
        
        print_success(f"DNS lookup completed for {domain}")
        
    except Exception as e:
        print_error(f"DNS lookup failed: {e}")

# ==============================================================================
# FEATURE 2: PORT SCANNER
# ==============================================================================
def scan_port(host, port, timeout=1):
    """Scan a single port"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return port, result == 0
    except:
        return port, False

def port_scan(host, ports=None, threads=100):
    """Scan multiple ports on a host"""
    print_section(f"PORT SCAN: {host}")
    
    if ports is None:
        # Common ports
        ports = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445,
                 993, 995, 1723, 3306, 3389, 5900, 8080, 8443, 8888]
    
    print_info(f"Scanning {len(ports)} ports on {host}...")
    print_info(f"Using {threads} threads\n")
    
    open_ports = []
    start_time = datetime.datetime.now()
    
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {executor.submit(scan_port, host, port): port for port in ports}
            
            for future in concurrent.futures.as_completed(futures):
                port, is_open = future.result()
                if is_open:
                    open_ports.append(port)
                    service = get_service_name(port)
                    print_success(f"Port {port:<6} OPEN  ({service})")
    
    except KeyboardInterrupt:
        print_warning("\nScan interrupted by user")
        return open_ports
    
    end_time = datetime.datetime.now()
    duration = (end_time - start_time).total_seconds()
    
    print()
    if open_ports:
        print_success(f"Found {len(open_ports)} open ports in {duration:.2f}s")
    else:
        print_warning("No open ports found")
    
    return open_ports

def get_service_name(port):
    """Get common service name for a port"""
    services = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
        80: "HTTP", 110: "POP3", 111: "RPC", 135: "RPC", 139: "NetBIOS",
        143: "IMAP", 443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
        1723: "PPTP", 3306: "MySQL", 3389: "RDP", 5900: "VNC",
        8080: "HTTP-Alt", 8443: "HTTPS-Alt", 8888: "HTTP-Alt"
    }
    return services.get(port, "Unknown")

# ==============================================================================
# FEATURE 3: HTTP HEADER ANALYSIS
# ==============================================================================
def http_headers(url):
    """Analyze HTTP headers of a URL"""
    print_section(f"HTTP HEADER ANALYSIS: {url}")
    
    if not HAS_REQUESTS:
        print_error("'requests' library not installed. Run: pip install requests")
        return None
    
    try:
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        response = requests.get(url, timeout=10, allow_redirects=True)
        
        print_result("Status Code", response.status_code)
        print_result("Final URL", response.url)
        print_result("Server", response.headers.get('Server', 'N/A'))
        print_result("Content-Type", response.headers.get('Content-Type', 'N/A'))
        print_result("Content-Length", response.headers.get('Content-Length', 'N/A'))
        
        print(f"\n{Colors.WHITE}    Security Headers:{Colors.END}")
        security_headers = [
            'Strict-Transport-Security',
            'Content-Security-Policy',
            'X-Frame-Options',
            'X-Content-Type-Options',
            'X-XSS-Protection',
            'Referrer-Policy',
            'Permissions-Policy'
        ]
        
        for header in security_headers:
            value = response.headers.get(header)
            if value:
                print_success(f"{header}: {value[:60]}")
            else:
                print_warning(f"{header}: NOT SET")
        
        print_success(f"HTTP header analysis complete")
        return response
        
    except requests.exceptions.SSLError:
        print_error("SSL certificate error")
    except requests.exceptions.ConnectionError:
        print_error("Could not connect to server")
    except requests.exceptions.Timeout:
        print_error("Connection timed out")
    except Exception as e:
        print_error(f"Error: {e}")
    
    return None

# ==============================================================================
# FEATURE 4: SSL CERTIFICATE CHECKER
# ==============================================================================
def ssl_check(host, port=443):
    """Check SSL certificate of a host"""
    print_section(f"SSL CERTIFICATE CHECK: {host}:{port}")
    
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        with socket.create_connection((host, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                cipher = ssock.cipher()
                
                print_result("SSL/TLS Version", ssock.version())
                print_result("Cipher Suite", cipher[0])
                
                # Get certificate details (without verification)
                cert_bin = ssock.getpeercert(binary_form=True)
                print_result("Cert Size", f"{len(cert_bin)} bytes")
                
                # Try verified connection
                try:
                    context2 = ssl.create_default_context()
                    with socket.create_connection((host, port), timeout=10) as sock2:
                        with context2.wrap_socket(sock2, server_hostname=host) as ssock2:
                            cert2 = ssock2.getpeercert()
                            print_result("Subject", dict(x[0] for x in cert2['subject']).get('commonName', 'N/A'))
                            print_result("Issuer", dict(x[0] for x in cert2['issuer']).get('organizationName', 'N/A'))
                            print_result("Valid From", cert2['notBefore'])
                            print_result("Valid Until", cert2['notAfter'])
                            print_success("Certificate is VALID")
                except ssl.SSLCertVerificationError as e:
                    print_error(f"Certificate verification failed: {e}")
                
                print_success(f"SSL check complete")
                
    except Exception as e:
        print_error(f"SSL check failed: {e}")

# ==============================================================================
# FEATURE 5: WHOIS LOOKUP
# ==============================================================================
def whois_lookup(domain):
    """Perform WHOIS lookup"""
    print_section(f"WHOIS LOOKUP: {domain}")
    
    try:
        result = subprocess.run(
            ['whois', domain],
            capture_output=True,
            text=True,
            timeout=15
        )
        
        if result.returncode == 0:
            output = result.stdout
            
            # Extract key fields
            fields = {
                'Domain Name': r'Domain Name:\s*(.+)',
                'Registrar': r'Registrar:\s*(.+)',
                'Creation Date': r'Creation Date:\s*(.+)',
                'Expiry Date': r'(?:Registry Expiry Date|Expiry Date):\s*(.+)',
                'Name Server': r'Name Server:\s*(.+)',
                'Registrant': r'Registrant (?:Name|Organization):\s*(.+)',
            }
            
            for label, pattern in fields.items():
                matches = re.findall(pattern, output, re.IGNORECASE)
                if matches:
                    for match in matches[:2]:
                        print_result(label, match.strip())
            
            print_success("WHOIS lookup complete")
        else:
            print_error("WHOIS command failed")
            
    except FileNotFoundError:
        print_error("'whois' command not found. Install: sudo apt install whois")
    except subprocess.TimeoutExpired:
        print_error("WHOIS lookup timed out")
    except Exception as e:
        print_error(f"WHOIS error: {e}")

# ==============================================================================
# FEATURE 6: SUBDOMAIN FINDER
# ==============================================================================
def subdomain_finder(domain):
    """Find common subdomains"""
    print_section(f"SUBDOMAIN FINDER: {domain}")
    
    common_subdomains = [
        'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop',
        'ns1', 'webdisk', 'ns2', 'cpanel', 'whm', 'autodiscover',
        'autoconfig', 'm', 'imap', 'test', 'ns', 'blog', 'pop3',
        'dev', 'www2', 'admin', 'forum', 'news', 'vpn', 'ns3',
        'mail2', 'new', 'mysql', 'old', 'lists', 'support', 'mobile',
        'mx', 'static', 'docs', 'beta', 'shop', 'sql', 'secure',
        'demo', 'cp', 'calendar', 'wiki', 'web', 'media', 'email',
        'images', 'img', 'download', 'dns', 'api', 'staging', 'app'
    ]
    
    print_info(f"Testing {len(common_subdomains)} common subdomains...\n")
    
    found = []
    
    def check_subdomain(sub):
        full = f"{sub}.{domain}"
        try:
            ip = socket.gethostbyname(full)
            return (full, ip)
        except:
            return None
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        futures = [executor.submit(check_subdomain, sub) for sub in common_subdomains]
        
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                found.append(result)
                print_success(f"{result[0]:<40} → {result[1]}")
    
    print()
    if found:
        print_success(f"Found {len(found)} subdomains")
    else:
        print_warning("No subdomains found")
    
    return found

# ==============================================================================
# FEATURE 7: TRACEROUTE
# ==============================================================================
def traceroute(host):
    """Perform a simple traceroute"""
    print_section(f"TRACEROUTE: {host}")
    
    try:
        result = subprocess.run(
            ['traceroute', '-m', '15', host],
            capture_output=True,
            text=True,
            timeout=60
        )
        
        if result.returncode == 0:
            for line in result.stdout.split('\n')[:20]:
                if line.strip():
                    print(f"    {line}")
            print_success("Traceroute complete")
        else:
            print_error("Traceroute failed")
            
    except FileNotFoundError:
        print_error("'traceroute' not found. Install: sudo apt install traceroute")
    except subprocess.TimeoutExpired:
        print_error("Traceroute timed out")
    except Exception as e:
        print_error(f"Error: {e}")

# ==============================================================================
# FEATURE 8: FULL SCAN
# ==============================================================================
def full_scan(target):
    """Perform complete scan of target"""
    show_banner()
    
    print(f"{Colors.YELLOW}[*] Starting full security scan{Colors.END}")
    print(f"{Colors.YELLOW}[*] Target: {target}{Colors.END}")
    print(f"{Colors.YELLOW}[*] Time: {datetime.datetime.now()}{Colors.END}")
    
    # Extract domain from URL if needed
    if target.startswith(('http://', 'https://')):
        parsed = urlparse(target)
        domain = parsed.hostname
    else:
        domain = target
    
    results = {
        'target': target,
        'domain': domain,
        'timestamp': str(datetime.datetime.now()),
        'dns': None,
        'ports': None,
        'headers': None,
        'ssl': None,
        'subdomains': None
    }
    
    # DNS Lookup
    try:
        dns_lookup(domain)
    except Exception as e:
        print_error(f"DNS lookup failed: {e}")
    
    # Port Scan
    try:
        open_ports = port_scan(domain)
        results['ports'] = open_ports
    except Exception as e:
        print_error(f"Port scan failed: {e}")
    
    # HTTP Headers
    try:
        http_headers(f"https://{domain}")
    except Exception as e:
        print_error(f"HTTP analysis failed: {e}")
    
    # SSL Check
    try:
        ssl_check(domain)
    except Exception as e:
        print_error(f"SSL check failed: {e}")
    
    # Subdomain Finder
    try:
        subdomain_finder(domain)
    except Exception as e:
        print_error(f"Subdomain finding failed: {e}")
    
    # Summary
    print_section("SCAN COMPLETE")
    print_success(f"Full scan finished at {datetime.datetime.now()}")
    
    return results

# ==============================================================================
# HELP MENU
# ==============================================================================
def show_help():
    """Display help menu"""
    show_banner()
    
    print(f"{Colors.WHITE}USAGE:{Colors.END}")
    print(f"  python3 tool.py [OPTIONS] TARGET\n")
    
    print(f"{Colors.WHITE}OPTIONS:{Colors.END}")
    print(f"  {Colors.GREEN}-a, --all{Colors.END}           Run full scan (all features)")
    print(f"  {Colors.GREEN}-d, --dns{Colors.END}           DNS lookup only")
    print(f"  {Colors.GREEN}-p, --ports{Colors.END}         Port scan only")
    print(f"  {Colors.GREEN}-H, --headers{Colors.END}       HTTP header analysis")
    print(f"  {Colors.GREEN}-s, --ssl{Colors.END}           SSL certificate check")
    print(f"  {Colors.GREEN}-w, --whois{Colors.END}         WHOIS lookup")
    print(f"  {Colors.GREEN}-S, --subdomains{Colors.END}    Subdomain finder")
    print(f"  {Colors.GREEN}-t, --traceroute{Colors.END}    Traceroute")
    print(f"  {Colors.GREEN}-h, --help{Colors.END}          Show this help menu")
    print(f"  {Colors.GREEN}-v, --version{Colors.END}       Show version\n")
    
    print(f"{Colors.WHITE}EXAMPLES:{Colors.END}")
    print(f"  python3 tool.py --all example.com")
    print(f"  python3 tool.py --dns example.com")
    print(f"  python3 tool.py --ports example.com")
    print(f"  python3 tool.py --headers https://example.com")
    print(f"  python3 tool.py --ssl example.com")
    print(f"  python3 tool.py --subdomains example.com\n")
    
    print(f"{Colors.WHITE}REQUIREMENTS:{Colors.END}")
    print(f"  pip install requests dnspython")
    print(f"  sudo apt install whois traceroute\n")
    
    print(f"{Colors.YELLOW}⚠  WARNING: Use only on systems you own or have permission to test.{Colors.END}\n")

# ==============================================================================
# MAIN FUNCTION
# ==============================================================================
def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='Advanced Network & Security Scanner',
        add_help=False
    )
    
    parser.add_argument('target', nargs='?', help='Target domain or URL')
    parser.add_argument('-a', '--all', action='store_true', help='Run full scan')
    parser.add_argument('-d', '--dns', action='store_true', help='DNS lookup')
    parser.add_argument('-p', '--ports', action='store_true', help='Port scan')
    parser.add_argument('-H', '--headers', action='store_true', help='HTTP headers')
    parser.add_argument('-s', '--ssl', action='store_true', help='SSL check')
    parser.add_argument('-w', '--whois', action='store_true', help='WHOIS lookup')
    parser.add_argument('-S', '--subdomains', action='store_true', help='Subdomain finder')
    parser.add_argument('-t', '--traceroute', action='store_true', help='Traceroute')
    parser.add_argument('-h', '--help', action='store_true', help='Show help')
    parser.add_argument('-v', '--version', action='store_true', help='Show version')
    
    args = parser.parse_args()
    
    # Show version
    if args.version:
        print("Advanced Network & Security Scanner v2.0")
        return
    
    # Show help
    if args.help or (not args.target and not any([args.all, args.dns, args.ports,
                       args.headers, args.ssl, args.whois, args.subdomains, args.traceroute])):
        show_help()
        return
    
    # Check target
    if not args.target:
        print_error("Target required")
        print_info("Use --help for usage")
        sys.exit(1)
    
    # Extract domain
    target = args.target
    if target.startswith(('http://', 'https://')):
        domain = urlparse(target).hostname
    else:
        domain = target
    
    show_banner()
    
    # Execute based on arguments
    try:
        if args.all:
            full_scan(target)
        elif args.dns:
            dns_lookup(domain)
        elif args.ports:
            port_scan(domain)
        elif args.headers:
            http_headers(target)
        elif args.ssl:
            ssl_check(domain)
        elif args.whois:
            whois_lookup(domain)
        elif args.subdomains:
            subdomain_finder(domain)
        elif args.traceroute:
            traceroute(domain)
        else:
            show_help()
            
    except KeyboardInterrupt:
        print_warning("\n\nScan interrupted by user")
        sys.exit(0)
    except Exception as e:
        print_error(f"Unexpected error: {e}")
        sys.exit(1)

# ==============================================================================
# ENTRY POINT
# ==============================================================================
if __name__ == "__main__":
    main()