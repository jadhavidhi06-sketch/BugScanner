#!/usr/bin/env python3
"""
Bug Bounty Vulnerability Scanner
Author: Security Researcher
Version: 1.0
License: For authorized testing only
"""

import requests
import socket
import ssl
import dns.resolver
import re
import datetime
import json
import concurrent.futures
from urllib.parse import urlparse, urljoin
from typing import Dict, List, Tuple, Optional

class BugBountyScanner:
    def __init__(self, target_domain: str, wordlist_path: str = None):
        self.target_domain = target_domain
        self.target_url = f"https://{target_domain}" if not target_domain.startswith(('http://', 'https://')) else target_domain
        self.wordlist_path = wordlist_path or self._default_wordlist()
        self.findings = []
        self.scan_timestamp = datetime.datetime.now().isoformat()
        
        # Security headers to check
        self.security_headers = {
            'Strict-Transport-Security': 'High',
            'Content-Security-Policy': 'High',
            'X-Frame-Options': 'Medium',
            'X-Content-Type-Options': 'Medium',
            'Referrer-Policy': 'Low',
            'Permissions-Policy': 'Low'
        }
        
        # Sensitive paths to check
        self.sensitive_paths = [
            '/.env', '/backup.zip', '/.git/config', '/robots.txt',
            '/admin', '/wp-config.php', '/config.php', '/.htaccess',
            '/.gitignore', '/database.sql', '/dump.sql', '/phpinfo.php',
            '/.aws/credentials', '/sitemap.xml', '/crossdomain.xml',
            '/.well-known/security.txt', '/api/', '/swagger.json',
            '/.DS_Store', '/Thumbs.db', '/error.log', '/debug.log'
        ]
        
        # Open redirect parameters
        self.redirect_params = ['url', 'next', 'redirect', 'redirect_uri', 'return', 'return_to', 'goto', 'target']
        
        # Common ports to check
        self.common_ports = [80, 443, 8080, 8443, 21, 22]

    def _default_wordlist(self) -> List[str]:
        """Default subdomain wordlist if no file provided"""
        return [
            'www', 'mail', 'ftp', 'admin', 'api', 'dev', 'test', 'staging',
            'blog', 'shop', 'app', 'cdn', 'static', 'assets', 'images',
            'docs', 'help', 'support', 'portal', 'login', 'dashboard',
            'beta', 'demo', 'vpn', 'secure', 'webmail', 'forum', 'wiki',
            'git', 'jenkins', 'jira', 'confluence', 'grafana', 'prometheus',
            'monitor', 'status', 'statuspage', 'uptime', 'analytics',
            'tracking', 'metrics', 'logs', 'backup', 'old', 'new',
            'stage', 'prod', 'production', 'development', 'testing',
            'internal', 'external', 'public', 'private', 'corporate',
            'partner', 'vendor', 'customer', 'client', 'employee',
            'hr', 'payroll', 'finance', 'accounting', 'inventory',
            'erp', 'crm', 'sales', 'marketing', 'service', 'ticket',
            'helpdesk', 'desk', 'chat', 'livechat', 'knowledgebase',
            'kb', 'faq', 'news', 'press', 'media', 'download', 'upload',
            'files', 'file', 'storage', 'cloud', 'drive', 'sync',
            'calendar', 'contacts', 'tasks', 'notes', 'notepad',
            'whiteboard', 'board', 'trello', 'asana', 'basecamp',
            'monday', 'clickup', 'notion', 'slack', 'teams', 'discord',
            'zoom', 'webex', 'gotomeeting', 'meet', 'meeting',
            'webinar', 'event', 'events', 'register', 'registration',
            'signup', 'signin', 'login', 'logout', 'forgot', 'reset',
            'password', 'account', 'profile', 'settings', 'preferences',
            'config', 'configuration', 'setup', 'install', 'installer',
            'update', 'upgrade', 'patch', 'fix', 'hotfix', 'release',
            'changelog', 'roadmap', 'features', 'pricing', 'plans',
            'billing', 'invoice', 'payment', 'subscribe', 'subscription',
            'unsubscribe', 'cancel', 'refund', 'support', 'contact',
            'about', 'team', 'careers', 'jobs', 'apply', 'interview',
            'recruit', 'hiring', 'culture', 'values', 'mission',
            'privacy', 'terms', 'conditions', 'legal', 'compliance',
            'gdpr', 'ccpa', 'cookies', 'cookie', 'policy', 'policies',
            'security', 'safe', 'trust', 'verify', 'validation',
            'authenticate', 'authorize', 'permissions', 'roles',
            'groups', 'users', 'user', 'members', 'member',
            'administrator', 'moderator', 'editor', 'contributor',
            'author', 'publisher', 'reviewer', 'approver'
        ]

    def add_finding(self, category: str, severity: str, title: str, description: str, recommendation: str, evidence: str = ""):
        """Add a finding to the report"""
        finding = {
            'category': category,
            'severity': severity,
            'title': title,
            'description': description,
            'recommendation': recommendation,
            'evidence': evidence,
            'timestamp': datetime.datetime.now().isoformat()
        }
        self.findings.append(finding)
        print(f"[{severity}] {title}")

    # ========== TARGET RECON ==========
    def dns_recon(self):
        """Fetch DNS records for the target domain"""
        print("\n[+] Performing DNS Reconnaissance...")
        
        record_types = ['A', 'MX', 'NS', 'TXT']
        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(self.target_domain, record_type)
                records = [str(r) for r in answers]
                self.add_finding(
                    'DNS Reconnaissance',
                    'Info',
                    f'{record_type} Records Found',
                    f'Found {len(records)} {record_type} records for {self.target_domain}',
                    'Review DNS records for information leakage',
                    f'{record_type} Records: {", ".join(records)}'
                )
            except Exception as e:
                print(f"  [!] No {record_type} records found: {str(e)}")

    def ip_resolution(self):
        """Resolve IP address of the target"""
        print("\n[+] Resolving IP Address...")
        try:
            ip_address = socket.gethostbyname(self.target_domain)
            self.add_finding(
                'Target Reconnaissance',
                'Info',
                'IP Address Resolved',
                f'Target {self.target_domain} resolves to {ip_address}',
                'Document IP for further analysis',
                f'IP: {ip_address}'
            )
            return ip_address
        except Exception as e:
            print(f"  [!] Failed to resolve IP: {str(e)}")
            return None

    def subdomain_enumeration(self):
        """Enumerate subdomains using wordlist"""
        print("\n[+] Enumerating Subdomains...")
        found_subdomains = []
        
        def check_subdomain(subdomain):
            full_domain = f"{subdomain}.{self.target_domain}"
            try:
                socket.gethostbyname(full_domain)
                return full_domain
            except:
                return None
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            futures = {executor.submit(check_subdomain, sub): sub for sub in self.wordlist_path}
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    found_subdomains.append(result)
                    print(f"  [+] Found subdomain: {result}")
        
        if found_subdomains:
            self.add_finding(
                'Subdomain Enumeration',
                'Info',
                f'Found {len(found_subdomains)} Subdomains',
                f'Discovered {len(found_subdomains)} subdomains for {self.target_domain}',
                'Review subdomains for potential attack surface',
                f'Subdomains: {", ".join(found_subdomains)}'
            )
        else:
            print("  [!] No subdomains found")

    def port_scanning(self):
        """Check common open ports"""
        print("\n[+] Scanning Common Ports...")
        open_ports = []
        
        def check_port(port):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((self.target_domain, port))
                sock.close()
                if result == 0:
                    return port
            except:
                pass
            return None
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = {executor.submit(check_port, port): port for port in self.common_ports}
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    open_ports.append(result)
                    print(f"  [+] Port {result} is open")
        
        if open_ports:
            self.add_finding(
                'Port Scanning',
                'Medium',
                f'Found {len(open_ports)} Open Ports',
                f'Open ports detected: {open_ports}',
                'Review exposed services and close unnecessary ports',
                f'Open Ports: {", ".join(map(str, open_ports))}'
            )

    # ========== SECURITY HEADERS ANALYZER ==========
    def security_headers_analyzer(self):
        """Analyze HTTP security headers"""
        print("\n[+] Analyzing Security Headers...")
        
        try:
            response = requests.get(self.target_url, timeout=10, verify=False)
            headers = response.headers
            
            for header, severity in self.security_headers.items():
                if header not in headers:
                    self.add_finding(
                        'Security Headers',
                        severity,
                        f'Missing {header} Header',
                        f'The {header} security header is not present in the HTTP response',
                        f'Implement the {header} header with appropriate values',
                        f'Response headers: {dict(headers)}'
                    )
                else:
                    print(f"  [+] {header} header is present")
                    
        except Exception as e:
            print(f"  [!] Failed to fetch headers: {str(e)}")

    # ========== SSL/TLS ANALYZER ==========
    def ssl_tls_analyzer(self):
        """Analyze SSL/TLS configuration"""
        print("\n[+] Analyzing SSL/TLS Configuration...")
        
        try:
            context = ssl.create_default_context()
            with socket.create_connection((self.target_domain, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=self.target_domain) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Check certificate details
                    issuer = dict(x[0] for x in cert['issuer'])
                    subject = dict(x[0] for x in cert['subject'])
                    expiry_date = cert['notAfter']
                    
                    self.add_finding(
                        'SSL/TLS Analysis',
                        'Info',
                        'SSL Certificate Details',
                        f'Certificate issued by: {issuer.get("organizationName", "Unknown")}\n'
                        f'Common Name: {subject.get("commonName", "Unknown")}\n'
                        f'Expiry Date: {expiry_date}',
                        'Monitor certificate expiry and ensure valid CA signing',
                        f'Certificate: {cert}'
                    )
                    
                    # Check for weak protocols
                    weak_protocols = []
                    for protocol in ['SSLv2', 'SSLv3', 'TLSv1']:
                        try:
                            context = ssl.SSLContext(getattr(ssl, f'PROTOCOL_{protocol.replace(".", "_")}', None))
                            if context:
                                weak_protocols.append(protocol)
                        except:
                            pass
                    
                    if weak_protocols:
                        self.add_finding(
                            'SSL/TLS Analysis',
                            'High',
                            'Weak SSL/TLS Protocols Detected',
                            f'Weak protocols enabled: {weak_protocols}',
                            'Disable SSLv2, SSLv3, and TLS 1.0; enable TLS 1.2 and 1.3',
                            f'Weak protocols: {weak_protocols}'
                        )
                        
        except Exception as e:
            print(f"  [!] SSL/TLS analysis failed: {str(e)}")

    # ========== SENSITIVE FILES DISCOVERY ==========
    def sensitive_files_discovery(self):
        """Check for sensitive files and endpoints"""
        print("\n[+] Discovering Sensitive Files...")
        
        def check_path(path):
            try:
                url = urljoin(self.target_url, path)
                response = requests.get(url, timeout=5, verify=False)
                if response.status_code == 200:
                    severity = 'High' if path in ['/.env', '/.git/config', '/backup.zip', '/wp-config.php'] else 'Medium'
                    self.add_finding(
                        'Sensitive Files',
                        severity,
                        f'Sensitive Path Accessible: {path}',
                        f'The path {path} is accessible and returned status code {response.status_code}',
                        f'Restrict access to {path} or remove if not needed',
                        f'URL: {url}, Status: {response.status_code}'
                    )
                    return (path, response.status_code)
            except:
                pass
            return None
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = {executor.submit(check_path, path): path for path in self.sensitive_paths}
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    print(f"  [+] Found accessible path: {result[0]} (Status: {result[1]})")

    # ========== PARAMETER FUZZER ==========
    def parameter_fuzzer(self):
        """Fuzz parameters for SQLi and XSS vulnerabilities"""
        print("\n[+] Fuzzing Parameters...")
        
        # SQL injection payloads
        sqli_payloads = [
            "' OR '1'='1",
            "' OR 1=1--",
            "1' AND '1'='1",
            "1' AND 1=1--",
            "' UNION SELECT NULL--",
            "1; DROP TABLE users--",
            "' OR '1'='1' --",
            "' UNION SELECT 1,2,3--",
            "admin'--",
            "1' ORDER BY 1--"
        ]
        
        # XSS payloads
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "\"><script>alert('XSS')</script>",
            "'><script>alert('XSS')</script>",
            "<ScRiPt>alert('XSS')</ScRiPt>",
            "<img src=x onerror=alert(1)>",
            "<body onload=alert('XSS')>",
            "<input onfocus=alert('XSS') autofocus>"
        ]
        
        try:
            # Get URLs from the target
            response = requests.get(self.target_url, timeout=10, verify=False)
            
            # Find parameters in the page
            param_pattern = re.compile(r'[\?&](\w+)=')
            params = param_pattern.findall(response.text)
            
            if params:
                print(f"  [+] Found parameters: {params}")
                
                # Test SQLi payloads
                for param in params[:5]:  # Limit to first 5 params
                    for payload in sqli_payloads[:3]:  # Limit to first 3 SQLi payloads
                        test_url = f"{self.target_url}?{param}={payload}"
                        try:
                            test_response = requests.get(test_url, timeout=5, verify=False)
                            if any(error in test_response.text.lower() for error in ['sql', 'mysql', 'error', 'syntax', 'unexpected']):
                                self.add_finding(
                                    'SQL Injection',
                                    'Critical',
                                    f'Potential SQL Injection in parameter: {param}',
                                    f'The parameter {param} may be vulnerable to SQL injection with payload: {payload}',
                                    'Use parameterized queries and input validation',
                                    f'URL: {test_url}'
                                )
                        except:
                            pass
                
                # Test XSS payloads
                for param in params[:5]:
                    for payload in xss_payloads[:3]:  # Limit to first 3 XSS payloads
                        test_url = f"{self.target_url}?{param}={payload}"
                        try:
                            test_response = requests.get(test_url, timeout=5, verify=False)
                            if payload in test_response.text:
                                self.add_finding(
                                    'Cross-Site Scripting (XSS)',
                                    'Critical',
                                    f'Potential XSS in parameter: {param}',
                                    f'The parameter {param} reflects the XSS payload without sanitization',
                                    'Implement proper output encoding and input validation',
                                    f'URL: {test_url}'
                                )
                        except:
                            pass
            else:
                print("  [!] No parameters found in initial page")
                
        except Exception as e:
            print(f"  [!] Parameter fuzzing failed: {str(e)}")

    # ========== OPEN REDIRECT CHECKER ==========
    def open_redirect_checker(self):
        """Check for open redirect vulnerabilities"""
        print("\n[+] Checking Open Redirects...")
        
        external_url = "https://evil.com"
        
        for param in self.redirect_params:
            test_url = f"{self.target_url}?{param}={external_url}"
            try:
                response = requests.get(test_url, timeout=10, verify=False, allow_redirects=False)
                
                # Check if redirect header points to external URL
                if response.status_code in [301, 302, 303, 307, 308]:
                    redirect_location = response.headers.get('Location', '')
                    if external_url in redirect_location or 'evil' in redirect_location:
                        self.add_finding(
                            'Open Redirect',
                            'High',
                            f'Open Redirect via {param} parameter',
                            f'The {param} parameter allows redirecting to external URLs',
                            'Validate and whitelist redirect URLs',
                            f'Test URL: {test_url}\nRedirect Location: {redirect_location}'
                        )
                        print(f"  [+] Open redirect found via {param} parameter")
                        
            except Exception as e:
                print(f"  [!] Failed to check {param}: {str(e)}")

    # ========== REPORT GENERATOR ==========
    def generate_report(self, format_type: str = 'json'):
        """Generate a professional report"""
        print("\n[+] Generating Report...")
        
        report = {
            'scan_metadata': {
                'tool': 'Bug Bounty Vulnerability Scanner',
                'version': '1.0',
                'target_domain': self.target_domain,
                'target_url': self.target_url,
                'scan_timestamp': self.scan_timestamp,
                'total_findings': len(self.findings)
            },
            'summary': {
                'critical': len([f for f in self.findings if f['severity'] == 'Critical']),
                'high': len([f for f in self.findings if f['severity'] == 'High']),
                'medium': len([f for f in self.findings if f['severity'] == 'Medium']),
                'low': len([f for f in self.findings if f['severity'] == 'Low']),
                'info': len([f for f in self.findings if f['severity'] == 'Info'])
            },
            'findings': self.findings
        }
        
        if format_type == 'json':
            filename = f"bugbounty_report_{self.target_domain}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            with open(filename, 'w') as f:
                json.dump(report, f, indent=2)
            print(f"  [+] Report saved to {filename}")
            
        elif format_type == 'txt':
            filename = f"bugbounty_report_{self.target_domain}_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            with open(filename, 'w') as f:
                f.write("=" * 80 + "\n")
                f.write("BUG BOUNTY VULNERABILITY SCANNER REPORT\n")
                f.write("=" * 80 + "\n\n")
                f.write(f"Target Domain: {self.target_domain}\n")
                f.write(f"Target URL: {self.target_url}\n")
                f.write(f"Scan Timestamp: {self.scan_timestamp}\n")
                f.write(f"Total Findings: {len(self.findings)}\n\n")
                
                f.write("SUMMARY\n")
                f.write("-" * 40 + "\n")
                f.write(f"Critical: {report['summary']['critical']}\n")
                f.write(f"High: {report['summary']['high']}\n")
                f.write(f"Medium: {report['summary']['medium']}\n")
                f.write(f"Low: {report['summary']['low']}\n")
                f.write(f"Info: {report['summary']['info']}\n\n")
                
                f.write("FINDINGS\n")
                f.write("=" * 80 + "\n\n")
                
                for i, finding in enumerate(self.findings, 1):
                    f.write(f"Finding #{i}\n")
                    f.write("-" * 40 + "\n")
                    f.write(f"Category: {finding['category']}\n")
                    f.write(f"Severity: {finding['severity']}\n")
                    f.write(f"Title: {finding['title']}\n")
                    f.write(f"Description: {finding['description']}\n")
                    f.write(f"Recommendation: {finding['recommendation']}\n")
                    f.write(f"Evidence: {finding['evidence']}\n")
                    f.write(f"Timestamp: {finding['timestamp']}\n")
                    f.write("-" * 40 + "\n\n")
                
                f.write("=" * 80 + "\n")
                f.write("END OF REPORT\n")
                f.write("=" * 80 + "\n")
            
            print(f"  [+] Report saved to {filename}")

    # ========== MAIN SCAN FUNCTION ==========
    def run_scan(self):
        """Run all scanning modules"""
        print("\n" + "=" * 60)
        print(f"BUG BOUNTY VULNERABILITY SCANNER")
        print(f"Target: {self.target_domain}")
        print(f"Started: {self.scan_timestamp}")
        print("=" * 60 + "\n")
        
        print("[!] IMPORTANT: Only scan targets you are authorized to test!")
        print("[!] This tool must only be used against authorized targets.\n")
        
        # Run all modules
        self.dns_recon()
        self.ip_resolution()
        self.subdomain_enumeration()
        self.port_scanning()
        self.security_headers_analyzer()
        self.ssl_tls_analyzer()
        self.sensitive_files_discovery()
        self.parameter_fuzzer()
        self.open_redirect_checker()
        
        # Generate report
        self.generate_report('json')
        self.generate_report('txt')
        
        print("\n" + "=" * 60)
        print("SCAN COMPLETED")
        print(f"Total Findings: {len(self.findings)}")
        print("=" * 60)

# ========== MAIN EXECUTION ==========
if __name__ == "__main__":
    import sys
    
    print("""
    ╔══════════════════════════════════════════════╗
    ║     Bug Bounty Vulnerability Scanner v1.0    ║
    ║         For Authorized Testing Only          ║
    ╚══════════════════════════════════════════════╝
    """)
    
    if len(sys.argv) < 2:
        print("Usage: python bugscanner.py <target_domain> [wordlist_file]")
        print("Example: python bugscanner.py example.com")
        print("Example with wordlist: python bugscanner.py example.com subdomains.txt")
        sys.exit(1)
    
    target = sys.argv[1]
    wordlist = sys.argv[2] if len(sys.argv) > 2 else None
    
    # Load wordlist if provided
    wordlist_data = None
    if wordlist:
        try:
            with open(wordlist, 'r') as f:
                wordlist_data = [line.strip() for line in f if line.strip()]
            print(f"[+] Loaded {len(wordlist_data)} subdomains from {wordlist}")
        except FileNotFoundError:
            print(f"[!] Wordlist file not found: {wordlist}")
            print("[!] Using default wordlist")
    
    # Run scanner
    scanner = BugBountyScanner(target, wordlist_data)
    scanner.run_scan()
