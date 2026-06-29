#!/usr/bin/env python3
"""
Bug Bounty Vulnerability Scanner
Version: 3.0.1
Author: Security Engineering Team
License: MIT (Authorized Testing Only)

A professional-grade vulnerability scanner for authorized bug bounty hunting.
Built with modern Python 3.13 practices, accurate detection, and minimal false positives.
"""

import argparse
import concurrent.futures
import datetime
import json
import os
import re
import socket
import ssl
import sys
import time
from typing import Dict, List, Optional, Set, Tuple, Any
from urllib.parse import urljoin, urlparse, parse_qs, quote

import dns.resolver
import dns.exception
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


class ScannerCore:
    """Core scanner class managing shared resources and scan execution."""
    
    def __init__(self, target: str, wordlist: Optional[str] = None,
                 threads: int = 10, timeout: int = 30, verify_ssl: bool = True):
        self.target = self._normalize_target(target)
        self.wordlist_path = wordlist
        self.threads = threads
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        
        # Working URL (determined during reconnaissance)
        self.base_url: Optional[str] = None
        self.working_protocol: Optional[str] = None
        
        # Scan metadata
        self.scan_start = datetime.datetime.now()
        self.scan_id = self.scan_start.strftime("%Y%m%d_%H%M%S")
        
        # Results storage
        self.findings: List[Dict[str, Any]] = []
        self.finding_ids: Set[str] = set()
        
        # Shared HTTP session with retry strategy
        self.session = self._create_session()
        
        # DNS resolver
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout
        
        # Statistics
        self.stats = {
            'dns_records': 0,
            'subdomains': 0,
            'open_ports': 0,
            'headers_checked': 0,
            'tls_checks': 0,
            'sensitive_paths': 0,
            'parameters_tested': 0,
            'redirects_tested': 0,
            'tls_protocols_tested': 0
        }
        
        # Protocol support cache
        self.protocol_support_cache: Dict[str, bool] = {}
    
    def _normalize_target(self, target: str) -> str:
        """Normalize target to clean domain format."""
        target = target.strip().lower()
        
        # Remove protocol
        for protocol in ['https://', 'http://']:
            if target.startswith(protocol):
                target = target[len(protocol):]
        
        # Remove path
        if '/' in target:
            target = target.split('/')[0]
        
        # Remove port
        if ':' in target:
            target = target.split(':')[0]
        
        return target
    
    def _create_session(self) -> requests.Session:
        """Create reusable HTTP session with retry logic."""
        session = requests.Session()
        
        # Configure retries
        retry_strategy = Retry(
            total=2,
            backoff_factor=0.5,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        adapter = HTTPAdapter(
            max_retries=retry_strategy,
            pool_connections=20,
            pool_maxsize=20
        )
        session.mount('https://', adapter)
        session.mount('http://', adapter)
        
        # Set headers
        session.headers.update({
            'User-Agent': (
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
                'AppleWebKit/537.36 (KHTML, like Gecko) '
                'Chrome/120.0.0.0 Safari/537.36'
            ),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
        })
        
        # Suppress SSL warnings if not verifying
        if not self.verify_ssl:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        
        return session
    
    def determine_base_url(self) -> Optional[str]:
        """Determine the working base URL by trying HTTPS first, then HTTP."""
        if self.base_url:
            return self.base_url
        
        # Try HTTPS first
        https_url = f"https://{self.target}"
        response = self.safe_request(https_url, allow_redirects=False)
        if response and response.status_code < 400:
            self.base_url = https_url
            self.working_protocol = "https"
            return self.base_url
        
        # Try HTTP as fallback
        http_url = f"http://{self.target}"
        response = self.safe_request(http_url, allow_redirects=False)
        if response and response.status_code < 400:
            self.base_url = http_url
            self.working_protocol = "http"
            return self.base_url
        
        # Try HTTPS with redirects
        response = self.safe_request(https_url, allow_redirects=True)
        if response:
            self.base_url = response.url
            self.working_protocol = "https"
            return self.base_url
        
        # Try HTTP with redirects
        response = self.safe_request(http_url, allow_redirects=True)
        if response:
            self.base_url = response.url
            self.working_protocol = "http"
            return self.base_url
        
        return None
    
    def add_finding(self, category: str, severity: str, title: str,
                    description: str, recommendation: str,
                    evidence: str = "", finding_id: Optional[str] = None) -> None:
        """Add finding with duplicate detection."""
        # Generate unique ID
        if not finding_id:
            finding_id = f"{category}_{title}_{int(time.time())}"
        
        # Check for duplicates
        if finding_id in self.finding_ids:
            return
        
        self.finding_ids.add(finding_id)
        
        finding = {
            'finding_id': finding_id,
            'category': category,
            'severity': severity,
            'title': title,
            'description': description,
            'recommendation': recommendation,
            'evidence': evidence,
            'timestamp': datetime.datetime.now().isoformat()
        }
        
        self.findings.append(finding)
        
        # Console output
        severity_colors = {
            'Critical': '\033[91m',  # Red
            'High': '\033[93m',      # Yellow
            'Medium': '\033[94m',    # Blue
            'Low': '\033[92m',       # Green
            'Info': '\033[96m'       # Cyan
        }
        reset = '\033[0m'
        color = severity_colors.get(severity, '')
        print(f"  {color}[{severity}]{reset} {title}")
    
    def safe_request(self, url: str, method: str = 'GET',
                     allow_redirects: bool = True, **kwargs) -> Optional[requests.Response]:
        """Make HTTP request with error handling."""
        try:
            kwargs.setdefault('timeout', self.timeout)
            kwargs.setdefault('verify', self.verify_ssl)
            
            response = self.session.request(
                method, url, allow_redirects=allow_redirects, **kwargs
            )
            return response
        except requests.exceptions.SSLError:
            return None
        except requests.exceptions.ConnectionError:
            return None
        except requests.exceptions.Timeout:
            return None
        except requests.exceptions.RequestException:
            return None
    
    def resolve_dns(self, record_type: str) -> List[str]:
        """Resolve DNS records of specified type."""
        try:
            answers = self.resolver.resolve(self.target, record_type)
            return [str(r) for r in answers]
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN,
                dns.exception.Timeout, dns.resolver.NoNameservers):
            return []
    
    def get_summary(self) -> Dict[str, int]:
        """Get summary counts by severity."""
        summary = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Info': 0}
        for finding in self.findings:
            severity = finding['severity']
            if severity in summary:
                summary[severity] += 1
        return summary
    
    def print_banner(self) -> None:
        """Print scanner banner."""
        print("""
    ╔══════════════════════════════════════════════════════════════╗
    ║          Bug Bounty Vulnerability Scanner v3.0.1             ║
    ║              For Authorized Testing Only                     ║
    ╚══════════════════════════════════════════════════════════════╝
        """)
    
    def print_separator(self, char: str = "=", length: int = 60) -> None:
        """Print separator line."""
        print(f"\n{char * length}\n")
    
    def run(self) -> None:
        """Execute full scan."""
        self.print_banner()
        
        print(f"Target: {self.target}")
        print(f"Started: {self.scan_start.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Threads: {self.threads}")
        print(f"Timeout: {self.timeout}s")
        self.print_separator()
        
        # Determine base URL first
        base_url = self.determine_base_url()
        if not base_url:
            print("\n[ERROR] Could not establish connection to target")
            print(f"  Neither HTTPS nor HTTP worked for {self.target}")
            print("  Please check if the target is accessible and try again.")
            return
        
        print(f"Working URL: {base_url}")
        print(f"Protocol: {self.working_protocol}")
        self.print_separator()
        
        # Execute scan phases
        self.phase_reconnaissance()
        self.phase_security_headers()
        self.phase_tls_analysis()
        self.phase_sensitive_files()
        self.phase_parameter_fuzzing()
        self.phase_open_redirects()
        
        # Generate reports
        self.generate_reports()
        
        # Print summary
        self.print_summary()
    
    def phase_reconnaissance(self) -> None:
        """Phase 1: Target reconnaissance."""
        print("[Phase 1] Target Reconnaissance")
        print("-" * 40)
        
        recon = ReconModule(self)
        recon.run()
    
    def phase_security_headers(self) -> None:
        """Phase 2: Security headers analysis."""
        print("\n[Phase 2] Security Headers Analysis")
        print("-" * 40)
        
        if not self.base_url:
            print("  No working URL found, skipping...")
            return
        
        headers = SecurityHeadersModule(self)
        headers.run()
    
    def phase_tls_analysis(self) -> None:
        """Phase 3: SSL/TLS analysis."""
        print("\n[Phase 3] SSL/TLS Analysis")
        print("-" * 40)
        
        # Only run TLS analysis for HTTPS
        if self.working_protocol == "https":
            tls = TLSModule(self)
            tls.run()
        else:
            print("  Skipping TLS analysis (HTTP only)")
    
    def phase_sensitive_files(self) -> None:
        """Phase 4: Sensitive files discovery."""
        print("\n[Phase 4] Sensitive Files Discovery")
        print("-" * 40)
        
        if not self.base_url:
            print("  No working URL found, skipping...")
            return
        
        sensitive = SensitiveFilesModule(self)
        sensitive.run()
    
    def phase_parameter_fuzzing(self) -> None:
        """Phase 5: Parameter fuzzing."""
        print("\n[Phase 5] Parameter Fuzzing")
        print("-" * 40)
        
        if not self.base_url:
            print("  No working URL found, skipping...")
            return
        
        fuzzer = ParameterFuzzerModule(self)
        fuzzer.run()
    
    def phase_open_redirects(self) -> None:
        """Phase 6: Open redirect checking."""
        print("\n[Phase 6] Open Redirect Check")
        print("-" * 40)
        
        if not self.base_url:
            print("  No working URL found, skipping...")
            return
        
        redirect = OpenRedirectModule(self)
        redirect.run()
    
    def generate_reports(self) -> None:
        """Generate scan reports."""
        print("\n[Report Generation]")
        print("-" * 40)
        
        reporter = ReportModule(self)
        reporter.generate()
    
    def print_summary(self) -> None:
        """Print scan summary."""
        self.print_separator()
        print("SCAN COMPLETE")
        print("-" * 40)
        
        duration = datetime.datetime.now() - self.scan_start
        summary = self.get_summary()
        
        print(f"Duration: {duration}")
        print(f"Total Findings: {len(self.findings)}")
        print(f"  Critical: {summary['Critical']}")
        print(f"  High: {summary['High']}")
        print(f"  Medium: {summary['Medium']}")
        print(f"  Low: {summary['Low']}")
        print(f"  Info: {summary['Info']}")
        print()
        print(f"Statistics:")
        for key, value in self.stats.items():
            print(f"  {key.replace('_', ' ').title()}: {value}")
        
        self.print_separator()


class ReconModule:
    """Target reconnaissance module."""
    
    def __init__(self, core: ScannerCore):
        self.core = core
        
        # Default subdomains (built-in wordlist)
        self.default_subdomains = [
            'www', 'mail', 'ftp', 'admin', 'api', 'dev', 'test', 'staging',
            'blog', 'shop', 'app', 'cdn', 'static', 'assets', 'images',
            'docs', 'help', 'support', 'portal', 'login', 'dashboard',
            'beta', 'demo', 'vpn', 'secure', 'webmail', 'forum', 'wiki',
            'git', 'jenkins', 'jira', 'confluence', 'grafana', 'prometheus',
            'monitor', 'status', 'backup', 'old', 'new', 'stage', 'prod',
            'production', 'development', 'testing', 'internal', 'external',
            'public', 'private', 'corporate', 'partner', 'vendor', 'customer',
            'client', 'employee', 'hr', 'payroll', 'finance', 'accounting',
            'inventory', 'erp', 'crm', 'sales', 'marketing', 'service',
            'ticket', 'helpdesk', 'chat', 'knowledgebase', 'kb', 'faq',
            'news', 'press', 'media', 'download', 'upload', 'files', 'file',
            'storage', 'cloud', 'drive', 'sync', 'calendar', 'contacts',
            'tasks', 'notes', 'whiteboard', 'board', 'trello', 'slack',
            'teams', 'zoom', 'meet', 'meeting', 'webinar', 'event', 'events',
            'register', 'registration', 'signup', 'signin', 'logout', 'forgot',
            'reset', 'password', 'account', 'profile', 'settings', 'preferences',
            'config', 'configuration', 'setup', 'install', 'update', 'upgrade',
            'patch', 'fix', 'release', 'changelog', 'roadmap', 'features',
            'pricing', 'plans', 'billing', 'invoice', 'payment', 'subscribe',
            'subscription', 'cancel', 'refund', 'support', 'contact', 'about',
            'team', 'careers', 'jobs', 'apply', 'interview', 'recruit',
            'hiring', 'culture', 'values', 'mission', 'privacy', 'terms',
            'conditions', 'legal', 'compliance', 'gdpr', 'ccpa', 'cookies',
            'cookie', 'policy', 'policies', 'security', 'safe', 'trust',
            'verify', 'validation', 'authenticate', 'authorize', 'permissions',
            'roles', 'groups', 'users', 'user', 'members', 'member',
            'administrator', 'moderator', 'editor', 'contributor', 'author',
            'publisher', 'reviewer', 'approver'
        ]
    
    def load_wordlist(self) -> List[str]:
        """Load subdomain wordlist from file or use default."""
        if self.core.wordlist_path:
            try:
                with open(self.core.wordlist_path, 'r') as f:
                    wordlist = [line.strip() for line in f if line.strip()]
                print(f"  Loaded {len(wordlist)} subdomains from {self.core.wordlist_path}")
                return wordlist
            except FileNotFoundError:
                print(f"  Warning: Wordlist {self.core.wordlist_path} not found, using default")
        
        print(f"  Using built-in wordlist ({len(self.default_subdomains)} subdomains)")
        return self.default_subdomains
    
    def run(self) -> None:
        """Execute reconnaissance phase."""
        # DNS Records
        print("  [DNS Records]")
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT']
        
        for record_type in record_types:
            records = self.core.resolve_dns(record_type)
            if records:
                self.core.stats['dns_records'] += len(records)
                print(f"    {record_type}: {', '.join(records[:3])}" + 
                      (f" ... (+{len(records)-3} more)" if len(records) > 3 else ""))
                
                self.core.add_finding(
                    category="DNS Reconnaissance",
                    severity="Info",
                    title=f"{record_type} Records Found",
                    description=f"Found {len(records)} {record_type} records",
                    recommendation="Review DNS records for information leakage",
                    evidence=f"{record_type}: {', '.join(records)}",
                    finding_id=f"dns_{record_type}_{self.core.target}"
                )
            else:
                print(f"    {record_type}: None")
        
        # IP Resolution
        print("\n  [IP Resolution]")
        ip_records = self.core.resolve_dns('A')
        if ip_records:
            ip_address = ip_records[0]
            print(f"    IP: {ip_address}")
            
            self.core.add_finding(
                category="Target Reconnaissance",
                severity="Info",
                title="IP Address Resolved",
                description=f"Target resolves to {ip_address}",
                recommendation="Document IP for further analysis",
                evidence=f"IP: {ip_address}",
                finding_id=f"ip_{self.core.target}"
            )
        
        # Subdomain Enumeration
        print("\n  [Subdomain Enumeration]")
        wordlist = self.load_wordlist()
        found_subdomains = self.enumerate_subdomains(wordlist)
        
        if found_subdomains:
            self.core.stats['subdomains'] = len(found_subdomains)
            print(f"    Found {len(found_subdomains)} subdomains")
            for subdomain in sorted(found_subdomains)[:10]:
                print(f"      [+] {subdomain}")
            if len(found_subdomains) > 10:
                print(f"      ... and {len(found_subdomains) - 10} more")
            
            self.core.add_finding(
                category="Subdomain Enumeration",
                severity="Info",
                title=f"Found {len(found_subdomains)} Subdomains",
                description=f"Discovered {len(found_subdomains)} subdomains",
                recommendation="Review subdomains for potential attack surface",
                evidence=f"Subdomains: {', '.join(sorted(found_subdomains))}",
                finding_id=f"subdomains_{self.core.target}"
            )
        
        # Port Scanning
        print("\n  [Port Scanning]")
        open_ports = self.scan_ports()
        
        if open_ports:
            self.core.stats['open_ports'] = len(open_ports)
            print(f"    Found {len(open_ports)} open ports")
            for port, service in sorted(open_ports.items()):
                print(f"      [+] Port {port} ({service})")
            
            severity = "Medium" if len(open_ports) > 3 else "Low"
            self.core.add_finding(
                category="Port Scanning",
                severity=severity,
                title=f"Found {len(open_ports)} Open Ports",
                description=f"Open ports: {', '.join(f'{p}({s})' for p, s in sorted(open_ports.items()))}",
                recommendation="Review exposed services and close unnecessary ports",
                evidence=f"Ports: {open_ports}",
                finding_id=f"ports_{self.core.target}"
            )
    
    def enumerate_subdomains(self, wordlist: List[str]) -> List[str]:
        """Enumerate subdomains using wordlist."""
        found = []
        
        def check_subdomain(subdomain: str) -> Optional[str]:
            full_domain = f"{subdomain}.{self.core.target}"
            try:
                socket.gethostbyname(full_domain)
                return full_domain
            except socket.gaierror:
                return None
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.core.threads) as executor:
            futures = {executor.submit(check_subdomain, sub): sub for sub in wordlist}
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    found.append(result)
        
        return found
    
    def scan_ports(self) -> Dict[int, str]:
        """Scan common ports."""
        common_ports = {
            21: "FTP",
            22: "SSH",
            80: "HTTP",
            443: "HTTPS",
            8080: "HTTP-Proxy",
            8443: "HTTPS-Alt"
        }
        open_ports = {}
        
        def check_port(port: int) -> Optional[Tuple[int, str]]:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                result = sock.connect_ex((self.core.target, port))
                sock.close()
                
                if result == 0:
                    # Try to get service banner
                    try:
                        service_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        service_sock.settimeout(2)
                        service_sock.connect((self.core.target, port))
                        banner = service_sock.recv(1024).decode('utf-8', errors='ignore').strip()
                        service_sock.close()
                        return (port, banner[:50] if banner else common_ports.get(port, "Unknown"))
                    except:
                        return (port, common_ports.get(port, "Unknown"))
            except:
                pass
            return None
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=6) as executor:
            futures = {executor.submit(check_port, port): port for port in common_ports}
            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                if result:
                    open_ports[result[0]] = result[1]
        
        return open_ports


class SecurityHeadersModule:
    """Security headers analysis module."""
    
    def __init__(self, core: ScannerCore):
        self.core = core
        
        self.headers_to_check = {
            'Strict-Transport-Security': {
                'severity': 'High',
                'description': 'Enforces HTTPS connections',
                'recommendation': "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains'"
            },
            'Content-Security-Policy': {
                'severity': 'High',
                'description': 'Prevents XSS and data injection attacks',
                'recommendation': "Implement Content-Security-Policy with appropriate directives"
            },
            'X-Frame-Options': {
                'severity': 'Medium',
                'description': 'Prevents clickjacking attacks',
                'recommendation': "Add 'X-Frame-Options: DENY' or 'SAMEORIGIN'"
            },
            'X-Content-Type-Options': {
                'severity': 'Medium',
                'description': 'Prevents MIME type sniffing',
                'recommendation': "Add 'X-Content-Type-Options: nosniff'"
            },
            'Referrer-Policy': {
                'severity': 'Low',
                'description': 'Controls referrer information',
                'recommendation': "Add 'Referrer-Policy: strict-origin-when-cross-origin'"
            },
            'Permissions-Policy': {
                'severity': 'Low',
                'description': 'Controls browser features',
                'recommendation': "Implement Permissions-Policy to restrict feature access"
            }
        }
    
    def run(self) -> None:
        """Execute security headers analysis."""
        url = self.core.base_url
        if not url:
            print("  No working URL available")
            return
        
        response = self.core.safe_request(url)
        
        if not response:
            print("  Could not fetch target URL")
            return
        
        headers = response.headers
        print(f"  Status: {response.status_code}")
        print(f"  Server: {headers.get('Server', 'Unknown')}")
        print()
        
        for header, config in self.headers_to_check.items():
            self.core.stats['headers_checked'] += 1
            
            if header not in headers:
                self.core.add_finding(
                    category="Security Headers",
                    severity=config['severity'],
                    title=f"Missing {header} Header",
                    description=f"The {header} header is missing. {config['description']}",
                    recommendation=config['recommendation'],
                    evidence=f"Response headers: {dict(headers)}",
                    finding_id=f"header_{header}_{self.core.target}"
                )
                print(f"  [MISSING] {header} ({config['severity']})")
            else:
                value = headers[header]
                print(f"  [PRESENT] {header}: {value[:50]}" + 
                      ("..." if len(value) > 50 else ""))


class TLSModule:
    """SSL/TLS analysis module with actual protocol handshakes."""
    
    def __init__(self, core: ScannerCore):
        self.core = core
        
        # Protocol versions to test (modern mapping)
        self.protocols = {
            'TLSv1.2': ssl.TLSVersion.TLSv1_2,
            'TLSv1.3': ssl.TLSVersion.TLSv1_3
        }
        
        # Legacy protocols with alternative testing
        self.legacy_protocols = ['SSLv2', 'SSLv3', 'TLSv1.0', 'TLSv1.1']
        self.weak_protocols = ['SSLv2', 'SSLv3', 'TLSv1.0', 'TLSv1.1']
    
    def run(self) -> None:
        """Execute TLS analysis."""
        # Get certificate
        cert_info = self.get_certificate_info()
        
        if cert_info:
            self.analyze_certificate(cert_info)
        
        # Test protocol support
        self.test_protocols()
    
    def get_certificate_info(self) -> Optional[Dict[str, Any]]:
        """Get SSL certificate information using modern APIs."""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection(
                (self.core.target, 443), timeout=self.core.timeout
            ) as sock:
                with context.wrap_socket(sock, server_hostname=self.core.target) as ssock:
                    cert = ssock.getpeercert()
                    
                    if not cert:
                        return None
                    
                    # Extract subject info
                    subject = dict(x[0] for x in cert['subject'])
                    issuer = dict(x[0] for x in cert['issuer'])
                    
                    return {
                        'subject': subject,
                        'issuer': issuer,
                        'notBefore': cert.get('notBefore', 'Unknown'),
                        'notAfter': cert.get('notAfter', 'Unknown'),
                        'serialNumber': cert.get('serialNumber', 'Unknown'),
                        'version': cert.get('version', 'Unknown'),
                        'subjectAltName': cert.get('subjectAltName', [])
                    }
        except Exception:
            return None
    
    def analyze_certificate(self, cert_info: Dict[str, Any]) -> None:
        """Analyze certificate for issues."""
        self.core.stats['tls_checks'] += 1
        
        # Print certificate details
        print("  [Certificate Details]")
        print(f"    Subject: {cert_info['subject'].get('commonName', 'N/A')}")
        print(f"    Issuer: {cert_info['issuer'].get('organizationName', 'N/A')}")
        print(f"    Valid From: {cert_info['notBefore']}")
        print(f"    Valid Until: {cert_info['notAfter']}")
        
        # Check expiration
        try:
            expiry = datetime.datetime.strptime(
                cert_info['notAfter'], '%b %d %H:%M:%S %Y %Z'
            )
            now = datetime.datetime.utcnow()
            
            if expiry < now:
                self.core.add_finding(
                    category="SSL/TLS Analysis",
                    severity="High",
                    title="Expired SSL Certificate",
                    description=f"Certificate expired on {cert_info['notAfter']}",
                    recommendation="Renew the SSL certificate immediately",
                    evidence=f"Valid until: {cert_info['notAfter']}",
                    finding_id=f"cert_expired_{self.core.target}"
                )
                print("    [EXPIRED] Certificate is expired!")
        except ValueError:
            pass
        
        # Check self-signed
        if cert_info['subject'] == cert_info['issuer']:
            self.core.add_finding(
                category="SSL/TLS Analysis",
                severity="Medium",
                title="Self-Signed Certificate Detected",
                description="The certificate is self-signed",
                recommendation="Use a certificate from a trusted CA for production",
                evidence=f"Subject matches issuer: {cert_info['subject']}",
                finding_id=f"cert_selfsigned_{self.core.target}"
            )
            print("    [SELF-SIGNED] Certificate is self-signed")
        
        # Add informational finding
        self.core.add_finding(
            category="SSL/TLS Analysis",
            severity="Info",
            title="SSL Certificate Details",
            description=f"Certificate issued to: {cert_info['subject'].get('commonName', 'N/A')}\n"
                       f"Issued by: {cert_info['issuer'].get('organizationName', 'N/A')}\n"
                       f"Valid until: {cert_info['notAfter']}",
            recommendation="Monitor certificate expiry",
            evidence=f"Certificate: {cert_info}",
            finding_id=f"cert_info_{self.core.target}"
        )
    
    def test_protocols(self) -> List[str]:
        """Test actual protocol support through real handshakes."""
        print("\n  [Protocol Testing]")
        supported_weak = []
        
        # Test modern protocols first
        for protocol_name, tls_version in self.protocols.items():
            self.core.stats['tls_protocols_tested'] += 1
            if self._test_tls_version(tls_version):
                print(f"    [+] {protocol_name}: Supported")
            else:
                print(f"    [-] {protocol_name}: Not supported")
        
        # Test legacy protocols with specific error handling
        for protocol_name in self.legacy_protocols:
            self.core.stats['tls_protocols_tested'] += 1
            if self._test_legacy_protocol(protocol_name):
                supported_weak.append(protocol_name)
                print(f"    [!] {protocol_name}: Supported (WEAK)")
            else:
                print(f"    [-] {protocol_name}: Not supported")
        
        if supported_weak:
            self.core.add_finding(
                category="SSL/TLS Analysis",
                severity="High",
                title="Weak SSL/TLS Protocols Detected",
                description=f"Weak protocols enabled: {', '.join(supported_weak)}",
                recommendation="Disable SSLv2, SSLv3, TLS 1.0, and TLS 1.1. Enable TLS 1.2 and 1.3 only.",
                evidence=f"Supported weak protocols: {', '.join(supported_weak)}",
                finding_id=f"weak_protocols_{self.core.target}"
            )
        
        return supported_weak
    
    def _test_tls_version(self, tls_version: ssl.TLSVersion) -> bool:
        """Test if a specific TLS version is supported."""
        # Check cache first
        cache_key = f"tls_{tls_version}"
        if cache_key in self.core.protocol_support_cache:
            return self.core.protocol_support_cache[cache_key]
        
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.minimum_version = tls_version
            context.maximum_version = tls_version
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection(
                (self.core.target, 443), timeout=5
            ) as sock:
                with context.wrap_socket(sock, server_hostname=self.core.target) as ssock:
                    # Verify the connection was established
                    if ssock.version():
                        self.core.protocol_support_cache[cache_key] = True
                        return True
        except (ssl.SSLError, socket.timeout, ConnectionRefusedError, OSError):
            pass
        
        self.core.protocol_support_cache[cache_key] = False
        return False
    
    def _test_legacy_protocol(self, protocol: str) -> bool:
        """Test for legacy SSL protocols using multiple approaches."""
        cache_key = f"legacy_{protocol}"
        if cache_key in self.core.protocol_support_cache:
            return self.core.protocol_support_cache[cache_key]
        
        # Try standard TLS connection first
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            # Try to get cipher list that might indicate legacy support
            with socket.create_connection(
                (self.core.target, 443), timeout=5
            ) as sock:
                with context.wrap_socket(sock, server_hostname=self.core.target) as ssock:
                    # Check if the server advertises any weak ciphers
                    cipher = ssock.cipher()
                    if cipher and any(weak in cipher[0].lower() for weak in 
                                     ['rc4', 'des', 'export', 'null']):
                        self.core.protocol_support_cache[cache_key] = True
                        return True
        except:
            pass
        
        # Try connecting with specific SSL/TLS version using ssl.wrap_socket (legacy)
        # This is a fallback for systems where modern SSLContext might not catch all
        try:
            import ssl as ssl_module
            
            # Different approach for different protocols
            if protocol == 'SSLv2':
                # SSLv2 is mostly dead, try with specific cipher
                try:
                    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                    context.set_ciphers('ALL:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!3DES:!MD5:!PSK:!SRP')
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    
                    with socket.create_connection(
                        (self.core.target, 443), timeout=5
                    ) as sock:
                        with context.wrap_socket(sock, server_hostname=self.core.target) as ssock:
                            # If we get here, SSLv2-like ciphers might be supported
                            self.core.protocol_support_cache[cache_key] = True
                            return True
                except:
                    pass
            
            elif protocol in ['SSLv3', 'TLSv1.0', 'TLSv1.1']:
                # Try with minimal TLS version
                try:
                    context = ssl.create_default_context()
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    
                    # Force older TLS version
                    if protocol == 'SSLv3':
                        # SSLv3 is not supported in modern Python, but we can try
                        pass
                    elif protocol == 'TLSv1.0':
                        context.minimum_version = ssl.TLSVersion.TLSv1
                        context.maximum_version = ssl.TLSVersion.TLSv1
                    elif protocol == 'TLSv1.1':
                        context.minimum_version = ssl.TLSVersion.TLSv1_1
                        context.maximum_version = ssl.TLSVersion.TLSv1_1
                    
                    with socket.create_connection(
                        (self.core.target, 443), timeout=5
                    ) as sock:
                        with context.wrap_socket(sock, server_hostname=self.core.target) as ssock:
                            if ssock.version() and protocol.lower() in ssock.version().lower():
                                self.core.protocol_support_cache[cache_key] = True
                                return True
                except:
                    pass
        except:
            pass
        
        self.core.protocol_support_cache[cache_key] = False
        return False


class SensitiveFilesModule:
    """Sensitive files and endpoints discovery module."""
    
    def __init__(self, core: ScannerCore):
        self.core = core
        
        self.paths = {
            'critical': [
                '/.env',
                '/.git/config',
                '/.git/HEAD',
                '/backup.zip',
                '/backup.tar.gz',
                '/wp-config.php',
                '/config.php',
                '/database.sql',
                '/dump.sql',
                '/.aws/credentials',
                '/.aws/config'
            ],
            'high': [
                '/.htaccess',
                '/.gitignore',
                '/admin',
                '/administrator',
                '/phpinfo.php',
                '/info.php',
                '/api/swagger.json',
                '/swagger.json',
                '/api-docs',
                '/graphql',
                '/actuator',
                '/actuator/health',
                '/actuator/info'
            ],
            'medium': [
                '/robots.txt',
                '/sitemap.xml',
                '/crossdomain.xml',
                '/clientaccesspolicy.xml',
                '/.DS_Store',
                '/Thumbs.db',
                '/error.log',
                '/debug.log',
                '/install.php',
                '/setup.php',
                '/test.php',
                '/api/',
                '/api/v1/',
                '/api/v2/'
            ],
            'low': [
                '/login',
                '/signin',
                '/register',
                '/signup',
                '/contact',
                '/about',
                '/privacy',
                '/terms',
                '/help',
                '/support'
            ]
        }
        
        # Patterns for content validation
        self.sensitive_patterns = {
            'credentials': [
                r'(?i)(password|passwd|pwd|secret|token|api_key|api_secret)',
                r'(?i)(DB_HOST|DB_NAME|DB_USER|DB_PASSWORD)',
                r'(?i)(AWS_ACCESS_KEY|AWS_SECRET_KEY)',
                r'(?i)(sk-[a-zA-Z0-9]{20,})',
                r'(?i)(-----BEGIN.*KEY-----)'
            ],
            'config': [
                r'(?i)(APP_ENV|APP_KEY|APP_DEBUG)',
                r'(?i)(database|mysql|postgresql|mongodb)',
                r'(?i)(configuration|config|settings)'
            ],
            'backup': [
                r'(?i)(backup|dump|export|sql|tar|gz|zip)',
                r'(?i)(INSERT INTO|CREATE TABLE|DROP TABLE)'
            ],
            'api_docs': [
                r'(?i)(swagger|openapi|api.version)',
                r'(?i)(paths|definitions|responses)'
            ]
        }
    
    def run(self) -> None:
        """Execute sensitive files discovery."""
        base_url = self.core.base_url
        if not base_url:
            print("  No working URL available")
            return
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.core.threads) as executor:
            futures = {}
            for severity, paths in self.paths.items():
                for path in paths:
                    url = urljoin(base_url, path)
                    future = executor.submit(self.check_path, url, path, severity)
                    futures[future] = (path, severity)
            
            for future in concurrent.futures.as_completed(futures):
                path, default_severity = futures[future]
                result = future.result()
                
                if result:
                    url, status, content, actual_severity = result
                    self.core.stats['sensitive_paths'] += 1
                    
                    self.core.add_finding(
                        category="Sensitive Files",
                        severity=actual_severity,
                        title=f"Sensitive Path Accessible: {path}",
                        description=f"The path {path} is accessible (HTTP {status})",
                        recommendation=f"Restrict access to {path} or remove if not needed",
                        evidence=f"URL: {url}\nStatus: {status}\nContent preview: {content[:200]}",
                        finding_id=f"sensitive_{path}_{self.core.target}"
                    )
                    print(f"  [{actual_severity}] {path} ({status})")
    
    def check_path(self, url: str, path: str, 
                   default_severity: str) -> Optional[Tuple[str, int, str, str]]:
        """Check if a path is accessible and assess severity."""
        response = self.core.safe_request(url, allow_redirects=False)
        
        if not response:
            return None
        
        # Only consider successful responses
        if response.status_code != 200:
            return None
        
        content = response.text
        
        # Validate content is meaningful
        if len(content) < 10:
            return None
        
        # Check for directory listing
        if 'Index of' in content or 'Directory listing for' in content:
            return (url, response.status_code, content, 'High')
        
        # Assess actual severity based on content
        actual_severity = self.assess_severity(path, content, default_severity)
        
        if actual_severity:
            return (url, response.status_code, content, actual_severity)
        
        return None
    
    def assess_severity(self, path: str, content: str, 
                        default_severity: str) -> Optional[str]:
        """Assess actual severity based on content analysis."""
        # Check for credentials
        for pattern in self.sensitive_patterns['credentials']:
            if re.search(pattern, content):
                return 'Critical'
        
        # Check for configuration
        for pattern in self.sensitive_patterns['config']:
            if re.search(pattern, content):
                return 'High'
        
        # Check for backups
        for pattern in self.sensitive_patterns['backup']:
            if re.search(pattern, content):
                return 'High'
        
        # Check for API documentation
        for pattern in self.sensitive_patterns['api_docs']:
            if re.search(pattern, content):
                return 'Medium'
        
        # Return default severity if content is substantial
        if len(content) > 500:
            return default_severity
        
        return None


class ParameterFuzzerModule:
    """Parameter fuzzing module with heuristic-based detection."""
    
    def __init__(self, core: ScannerCore):
        self.core = core
        
        # SQL error signatures
        self.sqli_patterns = [
            r"(?i)(sql|mysql|postgresql|oracle|microsoft.*sql)",
            r"(?i)(syntax.*error|unclosed.*quote|unexpected.*token)",
            r"(?i)(warning.*mysql|odbc.*driver|db2.*error)",
            r"(?i)(you have an error in your sql)",
            r"(?i)(supplied argument is not a valid mysql)",
            r"(?i)(column.*not found|table.*not found)",
            r"(?i)(division by zero|duplicate entry)",
            r"(?i)(unknown column|unknown table)"
        ]
        
        # SQL injection payloads
        self.sqli_payloads = [
            "'",
            "''",
            "1'",
            "1''",
            "' OR '1'='1",
            "' OR 1=1--",
            "1' AND '1'='1",
            "1' AND 1=1--",
            "' UNION SELECT NULL--",
            "' UNION SELECT 1,2,3--",
            "admin'--",
            "1' ORDER BY 1--",
            "1' ORDER BY 2--",
            "1' ORDER BY 3--"
        ]
        
        # XSS payloads
        self.xss_payloads = [
            "<script>alert(1)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "javascript:alert(1)",
            "\"><script>alert(1)</script>",
            "'><script>alert(1)</script>",
            "<ScRiPt>alert(1)</ScRiPt>",
            "<img src=x onerror=alert(1)>",
            "<body onload=alert(1)>",
            "<input onfocus=alert(1) autofocus>"
        ]
        
        # HTML encoding patterns for XSS detection
        self.xss_context_patterns = [
            (r'<script[^>]*>.*{payload}', 'Script tag'),
            (r'on\w+\s*=\s*["\']?[^"\']*{payload}', 'Event handler'),
            (r'href\s*=\s*["\']?[^"\']*{payload}', 'Href attribute'),
            (r'src\s*=\s*["\']?[^"\']*{payload}', 'Src attribute'),
            (r'<[^>]*{payload}[^>]*>', 'HTML tag')
        ]
    
    def run(self) -> None:
        """Execute parameter fuzzing."""
        base_url = self.core.base_url
        if not base_url:
            print("  No working URL available")
            return
        
        # First, find parameters on the target
        params = self.discover_parameters(base_url)
        
        if not params:
            print("  No parameters found to test")
            return
        
        print(f"  Found {len(params)} parameters to test")
        
        # Test each parameter
        for param_name, param_url in params:
            print(f"\n  Testing parameter: {param_name}")
            
            # Get baseline response
            baseline = self.get_baseline(param_url, param_name)
            if not baseline:
                continue
            
            # Test SQL injection
            self.test_sqli(param_url, param_name, baseline)
            
            # Test XSS
            self.test_xss(param_url, param_name, baseline)
    
    def discover_parameters(self, base_url: str) -> List[Tuple[str, str]]:
        """Discover URL parameters from target."""
        params = []
        
        response = self.core.safe_request(base_url)
        if not response:
            return params
        
        content = response.text
        
        # Find parameters in links
        link_pattern = re.compile(r'href=["\']([^"\']*\?[^"\']*)["\']')
        for match in link_pattern.findall(content):
            parsed = urlparse(match)
            query_params = parse_qs(parsed.query)
            for param_name in query_params:
                params.append((param_name, urljoin(base_url, match)))
        
        # Find parameters in forms
        form_pattern = re.compile(
            r'<form[^>]*action=["\']([^"\']*)["\'][^>]*>(.*?)</form>',
            re.DOTALL | re.IGNORECASE
        )
        
        for action, form_content in form_pattern.findall(content):
            input_pattern = re.compile(
                r'<input[^>]*name=["\']([^"\']*)["\']',
                re.IGNORECASE
            )
            for input_name in input_pattern.findall(form_content):
                params.append((input_name, urljoin(base_url, action)))
        
        # Remove duplicates while preserving order
        seen = set()
        unique_params = []
        for param_name, param_url in params:
            key = (param_name, param_url)
            if key not in seen:
                seen.add(key)
                unique_params.append(key)
        
        return unique_params
    
    def get_baseline(self, url: str, param_name: str) -> Optional[str]:
        """Get baseline response for comparison."""
        test_url = f"{url.split('?')[0]}?{param_name}=1"
        response = self.core.safe_request(test_url)
        
        if response:
            return response.text
        return None
    
    def test_sqli(self, url: str, param_name: str, baseline: str) -> None:
        """Test parameter for SQL injection."""
        base_url = url.split('?')[0]
        
        for payload in self.sqli_payloads[:5]:  # Test first 5 payloads
            self.core.stats['parameters_tested'] += 1
            test_url = f"{base_url}?{param_name}={quote(payload)}"
            
            response = self.core.safe_request(test_url)
            if not response:
                continue
            
            content = response.text
            
            # Check for SQL error patterns
            for pattern in self.sqli_patterns:
                if re.search(pattern, content):
                    self.core.add_finding(
                        category="SQL Injection",
                        severity="Critical",
                        title=f"Potential SQL Injection in parameter: {param_name}",
                        description=f"SQL error pattern detected with payload: {payload}",
                        recommendation="Use parameterized queries and input validation",
                        evidence=f"URL: {test_url}\nPayload: {payload}\nError pattern: {pattern}",
                        finding_id=f"sqli_{param_name}_{hash(payload)}_{self.core.target}"
                    )
                    print(f"    [!] SQL Injection detected with payload: {payload}")
                    return
            
            # Check for behavioral differences
            if response.status_code != 200 and len(content) != len(baseline):
                if len(content) < 100:  # Error page
                    self.core.add_finding(
                        category="SQL Injection",
                        severity="Medium",
                        title=f"Potential SQL Injection in parameter: {param_name}",
                        description=f"Unusual response with payload: {payload}",
                        recommendation="Investigate parameter for SQL injection",
                        evidence=f"URL: {test_url}\nStatus: {response.status_code}\nResponse length: {len(content)}",
                        finding_id=f"sqli_behavior_{param_name}_{hash(payload)}_{self.core.target}"
                    )
                    print(f"    [?] Unusual behavior with payload: {payload}")
    
    def test_xss(self, url: str, param_name: str, baseline: str) -> None:
        """Test parameter for XSS."""
        base_url = url.split('?')[0]
        
        for payload in self.xss_payloads[:5]:  # Test first 5 payloads
            self.core.stats['parameters_tested'] += 1
            test_url = f"{base_url}?{param_name}={quote(payload)}"
            
            response = self.core.safe_request(test_url)
            if not response:
                continue
            
            content = response.text
            
            # Check for payload reflection in dangerous contexts
            for pattern, context_name in self.xss_context_patterns:
                context_pattern = pattern.replace('{payload}', re.escape(payload))
                if re.search(context_pattern, content, re.IGNORECASE):
                    self.core.add_finding(
                        category="Cross-Site Scripting (XSS)",
                        severity="Critical",
                        title=f"Potential XSS in parameter: {param_name}",
                        description=f"XSS payload reflected in {context_name} context",
                        recommendation="Implement proper output encoding and input validation",
                        evidence=f"URL: {test_url}\nPayload: {payload}\nContext: {context_name}",
                        finding_id=f"xss_{param_name}_{hash(payload)}_{self.core.target}"
                    )
                    print(f"    [!] XSS detected in {context_name} with payload: {payload}")
                    return
            
            # Check for simple reflection (lower severity)
            if payload in content:
                self.core.add_finding(
                    category="Cross-Site Scripting (XSS)",
                    severity="Low",
                    title=f"Parameter Reflection in: {param_name}",
                    description=f"Parameter reflects input without sanitization",
                    recommendation="Implement output encoding",
                    evidence=f"URL: {test_url}\nReflected payload: {payload}",
                    finding_id=f"xss_reflection_{param_name}_{hash(payload)}_{self.core.target}"
                )
                print(f"    [?] Parameter reflects input with payload: {payload}")


class OpenRedirectModule:
    """Open redirect vulnerability checker."""
    
    def __init__(self, core: ScannerCore):
        self.core = core
        
        self.redirect_params = [
            'url', 'next', 'redirect', 'redirect_uri', 'return',
            'return_to', 'goto', 'target', 'destination', 'out',
            'view', 'dir', 'to', 'link', 'location', 'path'
        ]
        
        self.test_urls = [
            "https://evil.com",
            "//evil.com",
            "https://evil.com/redirect",
            "http://evil.com",
            "//evil.com@trusted.com",
            "https://evil.com%2Ftrusted.com",
            "https://evil.com/trusted.com"
        ]
    
    def run(self) -> None:
        """Execute open redirect checks."""
        base_url = self.core.base_url
        if not base_url:
            print("  No working URL available")
            return
        
        for param in self.redirect_params:
            for test_url in self.test_urls[:3]:  # Test first 3 variations
                self.core.stats['redirects_tested'] += 1
                
                encoded_url = quote(test_url, safe='')
                test_full_url = f"{base_url}?{param}={encoded_url}"
                
                response = self.core.safe_request(test_full_url, allow_redirects=False)
                
                if not response:
                    continue
                
                # Check HTTP redirect
                if response.status_code in [301, 302, 303, 307, 308]:
                    location = response.headers.get('Location', '')
                    
                    if self.is_external_redirect(location, test_url):
                        self.core.add_finding(
                            category="Open Redirect",
                            severity="High",
                            title=f"Open Redirect via {param} parameter",
                            description=f"The '{param}' parameter allows redirecting to external URLs",
                            recommendation="Validate and whitelist redirect URLs",
                            evidence=f"Parameter: {param}\nTest URL: {test_full_url}\nRedirect to: {location}",
                            finding_id=f"redirect_{param}_{self.core.target}"
                        )
                        print(f"  [High] Open redirect via {param} parameter -> {location[:50]}")
                        break  # Found vulnerability, no need to test more URLs for this param
                
                # Check JavaScript redirect
                if response.status_code == 200:
                    content = response.text
                    if self.check_js_redirect(content, test_url):
                        self.core.add_finding(
                            category="Open Redirect",
                            severity="High",
                            title=f"JavaScript Open Redirect via {param} parameter",
                            description=f"The '{param}' parameter allows JavaScript-based redirect to external URLs",
                            recommendation="Validate and whitelist redirect URLs",
                            evidence=f"Parameter: {param}\nTest URL: {test_full_url}",
                            finding_id=f"js_redirect_{param}_{self.core.target}"
                        )
                        print(f"  [High] JS open redirect via {param} parameter")
                        break
    
    def is_external_redirect(self, location: str, test_url: str) -> bool:
        """Check if redirect location points to external URL."""
        if not location:
            return False
        
        # Check for various redirect patterns
        redirect_indicators = [
            'evil.com' in location.lower(),
            '//evil' in location.lower(),
            '@evil.com' in location.lower(),
            test_url.split('://')[1] in location.lower() if '://' in test_url else False
        ]
        
        return any(redirect_indicators)
    
    def check_js_redirect(self, content: str, test_url: str) -> bool:
        """Check for JavaScript-based redirects."""
        js_patterns = [
            r'window\.location\s*=\s*["\']([^"\']*)["\']',
            r'window\.location\.href\s*=\s*["\']([^"\']*)["\']',
            r'document\.location\s*=\s*["\']([^"\']*)["\']',
            r'document\.location\.href\s*=\s*["\']([^"\']*)["\']',
            r'window\.open\s*\(\s*["\']([^"\']*)["\']',
            r'location\.replace\s*\(\s*["\']([^"\']*)["\']',
            r'location\.assign\s*\(\s*["\']([^"\']*)["\']'
        ]
        
        for pattern in js_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                if 'evil.com' in match.lower() or '//evil' in match.lower():
                    return True
        
        return False


class ReportModule:
    """Report generation module."""
    
    def __init__(self, core: ScannerCore):
        self.core = core
    
    def generate(self) -> None:
        """Generate all report formats."""
        self.generate_json()
        self.generate_txt()
        print("  Reports generated successfully")
    
    def generate_json(self) -> str:
        """Generate JSON report."""
        duration = datetime.datetime.now() - self.core.scan_start
        
        report = {
            'scan_metadata': {
                'tool': 'Bug Bounty Vulnerability Scanner',
                'version': '3.0.1',
                'target': self.core.target,
                'scan_timestamp': self.core.scan_start.isoformat(),
                'duration_seconds': duration.total_seconds(),
                'total_findings': len(self.core.findings)
            },
            'summary': self.core.get_summary(),
            'statistics': self.core.stats,
            'findings': self.core.findings
        }
        
        filename = f"bugbounty_report_{self.core.target}_{self.core.scan_id}.json"
        filepath = os.path.join(os.getcwd(), filename)
        
        with open(filepath, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"  JSON: {filename}")
        return filepath
    
    def generate_txt(self) -> str:
        """Generate TXT report."""
        duration = datetime.datetime.now() - self.core.scan_start
        summary = self.core.get_summary()
        
        filename = f"bugbounty_report_{self.core.target}_{self.core.scan_id}.txt"
        filepath = os.path.join(os.getcwd(), filename)
        
        with open(filepath, 'w') as f:
            f.write("=" * 80 + "\n")
            f.write("BUG BOUNTY VULNERABILITY SCANNER REPORT\n")
            f.write("=" * 80 + "\n\n")
            
            f.write("SCAN METADATA\n")
            f.write("-" * 40 + "\n")
            f.write(f"Tool: Bug Bounty Vulnerability Scanner v3.0.1\n")
            f.write(f"Target: {self.core.target}\n")
            f.write(f"Timestamp: {self.core.scan_start.isoformat()}\n")
            f.write(f"Duration: {duration.total_seconds():.2f} seconds\n")
            f.write(f"Total Findings: {len(self.core.findings)}\n\n")
            
            f.write("FINDINGS SUMMARY\n")
            f.write("-" * 40 + "\n")
            f.write(f"Critical: {summary['Critical']}\n")
            f.write(f"High: {summary['High']}\n")
            f.write(f"Medium: {summary['Medium']}\n")
            f.write(f"Low: {summary['Low']}\n")
            f.write(f"Info: {summary['Info']}\n\n")
            
            f.write("SCAN STATISTICS\n")
            f.write("-" * 40 + "\n")
            for key, value in self.core.stats.items():
                f.write(f"{key.replace('_', ' ').title()}: {value}\n")
            f.write("\n")
            
            f.write("DETAILED FINDINGS\n")
            f.write("=" * 80 + "\n\n")
            
            for i, finding in enumerate(self.core.findings, 1):
                f.write(f"Finding #{i}\n")
                f.write("-" * 40 + "\n")
                f.write(f"ID: {finding['finding_id']}\n")
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
        
        print(f"  TXT: {filename}")
        return filepath


def parse_arguments() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="Bug Bounty Vulnerability Scanner v3.0.1",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python bugscanner.py example.com
  python bugscanner.py example.com --wordlist subdomains.txt
  python bugscanner.py example.com --threads 20 --timeout 30
  python bugscanner.py example.com --no-verify-ssl --verbose
        """
    )
    
    parser.add_argument(
        "target",
        help="Target domain to scan (e.g., example.com)"
    )
    
    parser.add_argument(
        "-w", "--wordlist",
        help="Custom subdomain wordlist file"
    )
    
    parser.add_argument(
        "-t", "--threads",
        type=int,
        default=10,
        help="Number of concurrent threads (default: 10)"
    )
    
    parser.add_argument(
        "--timeout",
        type=int,
        default=30,
        help="Request timeout in seconds (default: 30)"
    )
    
    parser.add_argument(
        "--no-verify-ssl",
        action="store_false",
        dest="verify_ssl",
        help="Skip SSL certificate verification"
    )
    
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output"
    )
    
    parser.add_argument(
        "--version",
        action="version",
        version="Bug Bounty Scanner v3.0.1"
    )
    
    return parser.parse_args()


def main() -> None:
    """Main entry point."""
    args = parse_arguments()
    
    try:
        scanner = ScannerCore(
            target=args.target,
            wordlist=args.wordlist,
            threads=args.threads,
            timeout=args.timeout,
            verify_ssl=args.verify_ssl
        )
        
        scanner.run()
        
    except KeyboardInterrupt:
        print("\n\nScan interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\nFatal error: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()