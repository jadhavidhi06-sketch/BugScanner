# Bug Bounty Vulnerability Scanner

A comprehensive vulnerability scanner designed for authorized bug bounty hunting and security testing.

## ⚠️ Legal Disclaimer

**IMPORTANT**: This tool is for authorized security testing only. You must:
- Only scan targets you own or have explicit written permission to test
- Only use against targets listed in active bug bounty programs (HackerOne, Bugcrowd, etc.)
- Submit proof of authorization with your bug bounty report
- Comply with all applicable laws and regulations

Unauthorized use of this tool is illegal and unethical.

## Features

1. **Target Reconnaissance**
   - DNS record enumeration (A, MX, NS, TXT)
   - IP address resolution
   - Subdomain enumeration with wordlist support
   - Common port scanning (80, 443, 8080, 8443, 21, 22)

2. **Security Headers Analysis**
   - Checks for missing security headers
   - Severity classification (High, Medium, Low)
   - Headers checked: HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy

3. **SSL/TLS Analysis**
   - Certificate details extraction
   - Expired/self-signed certificate detection
   - Weak protocol detection (SSLv2, SSLv3, TLS 1.0)

4. **Sensitive Files Discovery**
   - Checks 30+ common sensitive paths
   - Status code verification
   - Severity-based flagging

5. **Parameter Fuzzing**
   - SQL injection payload testing
   - XSS payload testing
   - Response analysis for vulnerabilities

6. **Open Redirect Detection**
   - Tests common redirect parameters
   - External URL redirect verification

7. **Professional Report Generation**
   - JSON format for programmatic use
   - TXT format for human readability
   - Detailed findings with severity and recommendations

## Installation

### Prerequisites
- Python 3.7 or higher
- pip (Python package manager)

### Step 1: Clone or Download
```bash
git clone https://github.com/yourusername/bugbounty-scanner.git
cd bugbounty-scanner

Step 2: Install Dependencies
bash

Copy

pip install requests dnspython
Step 3: Verify Installation
bash

Copy

python -c "import requests, dns, ssl, socket, json; print('All dependencies installed successfully')"
Usage
Basic Usage
bash

Copy

python bugscanner.py example.com
With Custom Wordlist
bash

Copy

python bugscanner.py example.com subdomains.txt
Example Output
text

Copy

    ╔══════════════════════════════════════════════╗
    ║     Bug Bounty Vulnerability Scanner v1.0    ║
    ║         For Authorized Testing Only          ║
    ╚══════════════════════════════════════════════╝

[!] IMPORTANT: Only scan targets you are authorized to test!
[!] This tool must only be used against authorized targets.

[+] Performing DNS Reconnaissance...
[Info] A Records Found: Found 2 A records for example.com
[Info] MX Records Found: Found 1 MX records for example.com

[+] Resolving IP Address...
[Info] IP Address Resolved: Target example.com resolves to 93.184.216.34

[+] Enumerating Subdomains...
  [+] Found subdomain: www.example.com
  [+] Found subdomain: mail.example.com
[Info] Found 2 Subdomains

[+] Scanning Common Ports...
  [+] Port 80 is open
  [+] Port 443 is open
[Medium] Found 2 Open Ports

[+] Analyzing Security Headers...
[High] Missing Strict-Transport-Security Header
[High] Missing Content-Security-Policy Header
[Medium] Missing X-Frame-Options Header

[+] Analyzing SSL/TLS Configuration...
[Info] SSL Certificate Details
[High] Weak SSL/TLS Protocols Detected

[+] Discovering Sensitive Files...
  [+] Found accessible path: /robots.txt (Status: 200)
[High] Sensitive Path Accessible: /robots.txt

[+] Fuzzing Parameters...
[!] No parameters found in initial page

[+] Checking Open Redirects...
[!] No open redirects found

[+] Generating Report...
  [+] Report saved to bugbounty_report_example.com_20240101_120000.json
  [+] Report saved to bugbounty_report_example.com_20240101_120000.txt

============================================================
SCAN COMPLETED
Total Findings: 12
============================================================
Report Format
JSON Report Structure
json

Copy

{
  "scan_metadata": {
    "tool": "Bug Bounty Vulnerability Scanner",
    "version": "1.0",
    "target_domain": "example.com",
    "scan_timestamp": "2024-01-01T12:00:00",
    "total_findings": 12
  },
  "summary": {
    "critical": 0,
    "high": 4,
    "medium": 3,
    "low": 2,
    "info": 3
  },
  "findings": [
    {
      "category": "Security Headers",
      "severity": "High",
      "title": "Missing Strict-Transport-Security Header",
      "description": "The Strict-Transport-Security header is not present...",
      "recommendation": "Implement the HSTS header...",
      "evidence": "Response headers: {...}",
      "timestamp": "2024-01-01T12:00:05"
    }
  ]
}
Proof of Authorization
Before running any scan, ensure you have:

Written authorization from the target organization
Confirmation the target is in an active bug bounty program
Documentation of scope limitations
Contact information for vulnerability disclosure
Include this proof with your bug bounty report submission.

Best Practices
Start with reconnaissance - Understand the target before scanning
Respect rate limits - Don't overwhelm target servers
Document everything - Keep detailed logs of your testing
Verify findings - Manually confirm automated findings
Responsible disclosure - Follow the program's disclosure policy
Troubleshooting
Common Issues
Issue: "Module not found" errors
Solution: Run pip install requests dnspython

Issue: SSL certificate verification errors
Solution: The tool uses verify=False for testing; ensure you're on authorized targets

Issue: Slow subdomain enumeration
Solution: Provide a smaller, targeted wordlist or increase thread count

License
This tool is for educational and authorized security testing purposes only.

Contributing
Contributions are welcome! Please ensure:

All code follows ethical guidelines
Features are documented
Tests are included
Support
For issues or questions:

Check the troubleshooting section
Review the code documentation
Submit issues on GitHub
Remember: With great power comes great responsibility. Use this tool ethically and legally.

text

Copy


## Installation Instructions

```bash
# Install Python dependencies
pip install requests dnspython

# Make the script executable (Linux/Mac)
chmod +x bugscanner.py

# Run the scanner
python bugscanner.py target.com

# Or with a custom subdomain wordlist
python bugscanner.py target.com my_wordlist.txt
This complete implementation includes:

All 7 requested features with proper implementation
Threading for efficient scanning
Professional reporting in both JSON and TXT formats
Comprehensive error handling
Legal disclaimers and authorization requirements
Detailed README with installation, usage, and examples
Default wordlist with 200+ common subdomains
Severity classification for all findings
Evidence collection for each finding
Timestamp tracking for all operations
The tool is production-ready and follows bug bounty best practices. Remember to only use it against authorized targets!
