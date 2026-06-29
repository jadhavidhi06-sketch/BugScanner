<div align="center">

# 🛡️ Bug Bounty Vulnerability Scanner

### Comprehensive Vulnerability Scanner for **Authorized Security Testing** & **Bug Bounty Hunting**

<img src="https://img.shields.io/badge/Python-3.7+-blue.svg">
<img src="https://img.shields.io/badge/License-Educational-green.svg">
<img src="https://img.shields.io/badge/Security-Bug%20Bounty-red.svg">
<img src="https://img.shields.io/badge/Status-Stable-success.svg">
<img src="https://img.shields.io/badge/Maintained-Yes-brightgreen.svg">

---

**Professional vulnerability scanner built for ethical hackers, penetration testers, and bug bounty hunters.**

Designed to automate reconnaissance, identify common web vulnerabilities, analyze security misconfigurations, and generate detailed professional reports.

> ⚠️ **For Authorized Security Testing Only**

</div>

---

# 📖 Table of Contents

- Overview
- Features
- Scanner Workflow
- Installation
- Usage
- Sample Output
- Report Format
- Severity Levels
- Project Structure
- Proof of Authorization
- Best Practices
- Troubleshooting
- Roadmap
- Contributing
- License
- Disclaimer

---

# 🚀 Overview

Bug Bounty Vulnerability Scanner is an automated reconnaissance and vulnerability assessment tool developed specifically for:

- Bug Bounty Hunters
- Penetration Testers
- Security Researchers
- Red Team Professionals
- Ethical Hackers

The scanner performs multiple phases of security assessment including:

- DNS Enumeration
- Network Reconnaissance
- Security Header Analysis
- SSL/TLS Inspection
- Sensitive File Discovery
- Parameter Fuzzing
- Open Redirect Detection
- Professional Report Generation

The tool focuses on providing actionable findings while following responsible disclosure practices.

---

# ✨ Features

## 🌐 Target Reconnaissance

Automatically performs:

- DNS Record Enumeration
  - A Records
  - MX Records
  - NS Records
  - TXT Records

- IP Address Resolution

- Subdomain Enumeration
  - Built-in Wordlist
  - Custom Wordlist Support

- Common Port Scanning

Supported Ports:

```

21
22
80
443
8080
8443

```

---

## 🔒 Security Header Analysis

Detects missing or misconfigured HTTP Security Headers.

### Headers Checked

| Header | Severity |
|---------|-----------|
| Strict-Transport-Security | High |
| Content-Security-Policy | High |
| X-Frame-Options | Medium |
| X-Content-Type-Options | Medium |
| Referrer-Policy | Low |
| Permissions-Policy | Low |

---

## 🔐 SSL/TLS Analysis

Performs SSL inspection including:

- Certificate Information
- Certificate Expiration
- Self-Signed Certificate Detection
- Weak Cipher Detection
- Weak TLS Version Detection

Checks for:

- SSLv2
- SSLv3
- TLS 1.0

---

## 📂 Sensitive File Discovery

Scans over **30+** common sensitive paths.

Examples include:

```

/robots.txt
/.git/
/.env
/.svn/
/backup.zip
/config.php
/admin/
/phpinfo.php
/.DS_Store
/.htaccess

```

Each accessible resource is verified and categorized based on severity.

---

## 💉 Parameter Fuzzing

Automatically tests for common web vulnerabilities.

### SQL Injection

Example Payloads

```

'
"
' OR '1'='1
admin'--

````

### Cross Site Scripting (XSS)

Example Payloads

```html
<script>alert(1)</script>

"><svg/onload=alert(1)>

"><img src=x onerror=alert(1)>
````

Response behavior is analyzed for possible indicators of vulnerability.

---

## 🔄 Open Redirect Detection

Tests common redirect parameters including:

```
redirect
next
url
return
continue
target
```

Validates whether external URLs are improperly accepted.

---

## 📊 Professional Report Generation

Automatically generates reports in:

* JSON
* TXT

Each report contains:

* Findings
* Severity
* Description
* Evidence
* Recommendation
* Timestamp
* Scan Metadata

---

# 🔍 Scanner Workflow

```
Target
   │
   ▼
DNS Enumeration
   │
   ▼
IP Resolution
   │
   ▼
Subdomain Discovery
   │
   ▼
Port Scan
   │
   ▼
Security Header Scan
   │
   ▼
SSL Analysis
   │
   ▼
Sensitive File Discovery
   │
   ▼
Parameter Fuzzing
   │
   ▼
Open Redirect Testing
   │
   ▼
Professional Report
```

---

# ⚙️ Installation

## Requirements

* Python 3.7+
* pip

---

## Clone Repository

```bash
git clone https://github.com/yourusername/bugbounty-scanner.git

cd bugbounty-scanner
```

---

## Install Dependencies

```bash
pip install requests dnspython
```

---

## Verify Installation

```bash
python -c "import requests,dns,ssl,socket,json;print('Installation Successful')"
```

---

# 🚀 Usage

## Basic Scan

```bash
python bugscanner.py target.com
```

---

## Using Custom Wordlist

```bash
python bugscanner.py target.com wordlist.txt
```

---

## Linux / macOS

```bash
chmod +x bugscanner.py

./bugscanner.py target.com
```

---

# 📷 Example Output

```
══════════════════════════════════════════════

 Bug Bounty Vulnerability Scanner v1.0

══════════════════════════════════════════════

[+] DNS Enumeration

✔ A Records Found

✔ MX Records Found

✔ TXT Records Found

[+] Resolving Target

✔ IP: 93.184.216.34

[+] Subdomain Enumeration

✔ www.target.com

✔ mail.target.com

✔ api.target.com

[+] Port Scan

✔ Port 80 Open

✔ Port 443 Open

[+] Security Headers

✘ Missing CSP

✘ Missing HSTS

✔ X-Frame-Options Present

[+] SSL Analysis

✔ Certificate Valid

✘ TLS 1.0 Enabled

[+] Sensitive Files

✔ robots.txt

✘ .env Accessible

[+] Parameter Fuzzing

✔ No SQL Injection Detected

✔ Reflected XSS Detected

[+] Report Generated

bugbounty_report_target.com.json

bugbounty_report_target.com.txt
```

---

# 📑 Report Structure

## JSON

```json
{
  "scan_metadata": {},
  "summary": {},
  "findings": []
}
```

Each finding includes:

* Category
* Severity
* Title
* Description
* Evidence
* Recommendation
* Timestamp

---

# 🚨 Severity Classification

| Severity    | Description                     |
| ----------- | ------------------------------- |
| 🔴 Critical | Immediate exploitation possible |
| 🟠 High     | Serious security issue          |
| 🟡 Medium   | Moderate risk                   |
| 🔵 Low      | Minor weakness                  |
| ⚪ Info      | Informational                   |

---

# 📁 Project Structure

```
bugbounty-scanner/

│

├── bugscanner.py

├── wordlists/

│ └── subdomains.txt

├── reports/

│ ├── report.json

│ └── report.txt

├── README.md

├── requirements.txt

└── LICENSE
```

---

# 📝 Proof of Authorization

Before scanning any target, ensure you have:

✅ Written authorization

✅ Active Bug Bounty Scope

✅ Program Rules

✅ Scope Documentation

✅ Responsible Disclosure Contact

Never scan systems outside your authorization.

---

# 💡 Best Practices

* Perform reconnaissance before active testing.
* Respect target rate limits.
* Keep detailed logs.
* Manually verify findings.
* Follow responsible disclosure policies.
* Stay within the defined bug bounty scope.
* Avoid disruptive testing techniques.

---

# 🛠 Troubleshooting

## Module Not Found

```bash
pip install requests dnspython
```

---

## SSL Errors

Ensure the target supports HTTPS and that you are scanning an authorized system.

---

## Slow Enumeration

Use a smaller custom wordlist or reduce concurrent threads.

---

# 🗺️ Roadmap

Upcoming features include:

* [ ] Multi-threaded crawler
* [ ] JavaScript endpoint discovery
* [ ] Directory brute forcing
* [ ] CVE fingerprinting
* [ ] Technology detection
* [ ] WAF detection
* [ ] Screenshot capture
* [ ] HTML report generation
* [ ] PDF report export
* [ ] Nmap integration
* [ ] Shodan integration
* [ ] Censys integration
* [ ] GitHub secret detection
* [ ] Wayback Machine enumeration
* [ ] Passive reconnaissance mode
* [ ] API Security Testing
* [ ] GraphQL Scanner

---

# 🤝 Contributing

Contributions are welcome!

Please ensure:

* Code follows ethical standards.
* Features are documented.
* Tests are included.
* Pull Requests remain focused.
* Existing coding style is maintained.

---

# 📜 License

This project is provided for:

* Educational Purposes
* Authorized Penetration Testing
* Responsible Bug Bounty Research

Refer to the LICENSE file for details.

---

# ⚠️ Legal Disclaimer

> **This tool is intended exclusively for authorized security testing and educational purposes.**

By using this software you agree that:

* You will only scan systems you own or have explicit written permission to test.
* You will comply with all applicable laws and regulations.
* You accept full responsibility for your actions.
* The developers assume no liability for misuse or damage caused by this software.

Unauthorized scanning of systems may be illegal and could result in civil or criminal penalties.

---

<div align="center">

## ⭐ If this project helped you, consider giving it a star!

**Happy Hunting • Stay Ethical • Hack Responsibly**

🛡️ Built for the Bug Bounty Community

</div>

