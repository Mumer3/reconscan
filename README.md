<div align="center">

```
██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗    ███████╗ ██████╗  █████╗ ███╗   ██╗
██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║    ██╔════╝██╔════╝ ██╔══██╗████╗  ██║
██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║    ███████╗██║      ███████║██╔██╗ ██║
██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║    ╚════██║██║      ██╔══██║██║╚██╗██║
██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║    ███████║╚██████╗ ██║  ██║██║ ╚████║
╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝    ╚══════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═══╝
```

**Advanced Domain Reconnaissance & Network Mapping Tool**

![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=flat-square&logo=python)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=flat-square)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey?style=flat-square)

*A real-world-grade passive & active recon tool for security researchers and penetration testers.*

</div>

---

## ⚠️ Legal Disclaimer

> **This tool is intended for authorized security testing and educational purposes only.**
> Running reconnaissance against domains you do not own or have **explicit written permission** to test is illegal in most jurisdictions. The author is not responsible for any misuse or damage caused by this tool. Always ensure you have proper authorization before scanning any target.

---

## 📖 Table of Contents

- [Overview](#-overview)
- [Features](#-features)
- [How It Works](#-how-it-works)
- [Installation](#-installation)
- [Usage](#-usage)
- [Output](#-output)
- [Configuration](#-configuration)
- [Project Structure](#-project-structure)
- [Contributing](#-contributing)
- [License](#-license)

---

## 🔍 Overview

**ReconScan** is a Python-based domain intelligence and network mapping tool designed for real-world security assessments. It goes far beyond basic subdomain enumeration — it probes live HTTP/S endpoints, inspects TLS certificates, scans for open ports, detects WAF/CDN protection, and fingerprints the technology stack of every discovered subdomain.

Built with concurrent execution and real-world accuracy in mind, ReconScan includes a **wildcard DNS false-positive guard** that prevents the flooding of fake results that plague basic tools.

---

## ✨ Features

| Feature | Description |
|---|---|
| 🌐 **WHOIS / Domain Intelligence** | Registrar, creation/expiry dates, name servers, DNSSEC, status codes |
| 🧩 **Subdomain Discovery** | Wordlist-based enumeration with configurable thread count |
| 🚫 **Wildcard DNS Detection** | Probes a random subdomain first to prevent thousands of false positives |
| 🌍 **IP Geolocation** | Country, city, ASN/ISP via ipinfo.io (no API key required) |
| 🔁 **Reverse DNS** | PTR record lookups for every discovered IP |
| 📋 **Full DNS Record Extraction** | A, AAAA, CNAME, MX, NS, TXT, SOA per subdomain |
| 🌐 **HTTP/S Probing** | Live status codes, page titles, redirect chain tracking |
| 🔒 **TLS Certificate Inspection** | CN, SANs, issuer, expiry, TLS version, cipher suite |
| 🚪 **Port Scanning** | TCP connect scan on 20 common ports per live host |
| 🧱 **WAF / CDN Detection** | Identifies Cloudflare, Akamai, Fastly, AWS CloudFront, Imperva, and more |
| 🖥️ **Technology Fingerprinting** | Detects server software, CMS, and frameworks from HTTP headers |
| 📊 **Multi-format Reporting** | JSON, CSV (Excel-ready), and a dark-themed HTML dashboard |
| 📝 **Audit Logging** | Timestamped `.log` file for every scan session |
| ⚡ **Concurrent Execution** | ThreadPoolExecutor with configurable thread count |

---

## ⚙️ How It Works

```
Target Domain
     │
     ├─► [1] WHOIS Lookup          → Registrar, dates, name servers
     │
     ├─► [2] Root DNS Records       → A, MX, NS, TXT, SOA
     │
     ├─► [3] Wildcard DNS Check     → Guards against false positives
     │
     └─► [4] Subdomain Enumeration (threaded)
                  │
                  ├─► DNS Resolution       → Live IP address
                  ├─► Reverse DNS          → PTR record
                  ├─► IP Geolocation       → Country / City / ASN
                  ├─► Port Scan            → Open TCP ports
                  ├─► HTTP/S Probe         → Status, title, redirects
                  ├─► TLS Inspection       → Certificate details & SANs
                  ├─► WAF/CDN Detection    → Protection layer identification
                  └─► Tech Fingerprinting  → Server, CMS, framework
                  
     └─► [5] Export Results
                  ├─► results.json    (full data)
                  ├─► results.csv     (Excel-ready)
                  └─► report.html     (visual dashboard)
```

---

## 🛠️ Installation

### Prerequisites

- Python **3.8 or higher**
- pip package manager

### Step 1 — Clone the repository

```bash
git clone https://github.com/YOUR_USERNAME/reconscan.git
cd reconscan
```

### Step 2 — Install dependencies

```bash
pip install -r requirements.txt
```

### Step 3 — Add a subdomain wordlist

Place your wordlist at `wordlists/subdomains.txt` (one subdomain prefix per line).

```bash
mkdir wordlists
# Option A: use SecLists (recommended)
curl -o wordlists/subdomains.txt https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt

# Option B: use your own list
echo -e "www\nmail\napi\ndev\nstaging\nadmin" > wordlists/subdomains.txt
```

> If no wordlist is found, the tool falls back to a built-in list of ~50 common subdomains.

---

## 🚀 Usage

### Basic scan

```bash
python recon_tool.py example.com
```

### Interactive mode (prompted input)

```bash
python recon_tool.py
# Enter target domain (example.com): example.com
```

### Example output

```
═══════════════════════════════════════════════════════
  ADVANCED DOMAIN RECON & NETWORK MAPPING TOOL
═══════════════════════════════════════════════════════

[1/5] Collecting WHOIS / Domain Info...
[2/5] Fetching root DNS records...
      Root IP: 93.184.216.34
[3/5] Checking for wildcard DNS (false-positive guard)...
[4/5] Scanning 5000 subdomains with 25 threads...

[FOUND] api.example.com → 93.184.216.34
  ↳ Location : US / Los Angeles
  ↳ Provider : AS15133 MCI Communications
  ↳ Ports    : [80, 443]
  ↳ TLS CN   : *.example.com (expires Sep 15 00:00:00 2025 GMT)
  ↳ HTTP     : HTTPS:200
  ↳ Title    : Example API Gateway
  ↳ Tech     : Server=nginx/1.24.0

[FOUND] mail.example.com → 93.184.216.100
  ↳ Location : US / Ashburn
  ↳ Provider : AS14618 Amazon.com Inc.
  ↳ Ports    : [25, 80, 443, 587]
  ↳ HTTP     : HTTPS:301 | HTTP:301
  ↳ WAF/CDN  : Cloudflare
```

---

## 📂 Output

All results are saved to the `output/` directory after each scan.

| File | Format | Contents |
|---|---|---|
| `results.json` | JSON | Complete structured data for all subdomains |
| `results.csv` | CSV | Flat table — open directly in Excel or Google Sheets |
| `report.html` | HTML | Dark-themed visual dashboard with summary stats |
| `recon_YYYYMMDD_HHMMSS.log` | Log | Full audit trail of the scan session |

### HTML Report Preview

The HTML report includes:
- **Summary cards** — total subdomains, live HTTP endpoints, TLS count, WAF/CDN count
- **WHOIS panel** — registrar, dates, name servers
- **Full results table** — sortable, color-coded, with WAF highlighted in red and wildcard matches in yellow

---

## 🔧 Configuration

Edit the constants at the top of `recon_tool.py` to customize behavior:

```python
THREADS      = 25      # Concurrent threads (increase for faster scans, be mindful of rate limits)
TIMEOUT      = 5       # Seconds per network call
MAX_RETRIES  = 2       # Retry attempts on failure
WORDLIST     = "wordlists/subdomains.txt"
OUTPUT_DIR   = "output"

# Ports to scan per discovered subdomain
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445,
                3306, 3389, 5432, 6379, 8080, 8443, 8888, 9200, 27017]
```

---

## 📁 Project Structure

```
reconscan/
├── recon_tool.py          # Main tool
├── requirements.txt       # Python dependencies
├── README.md              # This file
├── wordlists/
│   └── subdomains.txt     # Your subdomain wordlist (add manually)
└── output/                # Auto-created on first run
    ├── results.json
    ├── results.csv
    ├── report.html
    └── recon_*.log
```

---

## 📦 Dependencies

| Package | Purpose |
|---|---|
| `dnspython` | DNS record resolution |
| `requests` | HTTP probing & geolocation API |
| `python-whois` | WHOIS / domain registration data |
| `colorama` | Cross-platform terminal colors |

---

<div align="center">

Built for security researchers · Use responsibly · Happy hunting 🎯

</div>
