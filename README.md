# � TheWildEye

<div align="center">

**Unified Reconnaissance & OSINT Framework**

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/downloads/)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Windows%20%7C%20Termux-lightgrey.svg)](#)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](#)

*Fast, automated reconnaissance for penetration testing, bug bounty hunting, and OSINT*

[Features](#-features) • [Installation](#-installation) • [Usage](#-usage) • [Modules](#-modules) • [Cross-Platform](#-cross-platform)

</div>

---

## 📋 Overview

**TheWildEye** is a unified reconnaissance and OSINT framework that consolidates multiple offensive security tools into a single cross-platform command-line interface.

### Use Cases
- 🎯 Penetration Testing
- 💰 Bug Bounty Reconnaissance
- 🔍 Threat Intelligence
- 🕵️ OSINT Investigations
- 🔴 Red Team Operations

### Platform Support
Runs natively on **Kali Linux, ParrotOS, Ubuntu, Windows 10/11, and Termux** without modification.

---

## ⚡ Features

### 🕵️ **TigerCrawler** – Email Intelligence Harvester
*Source: `TigerCrawler.py`*

- Multithreaded email-focused web crawler
- Strict regex validation for email extraction
- Filters false positives (image URLs, etc.)
- Crawls up to 100 URLs with parallel workers
- URL normalization (absolute & relative)
- Real-time processing feed
- Persistent HTTP sessions for speed

---

### � **TigerHunt** – Directory & File Bruteforcer
*Source: `tigbuster.py`*

- High-speed multithreaded enumeration
- Live ETA and status tracking
- Detects `200`, `301`, `302`, `403`, `404` status codes
- Redirect handling and link extraction
- Custom wordlist support (`wordlists/common.txt`)
- Tabular result output
- Clean CLI interface

---

### 🔎 **TigerWP** – WordPress Reconnaissance Scanner
*Source: `wp_enum.py`*

- REST API user enumeration
- Meta tag extraction (OG tags, JSON-LD)
- Theme and plugin detection via HTML paths
- Parses `style.css` for theme metadata
- Fetches `robots.txt` and sitemaps
- SSL certificate analysis (CN & SAN)
- WordPress footprinting automation

---

### 🌐 **WHOIS Recon Engine**
*Source: `whois.py`*

- Multi-server WHOIS queries with referral follow-up
- Domain registrar, expiry, and nameserver extraction
- A and AAAA DNS record retrieval
- Reverse DNS lookups
- SSL certificate extraction (CN and SAN)

---

### � **WAFHunter** – Web Application Firewall Detector
*Source: `firewall.py`*

- Multi-vendor WAF detection (Cloudflare, AWS WAF, Fortinet, Sophos)
- Active HTTP probing with malicious payloads (XSS, SQLi)
- Passive SSL/TLS certificate analysis
- Weighted scoring algorithm for accuracy
- Detects suspicious status codes (403, 406, 429, 501, 503)
- DNS resolution and certificate SAN extraction

---

### �👨‍💻 **TheWildEye Launcher**
*Source: `TheWildEye.py`*

- Unified module launcher
- Pre-execution script detection
- Python subprocess execution
- Modern ANSI banner
- Cross-platform architecture

---

## �️ Installation

### Prerequisites
- Python 3.8 or higher
- pip package manager

### Install Dependencies
```bash
pip install -r requirements.txt
```

Or install manually:
```bash
pip install requests beautifulsoup4 lxml
```

### Clone the Repository
```bash
git clone https://github.com/TheWildEye/TheWildEye.git
cd TheWildEye
```

---

## 💻 Usage

### Quick Start

Run the unified launcher to access all modules:

**Windows (CMD/PowerShell):**
```cmd
python TheWildEye.py
```

**Linux/macOS/Termux:**
```bash
python3 TheWildEye.py
```

The launcher will present a menu where you can select any module:
```
1) TheCrawler      - Email Intelligence Harvester
2) DirHunter       - Directory & File Bruteforcer  
3) WPHunter        - WordPress Recon Scanner
4) WhoisHunt       - WHOIS Recon Engine
5) WAFHunter       - WAF Detection Tool
0) Exit
```

### Advanced: Running Modules Directly

For advanced users, modules can be run independently:
```bash
python TigerCrawler.py    # Email Harvester
python tigbuster.py       # Directory Bruteforcer
python wp_enum.py         # WordPress Scanner
python whois.py           # WHOIS Recon
python firewall.py        # WAF Detector
```

---

## 🌍 Cross-Platform

Fully supported operating systems:

| OS | Status |
|---|---|
| **Kali Linux** | ✅ Native |
| **ParrotOS** | ✅ Native |
| **Ubuntu** | ✅ Native |
| **Windows 10/11** | ✅ Native |
| **Termux (Android)** | ✅ Native |

Uses relative paths and Python standard libraries for OS independence.

---

## 📁 Project Structure

```
TheWildEye/
│
├── TheWildEye.py          # Main launcher
├── TigerCrawler.py        # Email harvester
├── tigbuster.py           # Directory bruteforcer
├── wp_enum.py             # WordPress scanner
├── whois.py               # WHOIS engine
├── firewall.py            # WAF detector
├── DirectCrawler.py       # Alternative email crawler
│
└── wordlists/
    ├── common.txt         # Directory wordlist
    └── rockyou.txt        # Password list
```

### Wordlist Downloads

**RockYou.txt** (required for some modules):
```bash
wget https://weakpass.com/download/90/rockyou.txt.gz
gunzip rockyou.txt.gz
mv rockyou.txt wordlists/
```
---

## ⚠️ Legal Disclaimer

**For authorized security testing only.**

This framework is designed for legitimate penetration testing, bug bounty hunting, and authorized security research. Users must:

- ✅ Only test systems you own or have explicit written permission to test
- ✅ Comply with all local and international laws
- ✅ Respect rate limits and terms of service
- ❌ Never use for unauthorized access or malicious purposes

**The author is not responsible for misuse of this tool.**

---

## 👨‍💻 Author

**Vyom Nagpal**  
*Cyber Security Researcher & Enthusiast*

---


<div align="center">

**Developed for the security community**

⭐ Star this repository if you find it useful!

</div>
