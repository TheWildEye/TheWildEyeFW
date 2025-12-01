# 🐯 TheWildEye  
### Unified Reconnaissance & OSINT Framework  
**Developer:** Vyom Nagpal

---

## ⚡ Overview

TheWildEye is a **Unified Reconnaissance and OSINT Framework**  
It unifies multiple offensive security tools into a single cross-platform command-line interface, enabling fast and automated reconnaissance for:

- Penetration Testing  
- Bug Bounty Recon  
- Threat Intelligence  
- OSINT
- Red Teaming

The entire framework runs on **Kali Linux, ParrotOS, Ubuntu, Windows 10/11, and Termux** without modification.

---

## ⚡ Features

### 1. 🕵️ TigerCrawler – Email Intelligence Harvester  
Source: `TigerCrawler.py`  
- Multithreaded email-focused crawler  
- Extracts valid email patterns using strict regex  
- Filters image-like false positives  
- Crawls up to 100 URLs using parallel workers  
- Normalizes absolute & relative URLs  
- Real-time URL processing feed  
- Uses persistent HTTP sessions for improved speed

---

### 2. 🐅 TigerHunt – Directory & File Bruteforcer  
Source: `tigbuster.py`  
- High-speed multithreaded directory enumeration  
- Live ETA, status tracking, and colored output
- Detects 200/301/302/403/404 and other statuses
- Redirect handling and redirecting links
- Uses `wordlists/common.txt` or personal dictionary for directory brute-force  
- Final tabular results for discovered directories  
- Clean CLI optimized for reconnaissance workflows

---

### 3. 🔎 TigerWP – WordPress Recon Scanner  
Source: `wp_enum.py`  
- Detects exposed REST API users  
- Extracts meta tags, OG tags, authors, JSON-LD  
- Identifies themes and plugins via HTML path detection  
- Parses `style.css` for theme metadata  
- Fetches `robots.txt` and common sitemap locations  
- Extracts SSL CN & SAN details automatically  
- Useful for WordPress footprinting during recon

---

### 4. 🌐 WHOIS Recon Engine  
Source: `whois.py`  
- Multi-server WHOIS querying (with referral follow-up)  
- Extracts domain registrar data, expiry, nameservers  
- Retrieves A and AAAA DNS records  
- Performs reverse DNS lookups  
- Extracts SSL certificates (CN and SAN)  

---

### 5. 👨🏻‍💻 TheWildEye Launcher  
Source: `TheWildEye.py`  
- Unified launcher for all modules  
- Detects missing scripts before execution  
- Executes tools via Python subprocess  
- Modern ANSI banner and clean interface  
- Fully cross-platform architecture

---

## 🛠️ Installation

### Requirements
- Python 3.8+  
- pip package manager

### Install Dependencies
```
pip install requests bs4 lxml
```

### Clone the Repository
```
git clone https://github.com/TheWildEye/TheWildEye
cd TheWildEye
```

---

## ⚡ Usage

### Launch the Framework
```
python TheWildEye.py
```

### Run Tools Individually
```
python TigerCrawler.py
python tigbuster.py
python wp_enum.py
python whois.py
```

---

## 💻 Cross-Platform Support

Fully supported operating systems:
- Linux (Kali, ParrotOS, Ubuntu)  
- Windows 10/11  
- Termux (Android)

The project uses relative paths and Python standard libraries, ensuring OS independence.

---

## 📁 Project Structure

```
TheWildEye/
│
├── TheWildEye.py
├── TigerCrawler.py
├── tigbuster.py
├── wp_enum.py
├── whois.py
│
└── wordlists/
    ├── rockyou.txt 
    └── common.txt
```
rockyou.txt Download Link - ( Download Link - https://weakpass.com/download/90/rockyou.txt.gz )

## 👨‍💻 Author
**Vyom Nagpal**  
Cyber Security Researcher & Enthusiast
