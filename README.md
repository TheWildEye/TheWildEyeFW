# TheWildEye

Unified reconnaissance and OSINT framework. JavaScript rendering via Playwright, API endpoint discovery via browser network capture + OpenAPI + JS static analysis + pattern inference, directory discovery without wordlist bruteforce, subdomain enumeration, technology fingerprinting, WHOIS recon, WAF detection, and Google dork generation.

## Installation

```
pip install -r requirements.txt
playwright install chromium
```

## Usage

Interactive menu:

```
python TheWildEye.py
```

Direct CLI mode:

```
python TheWildEye.py <module> <target>
```

Run all modules sequentially (press `s` to skip, `q` to quit):

```
python TheWildEye.py
Select: 11
```

## Modules

| Module | Target | Description |
|--------|--------|-------------|
| crawlerhunter | URL | Web crawler with Playwright JS rendering, SPA detection, form/email/API extraction |
| dirhunter | URL | Smart directory discovery via robots.txt + sitemap + common paths. SPA false positive filter. No wordlist bruteforce |
| apifuzzhunter | URL | API endpoint discovery via browser network capture + OpenAPI + JS analysis + pattern fuzzing |
| jsreaphunter | URL | JavaScript static analysis: endpoints, secrets/keys, SPA routes, source maps |
| techhunter | URL | Technology fingerprinting: CMS, frameworks, libraries via headers/cookies/HTML |
| wphunter | URL | WordPress vulnerability scanner: user enumeration, plugin/theme detection |
| whoishunter | Domain | WHOIS lookup, DNS A/AAAA/MX records, SSL certificate, reverse DNS |
| wafhunter | URL | Web firewall detection via active probes and SSL fingerprinting |
| subhunter | Domain | Subdomain enumeration via crt.sh, AlienVault OTX, UrlScan.io, DNS bruteforce |
| dorkhunter | Domain | Google dork generator: 60 dorks across 11 categories |

## Cross-Platform

Windows 10/11, Kali Linux, Ubuntu, macOS, Termux. ANSI colors auto-disable on dumb terminals or when NO_COLOR is set.

## Requirements

Python 3.8+. Run `pip install -r requirements.txt` (requests, beautifulsoup4, lxml, playwright, aiohttp, PyYAML, tqdm, colorama). Playwright Chromium required for JS rendering: `playwright install chromium`.

## Legal

For authorized security testing only. Users must have explicit written permission before testing any system.
