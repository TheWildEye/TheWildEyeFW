import requests
from urllib.parse import urljoin, urlparse
import re
import ssl
import socket


HEADERS = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'}
TIMEOUT = 6

BANNER = r"""
$$\      $$\ $$$$$$$\  $$\   $$\                      $$\                         
$$ | $\  $$ |$$  __$$\ $$ |  $$ |                     $$ |                        
$$ |$$$\ $$ |$$ |  $$ |$$ |  $$ |$$\   $$\ $$$$$$$\ $$$$$$\    $$$$$$\   $$$$$$\  
$$ $$ $$\$$ |$$$$$$$  |$$$$$$$$ |$$ |  $$ |$$  __$$\\_$$  _|  $$  __$$\ $$  __$$\ 
$$$$  _$$$$ |$$  ____/ $$  __$$ |$$ |  $$ |$$ |  $$ | $$ |    $$$$$$$$ |$$ |  \__|
$$$  / \$$$ |$$ |      $$ |  $$ |$$ |  $$ |$$ |  $$ | $$ |$$\ $$   ____|$$ |      
$$  /   \$$ |$$ |      $$ |  $$ |\$$$$$$  |$$ |  $$ | \$$$$  |\$$$$$$$\ $$ |      
\__/     \__|\__|      \__|  \__| \______/ \__|  \__|  \____/  \_______|\__|      
                                                                                                                                                                                                                                                     
WORDPRESS ENUM & HUNT
UNIFIED RECONNAISSANCE & OSINT FRAMEWORK - VYOM NAGPAL

"""

def show_banner():
    print("\033[92m" + BANNER + "\033[0m")

def normalize_base(url):
    if not url:
        return None
    parsed = urlparse(url)
    if not parsed.scheme:
        url = "https://" + url
        parsed = urlparse(url)
    base = parsed.scheme + "://" + parsed.netloc
    return base.rstrip("/")

def safe_get(url, allow_redirects=True):
    try:
        return requests.get(url, headers=HEADERS, timeout=TIMEOUT, allow_redirects=allow_redirects)
    except Exception:
        return None

def check_rest_users(base):
    api = urljoin(base + "/", "wp-json/wp/v2/users")
    resp = safe_get(api)
    if resp is None:
        print(f"[-] REST API request failed: {resp}")
        return False
    if resp.status_code == 200:
        try:
            users = resp.json()
            if isinstance(users, list) and users:
                print("\n[+] REST API: Users endpoint exposed:")
                for u in users:
                    name = u.get('name') or 'N/A'
                    slug = u.get('slug') or 'N/A'
                    print(f"    - {name} (username/slug: {slug})")
                return True
            else:
                print("[-] REST API returned empty/restricted list.")
                return False
        except Exception as e:
            print(f"[-] REST API returned 200 but JSON parse failed: {e}")
            return False
    elif resp.status_code == 403:
        print("[-] REST API blocked (403).")
    elif resp.status_code == 404:
        print("[-] REST API endpoint not found (404).")
    else:
        print(f"[-] REST API returned status: {resp.status_code}")
    return False

def fetch_home_meta(base):
    print("\n[*] Fetching home page meta (title / author / OG site_name / JSON-LD):")
    resp = safe_get(base + "/")
    if resp is None or resp.status_code != 200:
        print(f"[-] Could not fetch home page (status: {getattr(resp, 'status_code', 'error')})")
        return False
    text = resp.text
    found = False
    m = re.search(r'<title>([^<]+)</title>', text, re.I)
    if m:
        print(f"    - Title: {m.group(1).strip()}")
        found = True
    m = re.search(r'<meta[^>]+name=["\']author["\'][^>]+content=["\']([^"\']+)["\']', text, re.I)
    if m:
        print(f"    - Meta author: {m.group(1).strip()}")
        found = True
    m = re.search(r'<meta[^>]+property=["\']og:site_name["\'][^>]+content=["\']([^"\']+)["\']', text, re.I)
    if m:
        print(f"    - OG site_name: {m.group(1).strip()}")
        found = True
    for js in re.finditer(r'<script[^>]+type=["\']application/ld\+json["\'][^>]*>(.*?)</script>', text, re.I | re.S):
        snippet = js.group(1).strip()
        if '"@type"' in snippet and ('Organization' in snippet or 'Person' in snippet or 'publisher' in snippet or 'author' in snippet):
            print("    - JSON-LD snippet found (Organization/Person/Publisher)")
            found = True
            break
    if not found:
        print("    [-] No clear owner/company info found on home page.")
    return found

def detect_theme_plugins(base):
    print("\n[*] Detecting theme and plugin hints from HTML paths:")
    resp = safe_get(base + "/")
    if resp is None or resp.status_code != 200:
        print("    [-] Could not fetch home page.")
        return False
    text = resp.text
    themes = set(re.findall(r'wp-content/themes/([a-z0-9\-_]+)', text, re.I))
    plugins = set(re.findall(r'wp-content/plugins/([a-z0-9\-_]+)', text, re.I))
    if themes:
        print(f"    - Themes detected: {', '.join(sorted(themes))}")
    else:
        print("    - No themes detected in HTML.")
    if plugins:
        print(f"    - Plugin hints: {', '.join(sorted(plugins))}")
    else:
        print("    - No plugin hints detected.")
    if themes:
        theme = sorted(themes)[0]
        style_url = urljoin(base + "/", f"wp-content/themes/{theme}/style.css")
        r2 = safe_get(style_url)
        if not r2 is None and r2.status_code == 200 and 'Theme Name:' in r2.text:
            m = re.search(r'Theme Name:\s*(.+)', r2.text)
            if m:
                print(f"    - Theme '{theme}' details: {m.group(1).strip()}")
    return True

def fetch_robots_and_sitemap(base):
    print("\n[*] Fetching robots.txt and common sitemaps:")
    r = safe_get(urljoin(base + "/", "robots.txt"))
    if not r is None and r.status_code == 200:
        print("    - robots.txt (first 6 lines):")
        for i, line in enumerate(r.text.splitlines()):
            if i >= 6: break
            print("       " + line)
    else:
        print("    - robots.txt not found.")
    for p in ["sitemap.xml", "sitemap_index.xml", "sitemap"]:
        s = safe_get(urljoin(base + "/", p))
        if not s is None and s.status_code == 200 and ('<urlset' in s.text.lower() or 'sitemapindex' in s.text.lower()):
            m = re.search(r'<loc>([^<]+)</loc>', s.text, re.I)
            print(f"    - Sitemap found at /{p} (example: {m.group(1) if m else 'n/a'})")
            return True
    print("    - No sitemap found at common locations.")
    return False

def get_ssl_cert(base):
    host = urlparse(base).hostname
    if not host:
        print("[-] No hostname for SSL.")
        return None
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=host) as sock:
            sock.settimeout(3)
            sock.connect((host, 443))
            cert = sock.getpeercert()
            subject = cert.get('subject', ())
            cn = None
            for t in subject:
                if t and isinstance(t, (list, tuple)) and t[0][0].lower() == 'commonname':
                    cn = t[0][1]
            sans = [v[1] for v in cert.get('subjectAltName', []) if v[0].lower() == 'dns']
            print("\n[*] SSL certificate info:")
            print(f"    - CN: {cn}")
            print(f"    - SANs: {sans}")
            return {"cn": cn, "sans": sans}
    except Exception as e:
        print(f"[-] SSL fetch error: {e}")
        return None

def check_wp_specifics(base):
    print("\n[*] Running WordPress-specific URL Checks:")
    results = {}
    
    # 1. wp-login.php
    login_url = urljoin(base + "/", "wp-login.php")
    r_login = safe_get(login_url, allow_redirects=False)
    if r_login and r_login.status_code in [200, 301, 302]:
        print(f"    - [!] Exposed Login Page: {login_url} (Status: {r_login.status_code})")
        results["wp_login"] = f"Exposed: {login_url} (Status: {r_login.status_code})"
    else:
        print("    - Login page: Not directly exposed or returned error.")
        results["wp_login"] = "Not exposed / custom"

    # 2. xmlrpc.php
    xml_url = urljoin(base + "/", "xmlrpc.php")
    r_xml = safe_get(xml_url)
    # XML-RPC typically returns 405 Method Not Allowed on GET, but with specific body text
    if r_xml and ("XML-RPC server accepts POST requests only." in r_xml.text or r_xml.status_code == 405):
        print(f"    - [!] Exposed XML-RPC Endpoint: {xml_url} (Potential brute force vector)")
        results["xmlrpc"] = f"Exposed: {xml_url}"
    else:
        print("    - XML-RPC endpoint: Not detected.")
        results["xmlrpc"] = "Not detected / blocked"

    # 3. readme.html version leak
    readme_url = urljoin(base + "/", "readme.html")
    r_readme = safe_get(readme_url)
    if r_readme and r_readme.status_code == 200:
        ver_match = re.search(r'Version\s+([0-9.]+)', r_readme.text, re.I)
        if ver_match:
            version = ver_match.group(1)
            print(f"    - [!] Version Leak (readme.html): WordPress Version {version} detected!")
            results["version_leak"] = f"readme.html leaks Version {version}"
        else:
            print(f"    - readme.html exists but no version leaked.")
            results["version_leak"] = "readme.html exists, no version text"
    else:
        results["version_leak"] = "Not found"

    # 4. Author enumeration redirect check (?author=1)
    author_url = urljoin(base + "/", "?author=1")
    r_author = safe_get(author_url, allow_redirects=False)
    if r_author and r_author.status_code in [301, 302]:
        loc = r_author.headers.get("Location", "")
        if "/author/" in loc:
            username = loc.split("/author/")[-1].rstrip("/")
            print(f"    - [!] User Enumeration via redirect: Author ID 1 resolves to user slug '{username}'")
            results["author_enum"] = f"Author ID 1 -> '{username}' via redirect"
        else:
            results["author_enum"] = "No author redirect detected"
    else:
        results["author_enum"] = "No author redirect detected"

    return results

def run_all(base):
    report = {}
    
    # Run and log REST API users
    api = urljoin(base + "/", "wp-json/wp/v2/users")
    resp = safe_get(api)
    report["rest_users"] = []
    if resp and resp.status_code == 200:
        try:
            users = resp.json()
            if isinstance(users, list) and users:
                print("\n[+] REST API: Users endpoint exposed:")
                for u in users:
                    name = u.get('name') or 'N/A'
                    slug = u.get('slug') or 'N/A'
                    print(f"    - {name} (username/slug: {slug})")
                    report["rest_users"].append(f"{name} (slug: {slug})")
        except Exception:
            pass

    # Home meta
    print("\n[*] Fetching home page meta (title / author / OG site_name / JSON-LD):")
    resp = safe_get(base + "/")
    report["meta"] = {}
    if resp and resp.status_code == 200:
        text = resp.text
        m = re.search(r'<title>([^<]+)</title>', text, re.I)
        if m:
            print(f"    - Title: {m.group(1).strip()}")
            report["meta"]["title"] = m.group(1).strip()
        m = re.search(r'<meta[^>]+name=["\']author["\'][^>]+content=["\']([^"\']+)["\']', text, re.I)
        if m:
            print(f"    - Meta author: {m.group(1).strip()}")
            report["meta"]["author"] = m.group(1).strip()
        m = re.search(r'<meta[^>]+property=["\']og:site_name["\'][^>]+content=["\']([^"\']+)["\']', text, re.I)
        if m:
            print(f"    - OG site_name: {m.group(1).strip()}")
            report["meta"]["og_site_name"] = m.group(1).strip()

    # Detect theme / plugins
    print("\n[*] Detecting theme and plugin hints from HTML paths:")
    report["themes"] = []
    report["plugins"] = []
    if resp and resp.status_code == 200:
        text = resp.text
        themes = set(re.findall(r'wp-content/themes/([a-z0-9\-_]+)', text, re.I))
        plugins = set(re.findall(r'wp-content/plugins/([a-z0-9\-_]+)', text, re.I))
        if themes:
            print(f"    - Themes detected: {', '.join(sorted(themes))}")
            report["themes"] = sorted(list(themes))
        else:
            print("    - No themes detected in HTML.")
        if plugins:
            print(f"    - Plugin hints: {', '.join(sorted(plugins))}")
            report["plugins"] = sorted(list(plugins))
        else:
            print("    - No plugin hints detected.")
        if themes:
            theme = sorted(themes)[0]
            style_url = urljoin(base + "/", f"wp-content/themes/{theme}/style.css")
            r2 = safe_get(style_url)
            if not r2 is None and r2.status_code == 200 and 'Theme Name:' in r2.text:
                m = re.search(r'Theme Name:\s*(.+)', r2.text)
                if m:
                    print(f"    - Theme '{theme}' details: {m.group(1).strip()}")
                    report["theme_details"] = m.group(1).strip()

    # Robots/Sitemap
    print("\n[*] Fetching robots.txt and common sitemaps:")
    r = safe_get(urljoin(base + "/", "robots.txt"))
    report["robots"] = []
    if not r is None and r.status_code == 200:
        print("    - robots.txt (first 6 lines):")
        for i, line in enumerate(r.text.splitlines()):
            if i >= 6: break
            print("       " + line)
            report["robots"].append(line)
    
    report["sitemaps"] = []
    for p in ["sitemap.xml", "sitemap_index.xml", "sitemap"]:
        s = safe_get(urljoin(base + "/", p))
        if not s is None and s.status_code == 200 and ('<urlset' in s.text.lower() or 'sitemapindex' in s.text.lower()):
            m = re.search(r'<loc>([^<]+)</loc>', s.text, re.I)
            loc_str = m.group(1) if m else 'n/a'
            print(f"    - Sitemap found at /{p} (example: {loc_str})")
            report["sitemaps"].append(f"/{p} -> {loc_str}")

    # SSL
    report["ssl"] = get_ssl_cert(base)

    # WP Specifics
    report["wp_specifics"] = check_wp_specifics(base)

    print("\n[✔] Recon sweep complete.")

    save = input("\n[?] Save results to file? (y/n): ").strip().lower()
    if save == 'y':
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        parsed_url = urlparse(base)
        safe_host = parsed_url.netloc.replace(".", "_").replace(":", "_")
        filename = f"wphunter_{safe_host}_{timestamp}.txt"
        import time
        try:
            with open(filename, "w", encoding="utf-8") as f:
                f.write("TheWildEye - WPHunter WordPress Recon Report\n")
                f.write(f"Target Base URL: {base}\n")
                f.write(f"Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write("="*60 + "\n\n")

                f.write("[WordPress File & Endpoint Detections]\n")
                for k, v in report["wp_specifics"].items():
                    f.write(f"  {k.upper()}: {v}\n")
                f.write("\n")

                f.write("[REST API Enumerated Users]\n")
                if report["rest_users"]:
                    for u in report["rest_users"]:
                        f.write(f"  - {u}\n")
                else:
                    f.write("  No exposed users found via REST API.\n")
                f.write("\n")

                f.write("[Home Page Metadata]\n")
                for k, v in report["meta"].items():
                    f.write(f"  {k.title()}: {v}\n")
                f.write("\n")

                f.write("[Theme Detections]\n")
                if report["themes"]:
                    f.write(f"  Detected Themes: {', '.join(report['themes'])}\n")
                    if "theme_details" in report:
                        f.write(f"  Active Theme Details: {report['theme_details']}\n")
                else:
                    f.write("  No theme directories identified.\n")
                f.write("\n")

                f.write("[Plugin Detections]\n")
                if report["plugins"]:
                    for p in report["plugins"]:
                        f.write(f"  - {p}\n")
                else:
                    f.write("  No plugin paths identified.\n")
                f.write("\n")

                f.write("[SSL Certificate Details]\n")
                if report["ssl"]:
                    f.write(f"  Common Name (CN): {report['ssl'].get('cn')}\n")
                    f.write(f"  Subject Alternative Names (SANs): {', '.join(report['ssl'].get('sans') or [])}\n")
                else:
                    f.write("  Failed to extract SSL certificate or non-HTTPS target.\n")
                f.write("\n")

                f.write("[robots.txt Snippet]\n")
                if report["robots"]:
                    for line in report["robots"]:
                        f.write(f"  {line}\n")
                else:
                    f.write("  robots.txt not found.\n")
                f.write("\n")

                f.write("[Sitemaps Found]\n")
                if report["sitemaps"]:
                    for s in report["sitemaps"]:
                        f.write(f"  - {s}\n")
                else:
                    f.write("  No sitemaps detected in default paths.\n")

            print(f"[+] Results saved successfully to: {filename}")
        except Exception as err:
            print(f"[-] Failed to save file: {err}")

if __name__ == "__main__":
    import time
    show_banner()
    raw = input("\nEnter WordPress base URL (e.g. https://example.com): ").strip()
    base = normalize_base(raw)
    if not base:
        print("[-] Invalid URL. Exiting.")
    else:
        print(f"\n[~] Scanning: {base}")
        run_all(base)
