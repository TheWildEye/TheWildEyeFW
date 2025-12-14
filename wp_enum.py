import requests
from urllib.parse import urljoin, urlparse
import re
import ssl
import socket

try:
    from bs4 import BeautifulSoup
    BS4 = True
except Exception:
    BS4 = False

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
    except Exception as e:
        return e  

def check_rest_users(base):
    api = urljoin(base + "/", "wp-json/wp/v2/users")
    resp = safe_get(api)
    if isinstance(resp, Exception):
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
    if isinstance(resp, Exception) or resp.status_code != 200:
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
    if isinstance(resp, Exception) or resp.status_code != 200:
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
        if not isinstance(r2, Exception) and r2.status_code == 200 and 'Theme Name:' in r2.text:
            m = re.search(r'Theme Name:\s*(.+)', r2.text)
            if m:
                print(f"    - Theme '{theme}' details: {m.group(1).strip()}")
    return True

def fetch_robots_and_sitemap(base):
    print("\n[*] Fetching robots.txt and common sitemaps:")
    r = safe_get(urljoin(base + "/", "robots.txt"))
    if not isinstance(r, Exception) and r.status_code == 200:
        print("    - robots.txt (first 6 lines):")
        for i, line in enumerate(r.text.splitlines()):
            if i >= 6: break
            print("       " + line)
    else:
        print("    - robots.txt not found.")
    for p in ["sitemap.xml", "sitemap_index.xml", "sitemap"]:
        s = safe_get(urljoin(base + "/", p))
        if not isinstance(s, Exception) and s.status_code == 200 and ('<urlset' in s.text.lower() or 'sitemapindex' in s.text.lower()):
            m = re.search(r'<loc>([^<]+)</loc>', s.text, re.I)
            print(f"    - Sitemap found at /{p} (example: {m.group(1) if m else 'n/a'})")
            return True
    print("    - No sitemap found at common locations.")
    return False

def get_ssl_cert(base):
    host = urlparse(base).hostname
    if not host:
        print("[-] No hostname for SSL.")
        return False
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
            return True
    except Exception as e:
        print(f"[-] SSL fetch error: {e}")
        return False

def run_all(base):
    check_rest_users(base)
    fetch_home_meta(base)
    detect_theme_plugins(base)
    fetch_robots_and_sitemap(base)
    get_ssl_cert(base)
    print("\n[✔] Recon sweep complete.")

if __name__ == "__main__":
    show_banner()
    raw = input("\nEnter WordPress base URL (e.g. https://example.com): ").strip()
    base = normalize_base(raw)
    if not base:
        print("[-] Invalid URL. Exiting.")
    else:
        print(f"\n[~] Scanning: {base}")
        run_all(base)
