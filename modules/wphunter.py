import hashlib
import re
import ssl
import socket
from urllib.parse import urljoin, urlparse

import requests

from core.engine import ReconModule, register_module
from core.utils import colored, is_spa, random_ua


@register_module
class WPHunterModule(ReconModule):
    name = "wphunter"
    description = "WordPress reconnaissance scanner - users, themes, plugins, misconfigurations"

    def run(self, target):
        self.setup(target)

        session = requests.Session()
        session.headers["User-Agent"] = random_ua()
        timeout = self.config.get("general", "timeout", default=10)

        parsed = urlparse(target)
        if not parsed.scheme:
            target = "https://" + target
            parsed = urlparse(target)
        base = f"{parsed.scheme}://{parsed.netloc}"
        host = parsed.netloc

        self.log(f"Scanning WordPress target: {base}")

        results = {}

        # 1. REST API user enumeration
        api_url = urljoin(base + "/", "wp-json/wp/v2/users")
        rest_users = []
        try:
            resp = session.get(api_url, timeout=timeout)
            if resp.status_code == 200:
                users = resp.json()
                if isinstance(users, list):
                    for u in users:
                        rest_users.append({
                            "name": u.get("name", "N/A"),
                            "slug": u.get("slug", "N/A"),
                        })
        except Exception:
            pass

        # Detect SPA catch-all (to filter false positives)
        catchall_hash = None
        is_spa_site = False
        try:
            r0 = session.get(base + "/", timeout=timeout)
            if r0.status_code == 200:
                is_spa_site = is_spa(r0.text)
                if is_spa_site:
                    catchall_hash = hashlib.md5(r0.content).hexdigest()
        except Exception:
            pass

        # 2. Home page meta
        meta = {}
        try:
            resp = session.get(base + "/", timeout=timeout)
            if resp.status_code == 200:
                text = resp.text
                m = re.search(r'<title>([^<]+)</title>', text, re.I)
                if m:
                    meta["title"] = m.group(1).strip()
                for attr in ["author", "description", "keywords"]:
                    m = re.search(rf'<meta[^>]+name=["\']{attr}["\'][^>]+content=["\']([^"\']+)["\']', text, re.I)
                    if m:
                        meta[attr] = m.group(1).strip()
                m = re.search(r'<meta[^>]+property=["\']og:site_name["\'][^>]+content=["\']([^"\']+)["\']', text, re.I)
                if m:
                    meta["og_site_name"] = m.group(1).strip()
        except Exception:
            pass

        # 3. Theme & Plugin detection
        themes = set()
        plugins = set()
        theme_details = None
        try:
            resp = session.get(base + "/", timeout=timeout)
            if resp.status_code == 200:
                text = resp.text
                themes = set(re.findall(r'wp-content/themes/([a-z0-9\-_]+)', text, re.I))
                plugins = set(re.findall(r'wp-content/plugins/([a-z0-9\-_]+)', text, re.I))
                if themes:
                    theme = sorted(themes)[0]
                    style_url = urljoin(base + "/", f"wp-content/themes/{theme}/style.css")
                    r2 = session.get(style_url, timeout=timeout)
                    if r2.status_code == 200:
                        m = re.search(r'Theme Name:\s*(.+)', r2.text)
                        if m:
                            theme_details = {"slug": theme, "name": m.group(1).strip()}
        except Exception:
            pass

        # 4. robots.txt & sitemap
        robots_lines = []
        sitemaps = []
        try:
            r = session.get(urljoin(base + "/", "robots.txt"), timeout=timeout)
            if r.status_code == 200:
                robots_lines = r.text.splitlines()[:10]
        except Exception:
            pass
        for sitemap_path in ["sitemap.xml", "sitemap_index.xml", "sitemap"]:
            try:
                s = session.get(urljoin(base + "/", sitemap_path), timeout=timeout)
                if s.status_code == 200 and ('<urlset' in s.text.lower() or 'sitemapindex' in s.text.lower()):
                    loc_m = re.search(r'<loc>([^<]+)</loc>', s.text, re.I)
                    sitemaps.append(f"/{sitemap_path} -> {loc_m.group(1) if loc_m else 'found'}")
            except Exception:
                pass

        # 5. SSL certificate
        ssl_info = None
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((host, 443), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ss:
                    cert = ss.getpeercert()
                    cn = None
                    for t in cert.get("subject", ()):
                        for k, v in t:
                            if k.lower() == "commonname":
                                cn = v
                    sans = [v[1] for v in cert.get("subjectAltName", []) if v[0].lower() == "dns"]
                    ssl_info = {"cn": cn, "sans": sans}
        except Exception:
            pass

        # 6. WordPress-specific endpoints
        wp_checks = {}
        checks = {
            "wp_login": ("wp-login.php", [200, 301, 302]),
            "xmlrpc": ("xmlrpc.php", [200, 301, 302, 405]),
            "readme": ("readme.html", [200]),
            "wp_admin": ("wp-admin/", [200, 301, 302]),
            "wp_config_backup": ("wp-config.php.bak", [200]),
            "wp_config_save": ("wp-config.php.save", [200]),
            "install_php": ("wp-admin/install.php", [200]),
        }
        for name, (path, expected) in checks.items():
            try:
                r = session.get(urljoin(base + "/", path), timeout=timeout, allow_redirects=False)
                if r.status_code in expected:
                    if catchall_hash and hashlib.md5(r.content).hexdigest() == catchall_hash:
                        wp_checks[name] = {"path": path, "status": r.status_code, "detail": "SPA catch-all (false positive)"}
                        continue
                    extra = ""
                    if name == "readme" and r.status_code == 200:
                        vm = re.search(r'Version\s+([0-9.]+)', r.text, re.I)
                        if vm:
                            extra = f" (Version: {vm.group(1)})"
                    if name == "xmlrpc" and r.status_code == 200:
                        if "XML-RPC server accepts POST requests only." in r.text:
                            extra = " (Enabled)"
                    wp_checks[name] = {"path": path, "status": r.status_code, "detail": extra.strip()}
                else:
                    wp_checks[name] = {"path": path, "status": r.status_code, "detail": "Blocked/Not found"}
            except Exception:
                wp_checks[name] = {"path": path, "status": "error", "detail": "Request failed"}

        # 7. Version detection from readme
        version = None
        try:
            r = session.get(urljoin(base + "/", "readme.html"), timeout=timeout)
            if r.status_code == 200:
                vm = re.search(r'Version\s+([0-9.]+)', r.text, re.I)
                if vm:
                    version = vm.group(1)
        except Exception:
            pass

        # 8. Author enumeration via ?author=1 redirect
        author_enum = None
        try:
            r = session.get(urljoin(base + "/", "?author=1"), timeout=timeout, allow_redirects=False)
            if r.status_code in (301, 302):
                loc = r.headers.get("Location", "")
                if "/author/" in loc:
                    username = loc.split("/author/")[-1].rstrip("/")
                    author_enum = {"id": 1, "slug": username}
        except Exception:
            pass

        self.results["target"] = base
        self.results["is_wordpress"] = len(themes) > 0 or "/wp-" in str(wp_checks)
        self.results["is_spa_catchall"] = is_spa_site
        self.results["rest_api_users"] = rest_users
        self.results["rest_api_users_count"] = len(rest_users)
        self.results["meta"] = meta
        self.results["themes"] = sorted(themes)
        self.results["plugins"] = sorted(plugins)
        self.results["theme_details"] = theme_details
        self.results["wordpress_version"] = version
        self.results["author_enumeration"] = author_enum
        self.results["endpoint_checks"] = wp_checks
        self.results["ssl_certificate"] = ssl_info
        self.results["robots_txt"] = robots_lines
        self.results["sitemaps"] = sitemaps

        real_endpoints = {k: v for k, v in wp_checks.items() if "SPA catch-all" not in v.get("detail", "")}
        fp_endpoints = {k: v for k, v in wp_checks.items() if "SPA catch-all" in v.get("detail", "")}

        print(f"\n{colored('='*60, 'cyan')}")
        print(f"{colored('WPHUNT SUMMARY', 'bold')}")
        print(f"{colored('='*60, 'cyan')}")
        print(f"  Target:      {base}")
        print(f"  WordPress:   {colored('YES', 'green') if len(themes) > 0 else colored('Unlikely', 'yellow')}")
        if is_spa_site:
            print(f"  SPA:         {colored('YES (catch-all routing detected)', 'yellow')}")
        if version:
            print(f"  Version:     {version}")
        print(f"  REST Users:  {len(rest_users)}")
        if rest_users:
            for u in rest_users:
                print(f"    - {u['name']} ({u['slug']})")
        if themes:
            print(f"  Themes:      {', '.join(sorted(themes))}")
        if plugins:
            print(f"  Plugins:     {', '.join(sorted(plugins))}")
        if author_enum:
            print(f"  Author Enum: {colored('Vulnerable', 'red')} - {author_enum['slug']}")
        print(f"  Endpoints:")
        if real_endpoints:
            for name, check in real_endpoints.items():
                icon = colored("[!]", "red")
                extra = f" - {check['detail']}" if check.get("detail") else ""
                print(f"    {icon} /{check['path']} ({check['status']}){extra}")
        else:
            print(f"    {colored('No actual WordPress endpoints found', 'green')}")
        if fp_endpoints:
            print(f"  False positives (SPA catch-all):")
            for name, check in fp_endpoints.items():
                print(f"    {colored('[~]', 'yellow')} /{check['path']} ({check['status']})")

        session.close()
        self.teardown()
        return self.results
