import os
import sys
import re
import time
import hashlib
import threading
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests

from core.engine import ReconModule, register_module
from core.utils import colored, random_ua

SMART_PATHS = [
    # API docs & specs
    "openapi.json", "swagger.json", "swagger/v1/swagger.json", "swagger/v2/swagger.json",
    "api-docs", "api/swagger.json", "api/openapi.json", "api/docs",
    "swagger-ui.html", "api/swagger-ui.html", "swagger-resources",
    "v1/api-docs", "v2/api-docs", "v3/api-docs",
    "documentation", "api/documentation",
    "graphql", "api/graphql", "graphiql", "api/graphiql",
    # API base paths
    "api", "api/", "api/v1", "api/v2", "api/v3",
    "api/health", "api/status", "api/ping", "api/version",
    "api/info", "api/metrics", "api/debug",
    "api/config", "api/configuration", "api/settings",
    "rest", "rest/", "rest/v1", "rest/v2",
    "service", "service/", "services", "gateway",
    # Auth endpoints
    "auth", "auth/", "auth/login", "auth/logout", "auth/register",
    "auth/signup", "auth/signin", "auth/me", "auth/profile",
    "auth/refresh", "auth/token", "auth/verify",
    "auth/forgot-password", "auth/reset-password", "auth/change-password",
    "auth/send-otp", "auth/verify-otp",
    "oauth", "oauth2", "oauth/token", "oauth/authorize",
    "login", "register", "signup", "signin", "logout",
    "token", "tokens", "session", "sessions",
    "forgot-password", "reset-password", "change-password",
    "2fa", "mfa", "verify", "verification",
    # Admin & dashboard
    "admin", "admin/", "administrator", "admin/login",
    "dashboard", "dashboard/", "panel", "console",
    "management", "manage", "control",
    # Users
    "users", "user", "users/me", "users/profile",
    "users/list", "users/create", "users/stats",
    "members", "customers", "accounts",
    "admins", "staff", "employees",
    # Security-sensitive
    ".env", ".env.example", ".env.local", ".env.production",
    ".git/config", ".git/HEAD", ".gitignore",
    ".htaccess", ".htpasswd",
    "backup", "backups", "backup.zip", "backup.sql", "backup.tar.gz",
    "db.sql", "database.sql", "dump.sql",
    "config.json", "config.yaml", "config.yml", "config.php",
    "settings.json", "settings.yaml",
    "package.json", "package-lock.json", "yarn.lock",
    "Dockerfile", "docker-compose.yml", "docker-compose.yaml",
    "nginx.conf", "web.config", ".htaccess.bak",
    # Common web paths
    "robots.txt", "sitemap.xml", "sitemap_index.xml",
    "crossdomain.xml", "humans.txt", "security.txt",
    ".well-known/", ".well-known/security.txt",
    "favicon.ico", "apple-touch-icon.png",
    "index.html", "index.php", "index.js",
    "README", "README.md", "CHANGELOG", "CHANGELOG.md",
    # Static assets
    "static/", "assets/", "dist/", "build/", "public/",
    "js/", "css/", "img/", "images/", "fonts/",
    "uploads/", "upload/", "downloads/", "download/",
    "files/", "file/", "media/", "assets/",
    # Source maps
    "source-map", "sourcemap", "js/app.js.map",
    # CMS paths
    "wp-admin", "wp-content", "wp-json", "wp-includes",
    "wp-login.php", "wp-admin/admin-ajax.php",
    "administrator", "administrator/index.php",
    # Config endpoints
    "configurations", "configurations/", "configurations/custom",
    "configurations/sync",
    "features", "flags", "feature-flags",
    # Billing & payments
    "billing", "billing/", "billing-info",
    "payment", "payment/", "payments",
    "payment/create", "payment/plan-list", "payment/status",
    "payment/webhook", "payment/callback",
    "subscriptions", "subscription", "subscriptions/status",
    "plans", "pricing", "invoices", "invoice",
    # Notifications
    "notifications", "notification",
    "notifications/clear-all", "notifications/read-all",
    # Events & logs
    "events", "activity", "activity/",
    "logs", "log", "audit", "audit-log",
    # Chat & support
    "chat", "chat/", "chat/sessions",
    "support", "help", "contact", "feedback",
    "tickets", "ticket",
    # Data & content
    "data", "content", "content/",
    "categories", "tags", "groups",
    "products", "orders", "inventory",
    "search", "search/",
    # Reports
    "reports", "analytics", "stats", "metrics",
    "dashboard/stats", "dashboard/monthly-trend",
    "dashboard/company-breakdown",
    # Integrations
    "integrations", "connectors", "webhooks",
    "tally", "tally/", "tally/ledgers",
    "tally/voucher-types", "tally/xml",
    "bsr", "bsr/", "bsr/groups", "bsr/ledgers",
    "bsr/statements", "bsr/upload", "bsr/push-batch",
    # Permissions
    "permissions", "permissions/rights",
    "permissions/rights/categories",
    "permissions/users",
    # Companies
    "companies", "organizations", "teams",
    "companies/subscription-select",
    "companies/sync-from-tally",
    # Invitations
    "invitations", "invitations/",
    # Health & status
    "health", "status", "ping", "ready", "live",
    # Internal
    "internal", "internal/", "private", "private/",
    "debug", "debug/", "trace", "monitor",
    "phpinfo.php", "info.php", "test.php",
    "cron", "cron.php", "cron-job",
    "migration", "migrate", "seed",
    ".DS_Store", "Thumbs.db",
]

EXTENSIONS = ["", ".bak", ".old", ".txt", ".xml", ".json", ".yml", ".yaml",
              ".php", ".asp", ".aspx", ".jsp", ".do", ".action",
              ".zip", ".tar.gz", ".gz", ".rar", ".7z",
              ".sql", ".db", ".sqlite",
              ".env", ".conf", ".cfg", ".ini",
              ".log", ".md", ".html", ".htm"]


@register_module
class DirHunterModule(ReconModule):
    name = "dirhunter"
    description = "Directory & file discovery: robots/sitemap + smart paths + extension fuzzing"

    def run(self, target, threads=15, **kwargs):
        self.setup(target)

        timeout = self.config.get("general", "timeout", default=8)
        target = target.rstrip("/")

        self.log(f"Directory discovery on {target}")

        session = requests.Session()
        session.headers["User-Agent"] = random_ua()

        found = []
        scanned = [0]
        _thr_lock = threading.Lock()
        start_time = time.time()
        interrupted = False

        def probe(path, method="GET"):
            url = f"{target}/{path.lstrip('/')}"
            try:
                r = session.request(method, url, timeout=timeout, allow_redirects=False)
                if r.status_code not in (404, 0, 502, 503, 504):
                    if _spa_filter_hash and r.status_code == 200 and len(r.content) > 0:
                        _ch = hashlib.md5(r.content).hexdigest()
                        if _ch == _spa_filter_hash:
                            ct = r.headers.get("Content-Type", "").lower()
                            if "html" in ct or not ct:
                                return None
                    ct = r.headers.get("Content-Type", "")
                    size = len(r.content)
                    size_str = f"{size}B" if size < 1024 else f"{size/1024:.1f}KB" if size < 1048576 else f"{size/1048576:.1f}MB"
                    redirect = r.headers.get("Location", "")[:100] if r.status_code in (301, 302, 303, 307, 308) else ""
                    with _thr_lock:
                        found.append({
                            "path": "/" + path,
                            "url": url,
                            "status": r.status_code,
                            "size": size_str,
                            "content_type": ct[:50],
                            "redirect": redirect,
                        })
                    return r.status_code
            except requests.exceptions.ConnectionError:
                pass
            except Exception:
                pass
            return None

        def check_robots(base):
            try:
                r = session.get(f"{base}/robots.txt", timeout=timeout)
                if r.status_code == 200:
                    paths = []
                    for line in r.text.splitlines():
                        if line.lower().startswith("disallow:"):
                            d = line.split(":", 1)[1].strip()
                            if d and d != "/" and "*" not in d and "$" not in d:
                                paths.append(d.lstrip("/"))
                        elif line.lower().startswith("allow:"):
                            d = line.split(":", 1)[1].strip()
                            if d and d != "/" and "*" not in d and "$" not in d:
                                paths.append(d.lstrip("/"))
                        elif line.lower().startswith("sitemap:"):
                            sm = line.split(":", 1)[1].strip()
                            if sm:
                                paths.append(sm)
                    return paths
            except Exception:
                pass
            return []

        def check_sitemap(base):
            urls = []
            try:
                r = session.get(f"{base}/sitemap.xml", timeout=timeout)
                if r.status_code == 200:
                    for m in re.finditer(r'<loc>(.+?)</loc>', r.text, re.I):
                        u = m.group(1).strip()
                        p = urlparse(u).path.lstrip("/")
                        if p and len(p) > 1:
                            urls.append(p)
            except Exception:
                pass
            return urls

        # Detect app type from the target's HTML
        _html = ""
        _headers = {}
        try:
            _resp = session.get(target, timeout=timeout)
            if _resp.status_code == 200:
                _html = _resp.text
                _headers = dict(_resp.headers)
        except Exception:
            pass

        from core.utils import detect_app_type
        _app_type = detect_app_type(_html, _headers, target)

        self.log(f"  App type: {_app_type['type']}{' (' + _app_type['framework'] + ')' if _app_type['framework'] else ''}")

        probe_queue = []
        ext_paths = []

        if _app_type["type"] == "spa":
            # SPA strategy: extract real routes from JS bundles, skip SMART_PATHS
            self.log("  SPA mode: extracting routes from JS bundles")

            # Establish catch-all hash to filter false positives
            _catchall_hash = None
            for _probe in ("/__nope__", f"/api/__no_t_real_{int(time.time())}__"):
                try:
                    _pr = session.get(f"{target}{_probe}", timeout=timeout, allow_redirects=False)
                    if _pr.status_code == 200 and len(_pr.content) > 50:
                        h = hashlib.md5(_pr.content).hexdigest()
                        if _catchall_hash is None:
                            _catchall_hash = h
                        elif h == _catchall_hash:
                            break
                except Exception:
                    pass

            def probe_spa(path):
                url = f"{target}/{path.lstrip('/')}"
                try:
                    r = session.request("GET", url, timeout=timeout, allow_redirects=False)
                    if r.status_code not in (404, 0, 502, 503, 504):
                        if _catchall_hash and r.status_code == 200:
                            if hashlib.md5(r.content).hexdigest() == _catchall_hash:
                                return None
                        ct = r.headers.get("Content-Type", "")
                        size = len(r.content)
                        size_str = f"{size}B" if size < 1024 else f"{size/1024:.1f}KB" if size < 1048576 else f"{size/1048576:.1f}MB"
                        redirect = r.headers.get("Location", "")[:100] if r.status_code in (301, 302, 303, 307, 308) else ""
                        with _thr_lock:
                            found.append({
                                "path": "/" + path,
                                "url": url,
                                "status": r.status_code,
                                "size": size_str,
                                "content_type": ct[:50],
                                "redirect": redirect,
                            })
                        return r.status_code
                except Exception:
                    pass
                return None

            # JS bundle extraction
            js_urls = set()
            for m in re.finditer(r'<script[^>]+src=["\']([^"\']+)["\']', _html, re.I):
                src = m.group(1).strip()
                if src.startswith("//"):
                    src = "https:" + src
                elif src.startswith("/"):
                    src = f"{target}{src}"
                elif not src.startswith("http"):
                    src = f"{target}/{src.lstrip('/')}"
                js_urls.add(src)

            if js_urls:
                self.log(f"  Analyzing {len(js_urls)} JS bundles")

            def scan_spa_js(js_url):
                paths = set()
                try:
                    jr = session.get(js_url, timeout=timeout)
                    if jr.status_code != 200:
                        return paths
                    text = jr.text
                    # API paths in strings
                    for m in re.finditer(r'["\`](/[a-zA-Z0-9_\-/.]+)["\`]', text):
                        p = m.group(1)
                        if (p.startswith("/api/") or p.startswith("/v1/") or p.startswith("/v2/")
                            or p.count("/") >= 2 and "." not in p.split("/")[-1]
                            and len(p) > 2 and len(p) < 80
                            and not any(x in p for x in ("${", "//", "http", ".js", ".css", ".svg", ".png", ".ico", "favicon"))):
                            paths.add(p.lstrip("/"))
                    # route/path/endpoint definitions
                    for m in re.finditer(r'(?:path|route|endpoint)\s*[:=]\s*["\`](/[a-zA-Z0-9_\-/.]+)["\`]', text, re.I):
                        p = m.group(1)
                        if len(p) > 2 and len(p) < 80 and "{" not in p:
                            paths.add(p.lstrip("/"))
                    # fetch/axios calls
                    for m in re.finditer(r'(?:fetch|axios|ajax)\(["\`](/[a-zA-Z0-9_\-/.]+)["\`]', text, re.I):
                        p = m.group(1)
                        if len(p) > 3 and len(p) < 80:
                            paths.add(p.lstrip("/"))
                except Exception:
                    pass
                return paths

            with ThreadPoolExecutor(max_workers=10) as exe:
                for f in as_completed({exe.submit(scan_spa_js, u): u for u in js_urls}):
                    probe_queue.extend(f.result())

            # Append sitemap URLs too
            for sm_url in check_sitemap(target):
                probe_queue.append(sm_url)

            probe_queue = list(dict.fromkeys(probe_queue))
            if probe_queue:
                self.log(f"  Probing {len(probe_queue)} routes from JS + sitemap")
            total = len(probe_queue)

            interrupted = False
            try:
                with ThreadPoolExecutor(max_workers=threads) as exe:
                    fut_map = {exe.submit(probe_spa, p): p for p in probe_queue}
                    for f in as_completed(fut_map):
                        scanned[0] += 1
                        if scanned[0] % 25 == 0:
                            pct = scanned[0] / total * 100 if total else 0
                            print(f"\r  {scanned[0]}/{total} ({pct:.0f}%) | found: {len(found)}   ", end="", flush=True)
            except KeyboardInterrupt:
                interrupted = True
                print(f"\r  {scanned[0]}/{total} ({scanned[0]/total*100:.0f}%) | INTERRUPTED | found: {len(found)}   ")

            if total:
                print(f"\r  {total}/{total} (100%) | done | found: {len(found)}   ")

        elif _app_type["type"] == "api":
            self.log("  API mode: probing documentation & spec endpoints")
            _spa_filter_hash = None
            api_paths = [
                "openapi.json", "swagger.json", "api-docs", "api/openapi.json", "api/swagger.json",
                "v1/api-docs", "v2/api-docs", "v3/api-docs",
                "graphql", "api/graphql", "graphiql", "api/graphiql",
                "api/health", "api/status", "api/version", "api/ping",
                "health", "status", "ping", "version",
                "api/users", "api/auth/login", "api/config",
            ]
            for path in api_paths:
                probe(path)
            total = len(api_paths)

        elif _app_type["type"] == "static":
            self.log("  Static site mode: probing common paths")
            _spa_filter_hash = None
            static_paths = [
                ".env", ".env.example", ".git/config", ".git/HEAD",
                "robots.txt", "sitemap.xml", "crossdomain.xml",
                "backup.zip", "backup.tar.gz",
                "config.json", "config.yaml",
                "package.json", "Dockerfile",
            ]
            for path in static_paths:
                probe(path)
            total = len(static_paths)

        else:
            # Traditional strategy: full SMART_PATHS + robots/sitemap + extension fuzzing
            self.log("  Traditional mode: probing common paths")

            # SPA catch-all filter (just in case)
            _spa_baselines = {}
            _baseline_probes = [
                target,
                f"{target}/__th_is_no_t_real_{int(time.time())}__",
                f"{target}/api/__no_t_real_{int(time.time())}__",
                f"{target}/.env.xyz_nonexistent_{int(time.time())}",
                f"{target}/admin/__no_t_real_{int(time.time())}__",
                f"{target}/assets/__no_t_real_{int(time.time())}__",
                f"{target}/api/v1/__no_t_real_{int(time.time())}__",
            ]
            for _baseline_url in _baseline_probes:
                try:
                    _br = session.get(_baseline_url, timeout=timeout, allow_redirects=False)
                    if 200 <= _br.status_code < 300 and _br.status_code not in (204, 304):
                        _bhash = hashlib.md5(_br.content).hexdigest()
                        _spa_baselines[_baseline_url] = _bhash
                except Exception:
                    pass
            _hash_counts = {}
            for url, h in _spa_baselines.items():
                _hash_counts[h] = _hash_counts.get(h, 0) + 1
            _most_common_hash = max(_hash_counts, key=_hash_counts.get) if _hash_counts else None
            _dominant_count = _hash_counts.get(_most_common_hash, 0) if _most_common_hash else 0
            _non_real_probes = [u for u in _baseline_probes if u != target]
            _non_real_responded = sum(1 for u in _non_real_probes if u in _spa_baselines)
            _is_spa_catchall = _non_real_responded >= 2 and _dominant_count >= _non_real_responded * 0.6
            _spa_filter_hash = _most_common_hash if _is_spa_catchall else None

            # JS-based path discovery as supplement
            js_discovered_paths = set()
            try:
                js_urls = set()
                for m in re.finditer(r'<script[^>]+src=["\']([^"\']+)["\']', _html, re.I):
                    src = m.group(1).strip()
                    if src.startswith("//"):
                        src = "https:" + src
                    elif src.startswith("/"):
                        src = f"{target}{src}"
                    elif not src.startswith("http"):
                        src = f"{target}/{src.lstrip('/')}"
                    js_urls.add(src)

                if js_urls:
                    self.log(f"  JS supplement: {len(js_urls)} files")
                    def scan_js(js_url):
                        paths = set()
                        try:
                            jr = session.get(js_url, timeout=timeout)
                            if jr.status_code != 200:
                                return paths
                            text = jr.text
                            for m in re.finditer(r'["\`](/[a-zA-Z0-9_\-/.]+)["\`]', text):
                                p = m.group(1)
                                if (p.startswith("/api/") or p.count("/") >= 2
                                    and len(p) > 2 and len(p) < 80
                                    and not any(x in p for x in ("${", "http", ".js", ".css", ".svg", ".png"))):
                                    paths.add(p.lstrip("/"))
                            for m in re.finditer(r'(?:path|route|endpoint)\s*[:=]\s*["\`](/[a-zA-Z0-9_\-/.]+)["\`]', text, re.I):
                                p = m.group(1)
                                if len(p) > 2 and len(p) < 80 and "{" not in p:
                                    paths.add(p.lstrip("/"))
                            for m in re.finditer(r'(?:fetch|axios|ajax)\(["\`](/[a-zA-Z0-9_\-/.]+)["\`]', text, re.I):
                                p = m.group(1)
                                if len(p) > 3 and len(p) < 80:
                                    paths.add(p.lstrip("/"))
                        except Exception:
                            pass
                        return paths

                    with ThreadPoolExecutor(max_workers=10) as exe:
                        for f in as_completed({exe.submit(scan_js, u): u for u in js_urls}):
                            js_discovered_paths.update(f.result())
                    if js_discovered_paths:
                        self.log(f"  JS extracted: {len(js_discovered_paths)} paths")
            except Exception:
                pass

            robots_paths = check_robots(target)
            sitemap_urls = check_sitemap(target)

            probe_queue = list(dict.fromkeys(
                list(js_discovered_paths) + list(robots_paths) + list(sitemap_urls) + SMART_PATHS
            ))
            total = len(probe_queue)

            if robots_paths:
                self.log(f"  robots.txt: {len(robots_paths)} paths")
            if sitemap_urls:
                self.log(f"  sitemap.xml: {len(sitemap_urls)} URLs")
            self.log(f"  Probing {total} paths ({threads} threads)...")

            interrupted = False
            try:
                with ThreadPoolExecutor(max_workers=threads) as exe:
                    fut_map = {exe.submit(probe, p): p for p in probe_queue}
                    for f in as_completed(fut_map):
                        scanned[0] += 1
                        if scanned[0] % 50 == 0:
                            pct = scanned[0] / total * 100
                            elapsed = time.time() - start_time
                            rate = scanned[0] / elapsed if elapsed > 0 else 0
                            eta = (total - scanned[0]) / rate if rate > 0 else 0
                            with _thr_lock:
                                print(f"\r  {scanned[0]}/{total} ({pct:.0f}%) | {rate:.0f} req/s | ETA: {eta:.0f}s | found: {len(found)}   ", end="", flush=True)
            except KeyboardInterrupt:
                interrupted = True
                print(f"\r  {scanned[0]}/{total} ({scanned[0]/total*100:.0f}%) | INTERRUPTED | found: {len(found)}   ")

            print(f"\r  {total}/{total} (100%) | done | found: {len(found)}   ")

            # Extension fuzzing (traditional mode only)
            if found and not interrupted:
                self.log(f"  Extension fuzzing on high-value paths...")
                _api_like = re.compile(r'^(?:api|v[1-9]|rest|graphql|service|gateway|auth|health|status)(?:/|$)', re.I)
                high_value = []
                for f_item in found:
                    p = f_item["path"].lstrip("/")
                    if f_item["status"] < 400 and "." not in f_item["path"].split("/")[-1]:
                        if not _api_like.match(p.split("/")[0]):
                            high_value.append(p)
                for p in high_value[:15]:
                    for ext in EXTENSIONS[1:]:
                        ext_paths.append(p + ext)
                if ext_paths:
                    self.log(f"  Probing {len(ext_paths)} extension variants...")
                    try:
                        with ThreadPoolExecutor(max_workers=threads) as exe:
                            fut_map = {exe.submit(probe, p): p for p in ext_paths}
                            for f in as_completed(fut_map):
                                pass
                    except KeyboardInterrupt:
                        interrupted = True

        duration = time.time() - start_time

        session.close()

        found.sort(key=lambda x: (x["status"], x["path"]))

        self.results["interrupted"] = interrupted
        self.results["target"] = target
        self.results["method"] = "smart discovery (robots/sitemap + common paths + extension fuzz)"
        self.results["total_paths_tested"] = total + len(ext_paths)
        self.results["paths_found"] = found
        self.results["paths_found_count"] = len(found)
        self.results["duration_seconds"] = round(duration, 2)

        status_groups = {}
        for f_item in found:
            s = f_item["status"]
            status_groups.setdefault(s, []).append(f_item)

        header = "DIRHUNT SUMMARY (PARTIAL — INTERRUPTED)" if interrupted else "DIRHUNT SUMMARY"
        print(f"\n{colored('='*60, 'yellow')}")
        print(f"{colored(header, 'bold')}")
        print(f"{colored('='*60, 'yellow')}")
        print(f"  Target:    {target}")
        print(f"  Tested:    {self.results['total_paths_tested']} paths")
        print(f"  Found:     {len(found)} interesting paths")
        print(f"  Duration:  {duration:.1f}s")

        if found:
            print(f"\n{colored('[!] DISCOVERED PATHS BY STATUS:', 'bold')}")
            for st in sorted(status_groups.keys()):
                label = "GREEN" if st < 300 else "REDIRECT" if st < 400 else "DENIED" if st < 500 else "ERROR"
                sc = colored(f"[{st}]", "green") if st < 300 else colored(f"[{st}]", "yellow") if st < 400 else colored(f"[{st}]", "red")
                print(f"\n  {sc} {label} ({len(status_groups[st])} paths)")
                for f_item in status_groups[st]:
                    ct = f" [{f_item['content_type']}]" if f_item.get("content_type") else ""
                    redir = f" -> {f_item['redirect'][:60]}" if f_item.get("redirect") else ""
                    print(f"    /{f_item['path'].lstrip('/'):<55} {f_item['size']:>10}{ct}{redir}")

        self.teardown()
        return self.results
