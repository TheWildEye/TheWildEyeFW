import os
import re
import json
import time
import hashlib
import requests
from urllib.parse import urlparse, urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed

from core.engine import ReconModule, register_module
from core.utils import (
    normalize_url, get_domain, random_ua, colored, API_ENDPOINT_RE,
    SECRET_RE, AWS_KEY_RE, JWT_RE, FIREBASE_RE, STRIPE_RE,
    extract_from_script_tags,
)

COMMON_API_PATHS = [
    "v1", "v2", "v3", "v4",
    "users", "user", "admins", "admin", "moderators",
    "config", "configuration", "settings", "preferences",
    "payments", "payment", "payment-create", "checkout",
    "cart", "orders", "order", "invoices", "invoice",
    "products", "product", "items", "item", "catalog", "categories", "category",
    "auth", "login", "register", "signup", "signin", "logout", "token", "refresh",
    "profile", "account", "accounts", "me",
    "search", "query", "lookup", "suggest",
    "upload", "uploads", "file", "files", "media", "images", "image",
    "notifications", "notification", "alerts", "alert",
    "webhook", "webhooks", "hooks", "callback",
    "report", "reports", "analytics", "stats", "statistics",
    "export", "import", "backup", "restore",
    "logs", "log", "audit", "activity", "history",
    "health", "healthcheck", "ping", "status", "ready", "live",
    "docs", "documentation", "swagger", "openapi",
    "graphql", "graphiql", "playground",
    "socket", "ws", "wss", "events", "stream",
    "cron", "jobs", "tasks", "queue",
    "templates", "template", "email", "sms", "notify",
    "address", "addresses", "location", "locations",
    "feedback", "review", "reviews", "rating", "ratings",
    "coupon", "coupons", "discount", "promo", "promotions",
    "subscription", "subscriptions", "plan", "plans",
    "notification-settings", "notification-preferences",
    "device", "devices", "session", "sessions",
    "permissions", "roles", "role", "groups",
    "meta", "metadata", "tags", "tag",
    "bulk", "batch", "mass",
    "sms-send", "email-send", "send-email", "send-sms",
    "verify", "verification", "validate", "confirm",
    "reset-password", "forgot-password", "change-password",
    "otp", "otp-send", "otp-verify", "mfa", "2fa",
    "delivery", "delivery-options", "shipping", "tracking",
    "refund", "refunds", "dispute", "disputes",
    "wallet", "balance", "transaction", "transactions",
    "partner", "partners", "vendor", "vendors",
    "store", "stores", "branch", "branches",
    "inventory", "stock", "supplier", "suppliers",
    "tax", "taxes", "gst", "vat",
    "loyalty", "points", "rewards", "cashback",
    "campaign", "campaigns", "offer", "offers",
    "ticket", "tickets",
    "terms", "privacy", "policy", "about",
    "city", "cities", "state", "states", "pincode",
]

_JS_CODE_RE = re.compile(r'(?:function|=>|var\s|let\s|const\s|===|!==|\+\+|--|\.prototype|\.call\(|\.apply\(|new\s+\w+\s*\()')
_CREDENTIAL_KEY_RE = re.compile(r'(?:password|passwd|pwd|secret|token|apikey|api_key)\s*[:=]\s*["\']([^"\']{4,64})["\']', re.I)


def _is_js_code(val):
    return bool(_JS_CODE_RE.search(val)) or len(val) > 200 or val.count(")") > 2 or val.count("}") > 0


def _sane_endpoint(val):
    if not val or len(val) < 2 or len(val) > 200:
        return False
    if _is_js_code(val):
        return False
    if val.startswith(("{", "<", "[", "function")):
        return False
    if not val.startswith(("/", "http://", "https://")):
        return False
    return True


ENDPOINT_PATTERNS = [
    (re.compile(r'["\']((?:/api|/v[1-9]|/rest|/graphql|/service|/gateway)/[^"\'\\\s]*)["\']', re.I), 1),
    (re.compile(r'["\'](https?://[^"\']*?(?:api|rest|graphql|service|gateway)[^"\']*)["\']', re.I), 1),
    (re.compile(r'(?<![$\w])url:\s*["\']([^"\']{2,200})["\']', re.I), 1),
    (re.compile(r'(?<![$\w])path:\s*["\']([^"\']{2,200})["\']', re.I), 1),
    (re.compile(r'(?<![$\w])endpoint:\s*["\']([^"\']{2,200})["\']', re.I), 1),
    (re.compile(r'(?<![$\w])route:\s*["\']([^"\']{2,200})["\']', re.I), 1),
    (re.compile(r'(?<![$\w])baseURL:\s*["\']([^"\']{2,200})["\']', re.I), 1),
    (re.compile(r'(?<![$\w])baseUrl:\s*["\']([^"\']{2,200})["\']', re.I), 1),
    (re.compile(r'(?<![$\w])base_url:\s*["\']([^"\']{2,200})["\']', re.I), 1),
    (re.compile(r'axios\.create\s*\(\s*\{[^}]*baseURL:\s*["\']([^"\']{2,200})["\']', re.I), 1),
]

API_PATH_RE = re.compile(r'["\']/(?:api|v[1-9]|rest|graphql|service|gateway)/[a-zA-Z0-9_\-/{}]*["\']', re.I)
ABSOLUTE_API_URL_RE = re.compile(r'["\'](https?://[^"\']*?(?:api|rest|graphql|service|gateway)[^"\']*)["\']', re.I)
RELATIVE_PATH_RE = re.compile(r'["\'](/(?:api|v[1-9]|rest|graphql|service|gateway)/[a-zA-Z0-9_\-/]*)["\']', re.I)

SECRET_PATTERNS = [
    (AWS_KEY_RE, "AWS Access Key"), (JWT_RE, "JWT Token"),
    (FIREBASE_RE, "Firebase URL"), (STRIPE_RE, "Stripe Key"),
    (SECRET_RE, "Potential Secret"),
    (re.compile(r'(?:sk|pk)_(?:live|test)_[A-Za-z0-9]{10,}', re.I), "Stripe Key"),
    (re.compile(r'(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{10,}', re.I), "GitHub Token"),
    (re.compile(r'(?:xox[abp]|xapp|xoxb)-[A-Za-z0-9-]{10,}', re.I), "Slack Token"),
    (re.compile(r'AIza[A-Za-z0-9_\-]{35}', re.I), "Google API Key"),
    (re.compile(r'SG\.[A-Za-z0-9_\-]{20,}', re.I), "SendGrid Key"),
    (re.compile(r'(?:-----BEGIN\s*(?:RSA|EC|DSA|PGP)?\s*PRIVATE KEY-----)', re.I), "Private Key"),
    (_CREDENTIAL_KEY_RE, "Credential"),
]


@register_module
class JSReaperModule(ReconModule):
    name = "jsreaphunter"
    description = "JS analysis + API endpoint discovery + active API path fuzzing"

    def run(self, target, api_fuzz=True, max_fuzz=500):
        self.setup(target)

        parsed = urlparse(target)
        base_url = f"{parsed.scheme}://{parsed.netloc}" if parsed.scheme else f"https://{parsed.netloc}"
        timeout = self.config.get("general", "timeout", default=10)

        session = requests.Session()
        session.headers["User-Agent"] = random_ua()

        all_endpoints = set()
        all_secrets = []
        all_routes = set()
        sourcemaps = []
        js_analyzed = []
        internal_hosts = set()

        # === PHASE 1: Static JS analysis ===
        self.log(f"Phase 1: Static JS analysis on {target}")
        js_urls = set()
        inline_html = ""

        try:
            resp = session.get(target, timeout=timeout)
            html = resp.text
            inline_html = html

            for match in re.finditer(r'<script[^>]+src=["\']([^"\']+)["\']', html, re.I):
                js_url = normalize_url(match.group(1).strip(), target)
                if js_url:
                    js_urls.add(js_url)
        except Exception as e:
            self.error(f"Failed to fetch {target}: {e}")

        # App type detection
        from core.utils import detect_app_type
        _app_info = detect_app_type(inline_html or "", dict(resp.headers) if 'resp' in dir() else {}, target)
        self.log(f"  App type: {_app_info['type']}{' (' + _app_info['framework'] + ')' if _app_info['framework'] else ''}")
        _is_api = _app_info["type"] == "api"
        _is_spa = _app_info["type"] == "spa"

        max_js = self.config.get("js_reaper", "max_js_files", default=200)

        def analyze_js(js_url):
            result = {"url": js_url, "endpoints": [], "secrets": [], "routes": [], "sourcemap": None, "ips": set()}
            try:
                resp = session.get(js_url, timeout=timeout)
                if resp.status_code != 200:
                    return result
                content = resp.text
                result["size"] = len(content)

                for pat, grp in ENDPOINT_PATTERNS:
                    for m in pat.finditer(content):
                        ep = m.group(grp).strip('"').strip("'").strip()
                        if _sane_endpoint(ep):
                            result["endpoints"].append(ep)

                for m in RELATIVE_PATH_RE.finditer(content):
                    ep = m.group(1).strip()
                    if _sane_endpoint(ep) and ep not in result["endpoints"]:
                        result["endpoints"].append(ep)

                for m in ABSOLUTE_API_URL_RE.finditer(content):
                    ep = m.group(1).strip()
                    if _sane_endpoint(ep) and ep not in result["endpoints"]:
                        result["endpoints"].append(ep)

                for m in re.finditer(r"`([^`]*?(?:api|v[1-9]|rest|graphql|gateway|service)[^`]*)`", content, re.I):
                    raw = m.group(1)
                    cleaned = re.sub(r'\$\{[^}]+\}', ':param', raw)
                    cleaned = re.sub(r'\s+', '', cleaned)
                    if _sane_endpoint(cleaned):
                        result["endpoints"].append(cleaned)

                for m in re.finditer(r'["\']/(api|v[1-9]|rest|graphql)/["\'][^;]*\+[^;]*', content, re.I):
                    ep = m.group(0)[:80]
                    if _sane_endpoint(ep):
                        result["endpoints"].append(ep)

                for m in re.finditer(r"(?:fetch|axios|ajax|get|post|put|delete|patch)\s*\(\s*['\"`]([^'\"`]+)['\"`]", content, re.I):
                    ep = m.group(1).strip()
                    if "/" in ep and not ep.startswith(("{", "<")) and not _is_js_code(ep):
                        result["endpoints"].append(ep)

                for pattern, name in SECRET_PATTERNS:
                    for m in pattern.finditer(content):
                        val = m.group(0)[:100]
                        if not _is_js_code(val):
                            result["secrets"].append({"type": name, "value": val})

                route_pats = [
                    re.compile(r"(?<![$\w])path:\s*['\"]([^'\"]{2,200})['\"]", re.I),
                    re.compile(r"(?<![$\w])route:\s*['\"]([^'\"]{2,200})['\"]", re.I),
                    re.compile(r"(?<![$\w])component:\s*['\"]([^'\"]{2,200})['\"]", re.I),
                ]
                for pat in route_pats:
                    for m in pat.finditer(content):
                        rt = m.group(1).strip()
                        if rt.startswith("/") and len(rt) < 100 and "{" not in rt and not _is_js_code(rt):
                            result["routes"].append(rt)

                sm = re.search(r'//# sourceMappingURL=([^\s]+)', content)
                if sm:
                    sm_url = normalize_url(sm.group(1).strip(), js_url)
                    if sm_url:
                        result["sourcemap"] = sm_url

                ips = re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', content)
                found_ips = set()
                for ip in ips[:10]:
                    if not ip.startswith(("127.", "10.", "192.168.", "169.254.", "172.16.", "0.")):
                        try:
                            parts = [int(x) for x in ip.split(".")]
                            if all(0 <= p <= 255 for p in parts):
                                found_ips.add(ip)
                        except Exception:
                            pass
                result["ips"] = found_ips
            except Exception:
                pass
            return result

        js_list = list(js_urls)[:max_js]
        interrupted = False
        try:
            with ThreadPoolExecutor(max_workers=10) as exe:
                fut = {exe.submit(analyze_js, u): u for u in js_list}
                for f in as_completed(fut):
                    r = f.result()
                    if r.get("endpoints") or r.get("secrets") or r.get("routes") or r.get("sourcemap"):
                        js_analyzed.append(r)
                        for ep in r["endpoints"]:
                            all_endpoints.add(ep)
                        for sec in r["secrets"]:
                            all_secrets.append(sec)
                        for rt in r["routes"]:
                            all_routes.add(rt)
                        if r.get("sourcemap"):
                            sourcemaps.append(r["sourcemap"])
                        for ip in r.get("ips", set()):
                            internal_hosts.add(ip)
        except KeyboardInterrupt:
            interrupted = True

        if inline_html:
            script_text = extract_from_script_tags(inline_html)
            inline_pats = [
                API_ENDPOINT_RE,
                re.compile(r'["\'](https?://[^"\']*?(?:api|rest|graphql|gateway)[^"\']*)["\']', re.I),
            ]
            for pat in inline_pats:
                for m in pat.finditer(script_text):
                    ep = m.group(0).strip('"').strip("'")
                    if _sane_endpoint(ep):
                        all_endpoints.add(ep)

            for json_block_pat in [r'__NEXT_DATA__\s*=\s*({.+?})</script>', r'__NUXT__\s*=\s*({.+?})</script>', r'window\.__INITIAL_STATE__\s*=\s*({.+?});']:
                for jm in re.finditer(json_block_pat, inline_html, re.I | re.S):
                    try:
                        data = json.loads(jm.group(1))
                        data_str = json.dumps(data)
                        for epm in re.finditer(r'["\']((?:https?://[^"\']*?api[^"\']*|/api/[^"\'\s]*))["\']', data_str):
                            ep = epm.group(1)
                            if _sane_endpoint(ep):
                                all_endpoints.add(ep)
                        for sp, sn in SECRET_PATTERNS:
                            for smm in sp.finditer(data_str):
                                val = smm.group(0)[:100]
                                if not _is_js_code(val):
                                    all_secrets.append({"type": sn, "value": val})
                    except Exception:
                        pass

            for m in re.finditer(r'["\']/(?:api|v[1-9]|rest|graphql|gateway|service)/[^"\'\\\s<>]*["\']', inline_html, re.I):
                ep = m.group(0).strip('"').strip("'")
                if _sane_endpoint(ep):
                    all_endpoints.add(ep)
            for m in re.finditer(r'(?:api_url|api_base|base_url|endpoint|apiEndpoint)\s*[=:]\s*["\']([^"\']{2,200})["\']', inline_html, re.I):
                ep = m.group(1).strip()
                if _sane_endpoint(ep):
                    all_endpoints.add(ep)

            for m in re.finditer(r"(?:fetch|axios|ajax|get|post|put|delete|patch)\s*\(\s*['\"`]([^'\"`]+)['\"`]", script_text, re.I):
                ep = m.group(1).strip()
                if "/" in ep and not _is_js_code(ep):
                    all_endpoints.add(ep)

        # === PHASE 2: Active API path fuzzing ===
        fuzz_target = target.rstrip("/")
        if _is_api:
            self.log(f"Phase 2: API target — probing spec/documentation endpoints")
            api_discovered = []
            spec_paths = [
                "openapi.json", "swagger.json", "api-docs", "api/openapi.json", "api/swagger.json",
                "v1/api-docs", "v2/api-docs", "v3/api-docs",
                "graphql", "api/graphql", "graphiql", "api/graphiql",
                "api/health", "api/status", "api/version", "api/ping",
                "health", "status", "ping", "version",
            ]
            for sp in spec_paths:
                url = f"{fuzz_target}/{sp}"
                try:
                    r = session.get(url, timeout=4, allow_redirects=False)
                    if r.status_code not in (404, 405, 0):
                        api_discovered.append({
                            "method": "GET", "url": url,
                            "status": r.status_code, "size": len(r.content),
                            "content_type": r.headers.get("Content-Type", "")[:50],
                        })
                except Exception:
                    pass

        elif api_fuzz:
            self.log(f"Phase 2: Active API endpoint fuzzing")
            fuzz_paths = set(COMMON_API_PATHS)
            parsed_target = urlparse(target)
            target_domain = parsed_target.netloc

            for ep in all_endpoints:
                clean = ep.strip("'").strip('"')
                if clean.startswith("/"):
                    clean = clean.lstrip("/")
                    if clean and len(clean) < 80:
                        fuzz_paths.add(clean)

            # Collect cross-domain API hosts from absolute URLs in endpoints
            api_hosts_to_fuzz = {}
            for ep in all_endpoints:
                if ep.startswith(("http://", "https://")):
                    try:
                        ep_parsed = urlparse(ep)
                        if ep_parsed.netloc != target_domain:
                            base = f"{ep_parsed.scheme}://{ep_parsed.netloc}"
                            path_parts = ep_parsed.path.strip("/").split("/")
                            if path_parts and path_parts[0]:
                                api_hosts_to_fuzz.setdefault(base, set()).add(path_parts[0])
                    except Exception:
                        pass

            self.log(f"Fuzzing {len(fuzz_paths)} API paths against {fuzz_target}")
            if api_hosts_to_fuzz:
                self.log(f"  + {len(api_hosts_to_fuzz)} cross-domain API hosts from JS endpoints")

            # Establish catch-all fingerprint to filter SPA false positives
            _catchall_hash = None
            _catchall_size = None
            _catchall_ct = None
            for _probe_path in ("/__th_is_no_t_real__", f"/api/__no_t_real_{int(time.time())}__"):
                try:
                    _pr = session.get(f"{fuzz_target}{_probe_path}", timeout=4, allow_redirects=False)
                    if _pr.status_code == 200 and len(_pr.content) > 100:
                        _ch = hashlib.md5(_pr.content).hexdigest()
                        _ct = (_pr.headers.get("Content-Type") or "").lower()
                        if _catchall_hash is None:
                            _catchall_hash = _ch
                            _catchall_size = len(_pr.content)
                            _catchall_ct = _ct
                        elif _ch == _catchall_hash and _ct == _catchall_ct:
                            break
                except Exception:
                    pass

            found_api = []
            checked = set()

            def try_path(path, base_url=None):
                if base_url is None:
                    base_url = fuzz_target
                url = f"{base_url}/{path}"
                cache_key = f"{url}_{path}"
                if cache_key in checked:
                    return None
                checked.add(cache_key)
                results = []
                for method in ["GET", "POST"]:
                    try:
                        if method == "GET":
                            r = session.get(url, timeout=4, allow_redirects=False)
                        else:
                            r = session.post(url, json={}, timeout=4, allow_redirects=False)

                        if r.status_code not in (404, 405, 0):
                            _ct = (r.headers.get("Content-Type") or "").lower()
                            _is_html_response = "html" in _ct or (not _ct and len(r.content) > 500)
                            if _catchall_hash and r.status_code == 200 and _is_html_response:
                                _ch = hashlib.md5(r.content).hexdigest()
                                if _ch == _catchall_hash and len(r.content) == _catchall_size:
                                    continue
                            size = len(r.content)
                            ct = r.headers.get("Content-Type", "")
                            results.append({
                                "method": method, "url": url,
                                "status": r.status_code, "size": size,
                                "content_type": ct[:50],
                            })
                    except Exception:
                        pass
                return results if results else None

            try:
                with ThreadPoolExecutor(max_workers=20) as exe:
                    fut_map = {}
                    for path in list(fuzz_paths)[:max_fuzz]:
                        fut_map[exe.submit(try_path, path)] = path
                    for f in as_completed(fut_map):
                        r = f.result()
                        if r:
                            found_api.extend(r)

                    # Fuzz cross-domain API hosts (probe their discovered paths)
                    for api_host, host_paths in api_hosts_to_fuzz.items():
                        for hp in host_paths:
                            fut_map[exe.submit(try_path, hp, api_host)] = f"{api_host}/{hp}"
                    for f in as_completed(fut_map):
                        r = f.result()
                        if r:
                            found_api.extend(r)
            except KeyboardInterrupt:
                interrupted = True

            found_api.sort(key=lambda x: x["url"])
            api_discovered = found_api
        else:
            api_discovered = []

        self.results["interrupted"] = interrupted
        self.results["target"] = target
        self.results["js_files_total"] = len(js_urls)
        self.results["js_files_analyzed"] = len(js_analyzed)
        self.results["api_endpoints_static"] = sorted(all_endpoints) if all_endpoints else []
        self.results["api_endpoints_active"] = api_discovered if api_discovered else []
        self.results["secrets_found"] = all_secrets if all_secrets else []
        self.results["spa_routes"] = sorted(all_routes) if all_routes else []
        self.results["sourcemaps"] = sourcemaps if sourcemaps else []
        self.results["internal_ips"] = sorted(internal_hosts) if internal_hosts else []

        # Extract cross-domain API hosts from endpoints
        api_domains = set()
        for ep in all_endpoints:
            if ep.startswith(("http://", "https://")):
                try:
                    api_domains.add(urlparse(ep).netloc)
                except Exception:
                    pass

        header = "JS REAPER / API HUNTER SUMMARY (PARTIAL — INTERRUPTED)" if interrupted else "JS REAPER / API HUNTER SUMMARY"
        print(f"\n{colored('='*60, 'magenta')}")
        print(f"{colored(header, 'bold')}")
        print(f"{colored('='*60, 'magenta')}")
        print(f"  Target:              {target}")
        print(f"  JS files found:      {len(js_urls)}")
        print(f"  Endpoints (static):  {len(all_endpoints)}")
        print(f"  Endpoints (active):  {len(api_discovered)}")
        print(f"  Secrets/keys:        {len(all_secrets)}")
        print(f"  SPA routes:          {len(all_routes)}")
        print(f"  Sourcemaps:          {len(sourcemaps)}")
        print(f"  Internal IPs:        {len(internal_hosts)}")
        if api_domains:
            print(f"  API hosts found:     {', '.join(sorted(api_domains))}")

        if js_analyzed:
            print(f"\n{colored('[!] JS FILES ANALYZED:', 'yellow')}")
            for js in js_analyzed:
                print(f"    {js['url']} ({js.get('size', 0)}b)")

        if all_endpoints:
            print(f"\n{colored('[!] STATIC API ENDPOINTS (from JS):', 'cyan')}")
            for ep in sorted(all_endpoints):
                print(f"    {ep}")

        if all_routes:
            print(f"\n{colored('[!] SPA ROUTES:', 'cyan')}")
            for r in sorted(all_routes):
                print(f"    {r}")

        if api_discovered:
            print(f"\n{colored('[!] ACTIVE API ENDPOINTS FOUND:', 'green')}")
            for ep in api_discovered:
                ms = colored(ep["method"], "cyan")
                sc = colored(str(ep["status"]), "green") if ep["status"] < 400 else colored(str(ep["status"]), "red")
                print(f"    {ms} {sc} {ep['url']} ({ep['size']}b, {ep['content_type']})")

        if all_secrets:
            print(f"\n{colored('[!] POTENTIAL SECRETS', 'red')}")
            seen_types = {}
            for s in all_secrets:
                if s['value'] in seen_types:
                    continue
                seen_types[s['value']] = True
                display_val = s['value'].replace('\n', '\\n').replace('\r', '\\r')
                print(f"    {s['type']}: {display_val}")

        session.close()
        self.teardown()
        return self.results
