import os
import re
import json
import time
import random
import hashlib
import threading
import requests
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict

from core.engine import ReconModule, register_module
from core.utils import colored, random_ua, normalize_url, extract_from_script_tags

REST_SYNONYMS = {
    "users": ["user", "admins", "admin", "members", "member", "customers", "customer", "staff", "employees", "employee", "accounts", "account", "people", "person", "clients", "client"],
    "orders": ["order", "purchases", "purchase", "transactions", "transaction", "carts", "cart", "checkouts", "checkout", "invoices", "invoice", "receipts", "receipt"],
    "products": ["product", "items", "item", "goods", "catalog", "catalogue", "inventory", "stock", "merchandise", "sku", "skus", "variants", "variant"],
    "payments": ["payment", "billing", "bills", "bill", "charges", "charge", "payouts", "payout", "refunds", "refund", "settlements", "settlement"],
    "config": ["configuration", "settings", "preferences", "options", "features", "flags", "env", "environment", "constants", "variables"],
    "auth": ["authentication", "login", "signin", "signup", "register", "logout", "signout", "token", "tokens", "session", "sessions", "oauth", "saml"],
    "profile": ["profiles", "me", "account", "avatar", "bio", "settings", "preferences"],
    "notifications": ["notification", "alerts", "alert", "messages", "message", "push", "email", "sms", "webhook", "webhooks"],
    "reports": ["report", "analytics", "stats", "statistics", "metrics", "dashboard", "insights", "summary"],
    "content": ["pages", "page", "blogs", "blog", "articles", "article", "posts", "post", "news", "media", "files", "file"],
    "categories": ["category", "tags", "tag", "labels", "label", "groups", "group"],
    "addresses": ["address", "locations", "location", "places", "place", "cities", "city"],
    "organizations": ["organization", "orgs", "org", "teams", "team", "workspaces", "workspace", "companies", "company", "tenants", "tenant"],
    "permissions": ["permission", "roles", "role", "rights", "access"],
    "subscriptions": ["subscription", "plans", "plan", "packages", "package", "tiers", "tier"],
    "integrations": ["integration", "connectors", "connector", "plugins", "plugin"],
    "support": ["tickets", "ticket", "faq", "contact", "feedback", "help"],
}

API_PATH_PATTERNS = re.compile(
    r'(?:"|\'|\`)(/(?:api|v[1-9]|rest|graphql|service|gateway|backend|external|ws|socket)'
    r'(?:/[a-zA-Z0-9_\-{}]+)+)(?:"|\'|\`)', re.I
)

SECRET_PATTERNS = re.compile(
    r'(?:"|\')(?:api[Kk]ey|apikey|api[_-]?secret|api[_-]?token|access[_-]?token|'
    r'secret|token|bearer|auth[_-]?token|jwt|refresh[_-]?token)(?:"|\')\s*:\s*'
    r'(?:"|\')([^"\']{8,})(?:"|\')'
)

SOURCE_MAP_ENDPOINT_RE = re.compile(
    r'(?:"|\')(/[a-zA-Z0-9_\-/.{}]+(?::[a-zA-Z]+)?)(?:"|\')'
)

_TRACKING = {"google-analytics.com", "googletagmanager.com", "doubleclick.net", "googleadservices.com",
              "googleads", "pagead2.googlesyndication.com", "facebook.com", "fbcdn.net", "hotjar.com",
              "newrelic.com", "datadoghq.com", "sentry.io", "amplitude.com", "mixpanel.com",
              "segment.io", "segment.com", "fullstory.com", "crazyegg.com", "optimizely.com",
              "adroll.com", "criteo.com", "taboola.com", "outbrain.com", "adsrvr.org",
              "casalemedia.com", "pubmatic.com", "openx.net", "rubiconproject.com",
              "analytics", "tracking", "cdn."}


SWAGGER_PATHS = [
    "/openapi.json", "/swagger.json", "/swagger/v1/swagger.json", "/swagger/v2/swagger.json",
    "/api-docs", "/api/swagger.json", "/api/openapi.json", "/api/docs",
    "/swagger-ui.html", "/api/swagger-ui.html", "/swagger-resources",
    "/v1/api-docs", "/v2/api-docs", "/v3/api-docs",
    "/documentation", "/api/documentation",
    "/graphql", "/api/graphql", "/graphiql", "/api/graphiql",
]


class SmartRateLimiter:
    def __init__(self, base_delay=0.3):
        self.base_delay = base_delay
        self.current_delay = base_delay
        self.last_request_time = 0
        self.min_delay = 0.05
        self.max_delay = 8.0

    def wait(self):
        now = time.time()
        elapsed = now - self.last_request_time
        if elapsed < self.current_delay:
            time.sleep(self.current_delay - elapsed)
        jitter = random.uniform(-self.current_delay * 0.3, self.current_delay * 0.3)
        if jitter > 0:
            time.sleep(jitter)
        self.last_request_time = time.time()

    def report_status(self, status_code):
        if status_code in (429, 503, 0):
            self.current_delay = min(self.max_delay, self.current_delay * 1.5)
        elif status_code < 500:
            self.current_delay = max(self.min_delay, self.current_delay * 0.95)


@register_module
class APIFuzzModule(ReconModule):
    name = "apihunter"
    description = "Recursive API discovery: browser capture -> JS analysis -> OpenAPI -> pattern fuzzing"

    def run(self, target, threads=15, **kwargs):
        self.setup(target)
        target = target.rstrip("/")
        parsed = urlparse(target)
        if not parsed.scheme:
            target = "https://" + target
            parsed = urlparse(target)
        timeout = self.config.get("general", "timeout", default=8)

        session = requests.Session()
        session.headers["User-Agent"] = random_ua()
        rate_limiter = SmartRateLimiter(base_delay=0.4)
        found_endpoints = []
        processed = set()
        queue = [(target, parsed.netloc)]

        interrupted = False
        while queue:
            if interrupted:
                break
            cur_target, cur_domain = queue.pop(0)
            if cur_target in processed:
                continue
            processed.add(cur_target)
            self.log(f"\n{'='*50}\n[{len(processed)}] Scanning: {cur_target}\n{'='*50}")

            seeds = set()
            js_files = set()
            browser_calls = set()
            secrets = []
            source_maps = []
            swagger_spec = None
            api_bases = set()

            _spa_hashes = set()
            try:
                _sr = session.get(cur_target, timeout=timeout, allow_redirects=True)
                if _sr.status_code == 200 and len(_sr.content) > 100:
                    _spa_hashes.add(hashlib.md5(_sr.content).hexdigest())
                    # Detect app type
                    from core.utils import detect_app_type
                    _app_info = detect_app_type(_sr.text, dict(_sr.headers), cur_target)
                    if _app_info["type"] != "unknown" and len(processed) == 1:
                        self.log(f"  App type: {_app_info['type']}{' (' + _app_info['framework'] + ')' if _app_info['framework'] else ''}")
                        if _app_info["type"] == "api":
                            self.log("  API target: skipping browser capture, focusing on OpenAPI + fuzzing")
                for _probe_path in ["/__th_is_no_t_real__", "/api/__no_t_real__", "/.env.xyz_nonexistent"]:
                    try:
                        _pr = session.get(cur_target.rstrip("/") + _probe_path, timeout=timeout, allow_redirects=False)
                        if _pr.status_code == 200 and len(_pr.content) > 50:
                            _spa_hashes.add(hashlib.md5(_pr.content).hexdigest())
                    except Exception:
                        pass
            except Exception:
                pass

            # Phase 1: Browser capture
            self.log("Phase 1: Browser capture")
            _is_html = False
            try:
                _hr = session.head(cur_target, timeout=5, allow_redirects=True)
                _is_html = "html" in _hr.headers.get("Content-Type", "").lower()
            except Exception:
                pass

            _is_api_target = _app_info.get("type") == "api" if '_app_info' in dir() else not _is_html

            if _is_html and not _is_api_target:
                self.log("  HTML target detected")
                try:
                    from playwright.sync_api import sync_playwright
                    pw = sync_playwright().start()
                    browser = pw.chromium.launch(headless=True)
                    ctx = browser.new_context(user_agent=random_ua(), ignore_https_errors=True)
                    page = ctx.new_page()
                    captured = []

                    def on_req(r):
                        ru = r.url; rt = r.resource_type
                        pr = urlparse(ru)
                        if rt in ("xhr", "fetch", "websocket"):
                            captured.append({"m": r.method, "p": pr.path, "h": pr.netloc})
                        elif rt == "script" and ".js" in pr.path:
                            js_files.add(ru)

                    page.on("request", on_req)
                    try:
                        page.goto(cur_target, wait_until="networkidle", timeout=20000)
                    except Exception:
                        try:
                            page.goto(cur_target, timeout=15000)
                        except Exception:
                            pass
                    page.wait_for_timeout(2000)
                    try:
                        page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
                        page.wait_for_timeout(1000)
                    except Exception:
                        pass

                    for req in captured:
                        browser_calls.add(f"{req['m']}:{req['p']}")
                        p = req["p"].lstrip("/")
                        if p and len(p) > 3:
                            seeds.add(p)
                            if not any(d in req['h'] for d in _TRACKING):
                                api_bases.add(f"https://{req['h']}")
                    self.log(f"  Captured {len(captured)} XHR, {len(js_files)} JS")
                    if api_bases:
                        self.log(f"  API hosts: {', '.join(sorted(api_bases))}")
                    browser.close(); pw.stop()
                except KeyboardInterrupt:
                    interrupted = True
                except Exception as e:
                    self.log(f"  Browser capture: {e}")
            else:
                self.log("  API target, no browser capture")

            # Phase 2: OpenAPI discovery
            self.log("Phase 2: OpenAPI/Swagger discovery")
            _base = cur_target.rstrip("/")
            for sp in SWAGGER_PATHS:
                if swagger_spec:
                    break
                urls_to_try = [_base + sp]
                if not sp.startswith("/"):
                    urls_to_try.append(_base + "/" + sp)
                for full_url in urls_to_try:
                    try:
                        r = session.get(full_url, timeout=4, allow_redirects=False)
                        if r.status_code == 200:
                            try:
                                data = r.json()
                                paths = data.get("paths", {})
                                if paths:
                                    swagger_spec = data
                                    spec_base = data.get("servers", [{}])[0].get("url", cur_target)
                                    self.log(f"  Found spec: {len(paths)} paths")
                                    for ap, methods in paths.items():
                                        cp = ap.lstrip("/")
                                        seeds.add(cp)
                                        if isinstance(methods, dict):
                                            for mn in methods:
                                                u = f"{spec_base.rstrip('/')}/{cp}"
                                                try:
                                                    rate_limiter.wait()
                                                    mr = session.request(mn.upper(), u, timeout=timeout, allow_redirects=False,
                                                                        headers={"User-Agent": random_ua()})
                                                    rate_limiter.report_status(mr.status_code)
                                                    if mr.status_code not in (404, 0, 502, 503):
                                                        if _spa_hashes and mr.status_code == 200 and hashlib.md5(mr.content).hexdigest() in _spa_hashes:
                                                            continue
                                                        found_endpoints.append({"method": mn.upper(), "url": u, "path": cp,
                                                                                "status": mr.status_code, "size": len(mr.content),
                                                                                "content_type": mr.headers.get("Content-Type", "")[:50], "source": "openapi"})
                                                except Exception:
                                                    pass
                                    break
                            except (json.JSONDecodeError, AttributeError):
                                if "graphql" in sp.lower() and "data" in r.text[:200]:
                                    self.log(f"  GraphQL at {sp}")
                    except Exception:
                        pass
                    if swagger_spec:
                        break

            # Phase 3: JS analysis
            self.log("Phase 3: JavaScript analysis")
            if not js_files:
                try:
                    r = session.get(cur_target, timeout=timeout)
                    for m in re.finditer(r'<script[^>]+src=["\']([^"\']+)["\']', r.text, re.I):
                        ju = normalize_url(m.group(1).strip(), cur_target)
                        if ju and (".js" in ju or ".ts" in ju):
                            js_files.add(ju)
                except Exception:
                    pass

            self.log(f"  Analyzing {len(js_files)} JS files")

            def analyze_js(js_url):
                ls = set(); lsec = []; lsm = []
                try:
                    r = session.get(js_url, timeout=8)
                    c = r.text
                    for m in API_PATH_PATTERNS.finditer(c):
                        ep = m.group(1).strip("\"'`")
                        if len(ep) > 5: ls.add(ep.lstrip("/"))
                    for m in re.finditer(r'(?:fetch|axios|ajax|\.get\(|\.post\(|\.put\(|\.delete\(|\.patch\()[\s\n]*\(?[\s\n]*["\'`]([^"\'`]{3,})["\'`]', c, re.I):
                        ep = m.group(1)
                        if ep.startswith("http"):
                            pu = urlparse(ep); ls.add(pu.path.lstrip("/"))
                        elif not ep.startswith(("{", "<", "function")):
                            ls.add(ep.lstrip("/"))
                    for m in re.finditer(r'(?:baseURL|baseUrl|base_url|apiUrl|api_url|endpoint|apiPath)[\s:=]+["\'`]([^"\'`]{3,})["\'`]', c, re.I):
                        ls.add(m.group(1).lstrip("/"))
                    for m in re.finditer(r'//# sourceMappingURL=(.+)$', c, re.M):
                        sm = m.group(1).strip()
                        if sm.endswith(".map"): lsm.append(normalize_url(sm, js_url))
                    for m in SECRET_PATTERNS.finditer(c):
                        lsec.append((m.group(1), m.group(2)[:30]))
                except Exception:
                    pass
                return ls, lsec, lsm

            with ThreadPoolExecutor(max_workers=10) as exe:
                for f in as_completed({exe.submit(analyze_js, u): u for u in list(js_files)[:80]}):
                    sds, secs, sms = f.result()
                    seeds.update(sds)
                    secrets.extend(secs[:5]); source_maps.extend(sms)

            if source_maps:
                self.log(f"  Analyzing {len(source_maps)} source maps")
                for sm_url in source_maps[:20]:
                    try:
                        r = session.get(sm_url, timeout=8)
                        sm_data = r.json()
                        for src in (sm_data.get("sources", []) if isinstance(sm_data, dict) else []):
                            if "node_modules" not in src.lower() and re.search(r'/?(?:api|v[1-9]|rest|service)/', src, re.I):
                                seeds.add(src.lstrip("./").lstrip("/"))
                    except Exception:
                        pass

            seeds = {s for s in seeds if '${' not in s and 'called.' not in s and 'function' not in s[:10]}
            self.log(f"  Seeds: {len(seeds)}")

            # Extract API bases from full URLs in seeds
            for s in list(seeds):
                if s.startswith("http"):
                    pu = urlparse(s)
                    if pu.netloc and pu.netloc != cur_domain and not any(d in pu.netloc for d in _TRACKING):
                        api_bases.add(f"{pu.scheme}://{pu.netloc}")
                        seeds.discard(s)
                        if pu.path.strip("/"):
                            seeds.add(pu.path.lstrip("/"))

            # Phase 4: Pattern inference
            self.log("Phase 4: Pattern inference")
            inferred = set()
            for seed in list(seeds):
                inferred.add(seed)
                parts = seed.split("/")
                for part in parts:
                    pc = part.rstrip("s").rstrip("es")
                    for syns in REST_SYNONYMS.values():
                        if part in syns or pc in syns:
                            for s in syns:
                                if s != part: inferred.add(seed.replace(part, s))
                if not re.match(r'^v\d+$', parts[-1]):
                    for sub in ["list", "count", "me", "search", "status", "create", "update"]:
                        inferred.add(f"{seed}/{sub}")
                for i in range(len(parts)-1, 0, -1):
                    inferred.add("/".join(parts[:i]))

            infer_list = [p for p in inferred if p not in seeds and '${' not in p and 'called.' not in p][:1000]

            # Phase 5: Probing
            if infer_list:
                self.log(f"Phase 5: Probing {len(infer_list)} paths on {cur_target}")
                _lock = threading.Lock()
                scanned = [0]

                def test_path(path):
                    url = f"{cur_target}/{path}"
                    methods = ["GET", "POST"] if any(path.endswith(x) for x in ["create", "add", "register", "signup", "send"]) else ["GET"]
                    for method in methods:
                        try:
                            rate_limiter.wait()
                            r = session.request(method, url, timeout=timeout, allow_redirects=False,
                                                headers={"Content-Type": "application/json", "User-Agent": random_ua()})
                            rate_limiter.report_status(r.status_code)
                            if r.status_code in (429, 0): time.sleep(random.uniform(2, 5)); continue
                            if r.status_code not in (404, 405, 0, 502, 503):
                                if _spa_hashes and r.status_code == 200 and hashlib.md5(r.content).hexdigest() in _spa_hashes:
                                    return None
                                with _lock:
                                    found_endpoints.append({"method": method, "url": url, "path": path,
                                                            "status": r.status_code, "size": len(r.content),
                                                            "content_type": r.headers.get("Content-Type", "")[:50], "source": "fuzzing"})
                                return r.status_code
                        except requests.exceptions.ConnectionError:
                            return None
                        except Exception:
                            pass
                    return None

                try:
                    with ThreadPoolExecutor(max_workers=threads) as exe:
                        for f in as_completed({exe.submit(test_path, p): p for p in infer_list}):
                            with _lock:
                                scanned[0] += 1
                                if scanned[0] % 100 == 0:
                                    self.log(f"  Progress: {scanned[0]}/{len(infer_list)}")
                except KeyboardInterrupt:
                    interrupted = True

            # Enqueue discovered API bases for full pipeline
            for ab in api_bases:
                if any(d in ab for d in _TRACKING):
                    continue
                abp = urlparse(ab)
                if ab not in processed and ab not in [t[0] for t in queue]:
                    queue.append((ab, abp.netloc))
                    self.log(f"  Queued for full scan: {ab}")

        session.close()

        # Deduplicate
        seen = set(); unique = []
        for ep in sorted(found_endpoints, key=lambda x: x["path"]):
            k = (ep["method"], ep["url"])
            if k not in seen:
                seen.add(k); unique.append(ep)
        found_endpoints = unique

        self.results["interrupted"] = interrupted
        self.results["target"] = target
        self.results["browser_captured_calls"] = []
        self.results["endpoints_found"] = found_endpoints
        self.results["endpoints_count"] = len(found_endpoints)
        self.results["secrets_found"] = secrets[:10]

        status_groups = defaultdict(list)
        for ep in found_endpoints:
            status_groups[ep["status"]].append(ep)

        header = "API RECON SUMMARY (PARTIAL — INTERRUPTED)" if interrupted else "API RECON SUMMARY"
        print(f"\n{colored('='*60, 'magenta')}")
        print(f"{colored(header, 'bold')}")
        print(f"{colored('='*60, 'magenta')}")
        print(f"  Target:           {target}")
        print(f"  Targets scanned:  {len(processed)} ({', '.join(sorted(processed))})")
        srcs = []
        openapi_n = len([e for e in found_endpoints if e.get('source') == 'openapi'])
        fuzz_n = len([e for e in found_endpoints if e.get('source') == 'fuzzing'])
        if openapi_n: srcs.append(f"openapi={openapi_n}")
        if fuzz_n: srcs.append(f"fuzzing={fuzz_n}")
        if not srcs: srcs.append("no sources")
        print(f"  Sources:          {', '.join(srcs)}")
        print(f"  Endpoints found:  {len(found_endpoints)}")

        if found_endpoints:
            print(f"\n{colored(f'[!] LIVE ENDPOINTS ({len(found_endpoints)}):', 'bold')}")
            for st in sorted(status_groups.keys()):
                sc = colored(f"[{st}]", "green") if st < 300 else colored(f"[{st}]", "yellow") if st < 400 else colored(f"[{st}]", "red")
                print(f"    {sc}: {len(status_groups[st])} endpoints")
            for ep in found_endpoints:
                ms = colored(ep["method"].ljust(6), "cyan")
                sc = colored(str(ep["status"]), "green") if ep["status"] < 300 else colored(str(ep["status"]), "yellow") if ep["status"] < 400 else colored(str(ep["status"]), "red")
                print(f"    {ms} {sc}  {ep['url']}  ({ep['size']}b) [{ep.get('source','?')}]")

        self.teardown()
        return self.results
