import time
import threading
import requests
from bs4 import BeautifulSoup
from core.utils import normalize_url, get_domain, is_spa, random_ua, USER_AGENTS, URLFilter

STATIC_ONLY = 0
HYBRID = 1
PLAYWRIGHT_ONLY = 2


class StaticRenderer:
    def __init__(self, config, proxy=None):
        self.timeout = config.get("general", "timeout", default=10)
        self.max_retries = config.get("general", "max_retries", default=2)
        self.delay = config.get("general", "delay", default=0.3)
        self.proxy = proxy
        self.session = requests.Session()
        self.session.headers["User-Agent"] = random_ua()
        if proxy:
            self.session.proxies = {"http": proxy, "https": proxy}
        self._thread_local = threading.local()

    def _rate_limit(self):
        tl = self._thread_local
        last_req = getattr(tl, "last_req", 0)
        elapsed = time.time() - last_req
        if elapsed < self.delay:
            time.sleep(self.delay - elapsed)
        tl.last_req = time.time()

    def fetch(self, url, allow_redirects=True):
        for attempt in range(self.max_retries + 1):
            try:
                self._rate_limit()
                self.session.headers["User-Agent"] = random_ua()
                resp = self.session.get(
                    url,
                    timeout=self.timeout,
                    allow_redirects=allow_redirects,
                )
                return resp
            except requests.exceptions.Timeout:
                if attempt < self.max_retries:
                    time.sleep(1)
                    continue
            except Exception:
                return None
        return None

    def close(self):
        self.session.close()


class PlaywrightRenderer:
    def __init__(self, config, proxy=None):
        self.timeout = config.get("general", "timeout", default=10) * 1000
        self.delay = config.get("general", "delay", default=0.3)
        self.proxy = proxy
        self._browser = None
        self._playwright = None
        self._lock = threading.Lock()
        self._launched = False

    def _ensure_browser(self):
        if self._launched:
            return True
        with self._lock:
            if self._launched:
                return True
            try:
                from playwright.sync_api import sync_playwright
                self._playwright = sync_playwright().start()
                launch_opts = {
                    "headless": True,
                }
                if self.proxy:
                    launch_opts["proxy"] = {"server": self.proxy}
                self._browser = self._playwright.chromium.launch(**launch_opts)
                self._launched = True
                return True
            except Exception as e:
                print(f"[-] Failed to launch Playwright: {e}")
                return False

    def fetch(self, url, wait_until="networkidle"):
        if not self._ensure_browser():
            return None
        context = None
        page = None
        try:
            ctx_opts = {
                "user_agent": random_ua(),
                "ignore_https_errors": True,
            }
            context = self._browser.new_context(**ctx_opts)
            page = context.new_page()
            requests_captured = []

            def on_request(request):
                if request.resource_type in ("xhr", "fetch"):
                    requests_captured.append({
                        "url": request.url,
                        "method": request.method,
                        "resource_type": request.resource_type,
                    })

            page.on("request", on_request)
            page.goto(url, wait_until=wait_until, timeout=self.timeout)
            page.wait_for_timeout(2000)
            html = page.content()
            return {
                "html": html,
                "url": page.url,
                "title": page.title(),
                "xhr_requests": requests_captured,
                "cookies": context.cookies(),
            }
        except Exception as e:
            return None
        finally:
            if page:
                try:
                    page.close()
                except Exception:
                    pass
            if context:
                try:
                    context.close()
                except Exception:
                    pass

    def screenshot(self, url, path=None):
        if not self._ensure_browser():
            return None
        context = None
        page = None
        try:
            ctx_opts = {
                "user_agent": random_ua(),
                "ignore_https_errors": True,
            }
            context = self._browser.new_context(**ctx_opts)
            page = context.new_page()
            page.goto(url, wait_until="networkidle", timeout=self.timeout)
            page.wait_for_timeout(1000)
            if path:
                page.screenshot(path=path, full_page=True)
                return path
            else:
                return page.screenshot(full_page=True)
        except Exception:
            return None
        finally:
            if page:
                try:
                    page.close()
                except Exception:
                    pass
            if context:
                try:
                    context.close()
                except Exception:
                    pass

    def close(self):
        try:
            if self._browser:
                self._browser.close()
        except Exception:
            pass
        try:
            if self._playwright:
                self._playwright.stop()
        except Exception:
            pass
        self._launched = False


class HybridRenderer:
    def __init__(self, config):
        self.config = config
        self.mode = STATIC_ONLY
        js_render = config.get("crawler", "js_render", default=False)
        if js_render:
            self.mode = PLAYWRIGHT_ONLY
        self.static = StaticRenderer(config)
        self.playwright = None
        self._pw_available = None

    def _check_playwright(self):
        if self._pw_available is not None:
            return self._pw_available
        try:
            import playwright
            self._pw_available = True
        except ImportError:
            self._pw_available = False
        return self._pw_available

    def fetch(self, url):
        if self.mode == PLAYWRIGHT_ONLY:
            if not self._check_playwright():
                print("[-] Playwright not installed, falling back to static render")
                return self._static_fetch(url)
            if not self.playwright:
                self.playwright = PlaywrightRenderer(self.config)
            return self._pw_fetch(url)

        if self.mode == HYBRID:
            result = self._static_fetch(url)
            if result and result.get("html") and is_spa(result["html"]):
                if self._check_playwright():
                    if not self.playwright:
                        self.playwright = PlaywrightRenderer(self.config)
                    pw_result = self._pw_fetch(url)
                    if pw_result:
                        return pw_result
            return result

        return self._static_fetch(url)

    def _static_fetch(self, url):
        resp = self.static.fetch(url)
        if resp is None:
            return {"html": "", "url": url, "title": "", "status": 0, "headers": {}, "renderer": "static", "xhr_requests": [], "error": "request failed"}
        return {
            "html": resp.text,
            "url": resp.url,
            "title": "",
            "status": resp.status_code,
            "headers": dict(resp.headers),
            "renderer": "static",
            "xhr_requests": [],
            "cookies": [],
            "error": None,
        }

    def _pw_fetch(self, url):
        result = self.playwright.fetch(url)
        if result is None:
            return self._static_fetch(url)
        return {
            "html": result["html"],
            "url": result["url"],
            "title": result.get("title", ""),
            "status": 200,
            "headers": {},
            "renderer": "playwright",
            "xhr_requests": result.get("xhr_requests", []),
            "cookies": result.get("cookies", []),
            "error": None,
        }

    def screenshot(self, url, path=None):
        if not self._check_playwright():
            return None
        if not self.playwright:
            self.playwright = PlaywrightRenderer(self.config)
        return self.playwright.screenshot(url, path)

    def close(self):
        self.static.close()
        if self.playwright:
            self.playwright.close()
