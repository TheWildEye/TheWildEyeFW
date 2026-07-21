import os
import re
import json
import sys
import random
import time
import threading
from urllib.parse import urlparse, urljoin

if sys.platform == "win32":
    try:
        import colorama
        colorama.just_fix_windows_console()
    except ImportError:
        pass

HERE = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
URL_RE = re.compile(r'https?://[^\s"\'<>]+', re.I)
IP_RE = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
API_ENDPOINT_RE = re.compile(r'["\']/(?:api|v[1-9]|rest|graphql|graph|service|ws|socket|gateway)/[^"\'\\\s<>]*["\']', re.I)
SECRET_RE = re.compile(
    r'(?:(?:api|secret|token|key|password|auth)\s*[:=]\s*["\']([A-Za-z0-9_\-+=/]{16,64})["\'])'
)
AWS_KEY_RE = re.compile(r'(?:AKIA|ASIA)[A-Z0-9]{16}')
JWT_RE = re.compile(r'eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}')
FIREBASE_RE = re.compile(r'["\'](https?://[^"\']+?\.firebaseio\.com)["\']', re.I)
STRIPE_RE = re.compile(r'(?:sk_live|pk_live)_[A-Za-z0-9]{24,}')

SPA_INDICATORS = [
    '<div id="root"', '<div id="app"', '<div id="__next"', '<div id="__nuxt"',
    'ng-app', 'ng-version', 'react-root', '__NUXT__', '__NEXT_DATA__',
    'vue-app', '<app-', 'createApp', 'createRoot', 'ReactDOM',
    '<router-view', '<nuxt-', 'data-server-rendered',
]

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
]

BINARY_EXTS = {".png", ".jpg", ".jpeg", ".webp", ".svg", ".gif", ".webex", ".ico",
               ".mp4", ".mp3", ".avi", ".mov", ".pdf", ".zip", ".gz", ".tar",
               ".exe", ".dll", ".bin", ".woff", ".woff2", ".ttf", ".eot"}

TECH_PATTERNS = [
    ("React", re.compile(r'react(\.min)?\.js|__NEXT_DATA__|data-reactroot|_reactRoot', re.I)),
    ("Angular", re.compile(r'ng-version|angular(\.min)?\.js|ng-app', re.I)),
    ("Vue.js", re.compile(r'vue(\.min)?\.js|__NUXT__|vue-app', re.I)),
    ("Next.js", re.compile(r'__NEXT_DATA__|_next/static', re.I)),
    ("Nuxt.js", re.compile(r'__NUXT__|_nuxt/', re.I)),
    ("Gatsby", re.compile(r'___gatsby|gatsby\.js', re.I)),
    ("Svelte", re.compile(r'__svelte', re.I)),
    ("jQuery", re.compile(r'jquery(\.min)?\.js', re.I)),
    ("Bootstrap", re.compile(r'bootstrap(\.min)?\.(js|css)', re.I)),
    ("Tailwind CSS", re.compile(r'tailwindcss|@tailwind', re.I)),
    ("Django", re.compile(r'csrfmiddlewaretoken|__admin_media_prefix__', re.I)),
    ("Flask", re.compile(r'flask|{{[^}]+}}', re.I)),
    ("Laravel", re.compile(r'laravel|_token|Livewire', re.I)),
    ("WordPress", re.compile(r'wp-content|wp-admin|wp-json', re.I)),
    ("Drupal", re.compile(r'drupal|Drupal\.settings|sites/default', re.I)),
    ("Shopify", re.compile(r'myshopify\.com|shopify\.js', re.I)),
    ("Express", re.compile(r'express|connect\.sid', re.I)),
    ("nginx", re.compile(r'nginx', re.I)),
    ("Apache", re.compile(r'apache|\.htaccess', re.I)),
    ("Cloudflare", re.compile(r'cloudflare|cf-ray|__cfduid', re.I)),
    ("Google Analytics", re.compile(r'google-analytics\.com|gtag\(|ga\(', re.I)),
    ("Hotjar", re.compile(r'hotjar\.com|_hjSettings', re.I)),
    ("Stripe", re.compile(r'js\.stripe\.com|stripe\.js', re.I)),
    ("Facebook Pixel", re.compile(r'fbq\(|facebook\.com/tr', re.I)),
]


class RateLimiter:
    def __init__(self, calls_per_sec=5):
        self.min_interval = 1.0 / max(calls_per_sec, 0.1)
        self.last_call = 0
        self.lock = threading.Lock()

    def wait(self):
        with self.lock:
            elapsed = time.time() - self.last_call
            if elapsed < self.min_interval:
                time.sleep(self.min_interval - elapsed)
            self.last_call = time.time()


class URLFilter:
    def __init__(self, target_domain=None, same_domain=True):
        self.target_domain = target_domain
        self.same_domain = same_domain
        self.visited = set()
        self.queued = set()
        self.lock = threading.Lock()

    def is_valid(self, url):
        try:
            parsed = urlparse(url)
            if parsed.scheme not in ("http", "https"):
                return False
            if not parsed.netloc:
                return False
            if self.same_domain and self.target_domain:
                if parsed.netloc != self.target_domain and not parsed.netloc.endswith("." + self.target_domain):
                    return False
            ext = os.path.splitext(parsed.path)[1].lower()
            if ext in BINARY_EXTS:
                return False
            return True
        except Exception:
            return False

    def seen(self, url):
        return url in self.visited or url in self.queued

    def mark_seen(self, url):
        with self.lock:
            if url not in self.visited and url not in self.queued:
                self.queued.add(url)
                return True
        return False

    def mark_visited(self, url):
        with self.lock:
            self.queued.discard(url)
            self.visited.add(url)

    def count(self):
        return len(self.visited)


def normalize_url(url, base=None, preserve_slash=False):
    if not url or url.startswith(("javascript:", "mailto:", "tel:", "ftp:", "#")):
        return None
    url = url.strip().split("#")[0]
    if url.startswith("//"):
        url = "https:" + url
    elif url.startswith("/"):
        if base:
            parsed = urlparse(base)
            url = f"{parsed.scheme}://{parsed.netloc}{url}"
        else:
            return None
    elif not url.startswith(("http://", "https://")):
        if base:
            url = urljoin(base, url)
        else:
            url = "https://" + url
    try:
        parsed = urlparse(url)
        path = parsed.path if preserve_slash else parsed.path.rstrip("/") or "/"
        return f"{parsed.scheme}://{parsed.netloc}{path}{'?' + parsed.query if parsed.query else ''}"
    except Exception:
        return None


def get_domain(url):
    try:
        parsed = urlparse(url)
        return parsed.netloc.lower()
    except Exception:
        return None


def is_spa(html):
    if not html:
        return False
    return any(indicator in html for indicator in SPA_INDICATORS)


def detect_technologies(html, headers):
    found = []
    text = (html or "") + " " + " ".join(f"{k}:{v}" for k, v in (headers or {}).items())
    tag_text = " ".join(re.findall(r'<[^>]+>', text))
    script_text = " ".join(re.findall(r'<script[^>]*>.*?</script>', text, re.DOTALL))
    header_text = " ".join(f"{k}:{v}" for k, v in (headers or {}).items())
    combined = tag_text + " " + script_text + " " + header_text
    for name, pattern in TECH_PATTERNS:
        if pattern.search(combined):
            found.append(name)
    return sorted(set(found))


def random_ua():
    return random.choice(USER_AGENTS)


_NO_COLOR = os.environ.get("NO_COLOR") or os.environ.get("TERM") == "dumb"
if sys.platform == "win32" and not _NO_COLOR:
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
    except Exception:
        _NO_COLOR = True

def colored(text, color):
    if _NO_COLOR:
        return text
    colors = {
        "red": "\033[91m",
        "green": "\033[92m",
        "yellow": "\033[93m",
        "blue": "\033[94m",
        "magenta": "\033[95m",
        "cyan": "\033[96m",
        "white": "\033[97m",
        "gray": "\033[90m",
        "bold": "\033[1m",
        "reset": "\033[0m",
    }
    c = colors.get(color, "")
    reset = colors["reset"]
    return f"{c}{text}{reset}"


def safe_path(base, *parts):
    resolved = os.path.realpath(os.path.join(base, *parts))
    base_real = os.path.realpath(base)
    if not resolved.startswith(base_real):
        raise ValueError(f"Path traversal detected: {resolved} not under {base_real}")
    return resolved


def strip_html_comments(html):
    return re.sub(r'<!--.*?-->', '', html, flags=re.DOTALL)


def extract_from_script_tags(html):
    scripts = re.findall(r'<script[^>]*>(.*?)</script>', html, re.I | re.S)
    return "\n".join(scripts)


# Terminal animations

_USE_ASCII = False
try:
    "\u2713".encode(sys.stdout.encoding or "utf-8")
except (UnicodeEncodeError, UnicodeDecodeError):
    _USE_ASCII = True

SPINNER_FRAMES = ["|", "/", "-", "\\"] if _USE_ASCII else ["\u280b", "\u2819", "\u2839", "\u2838", "\u283c", "\u2834", "\u2826", "\u2827", "\u280f", "\u2801"]
SPINNER_FRAMES_DOTS = ["|", "/", "-", "\\"] if _USE_ASCII else ["\u28fe", "\u28fd", "\u28fb", "\u28a7", "\u287f", "\u285f", "\u28af", "\u28ef"]
SPINNER_FRAMES_CLASSIC = ["-", "\\", "|", "/"]
_DONE_ICON = "OK" if _USE_ASCII else "\u2713"


class Spinner:
    def __init__(self, msg="", style="classic", color="green"):
        self._msg = msg
        self._frames = {"dots": SPINNER_FRAMES, "blocks": SPINNER_FRAMES_DOTS, "classic": SPINNER_FRAMES_CLASSIC}.get(style, SPINNER_FRAMES)
        self._color = color
        self._running = False
        self._thread = None

    def start(self):
        self._running = True
        self._thread = threading.Thread(target=self._spin, daemon=True)
        self._thread.start()

    def _spin(self):
        i = 0
        while self._running:
            frame = colored(self._frames[i % len(self._frames)], self._color)
            sys.stdout.write(f"\r{frame} {self._msg}  ")
            sys.stdout.flush()
            time.sleep(0.08)
            i += 1

    def stop(self, done_msg="done"):
        self._running = False
        if self._thread:
            self._thread.join(timeout=0.3)
        sys.stdout.write(f"\r{colored(_DONE_ICON, 'green')} {self._msg}: {done_msg}  \n")
        sys.stdout.flush()

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *args):
        self.stop()


def typewriter(text, color="green", delay=0.003, end="\n"):
    for ch in text:
        sys.stdout.write(colored(ch, color))
        sys.stdout.flush()
        time.sleep(delay)
    sys.stdout.write(end)


def matrix_line(text, color="green", delay=0.015):
    for i, ch in enumerate(text):
        prefix = text[:i]
        rest = " " * (len(text) - i)
        sys.stdout.write(f"\r{colored(prefix + ch, color)}{rest}")
        sys.stdout.flush()
        time.sleep(delay)
    sys.stdout.write(f"\r{colored(text, color)}\n")


def hide_cursor():
    sys.stdout.write("\033[?25l")
    sys.stdout.flush()


def show_cursor():
    sys.stdout.write("\033[?25h")
    sys.stdout.flush()


def status_tag(text, status="info"):
    colors = {"info": "cyan", "ok": "green", "warn": "yellow", "error": "red", "bold": "bold"}
    icons = {"info": "*", "ok": "+", "warn": "!", "error": "x", "bold": "#"}
    c = colors.get(status, "cyan")
    i = icons.get(status, "*")
    return f"[{colored(i, c)}] {text}"


APP_TYPE_CMS_INDICATORS = {
    "WordPress": [re.compile(r'wp-content|wp-admin|wp-json|wp-includes', re.I)],
    "Drupal": [re.compile(r'drupal|Drupal\.settings|sites/default', re.I)],
    "Joomla": [re.compile(r'joomla|com_content|com_users', re.I)],
    "Laravel": [re.compile(r'laravel|_token|Livewire|livewire', re.I)],
    "Django": [re.compile(r'csrfmiddlewaretoken|__admin_media_prefix__', re.I)],
    "Flask": [re.compile(r'flask|{{[^}]+}}', re.I)],
    "ASP.NET": [re.compile(r'__VIEWSTATE|__EVENTVALIDATION|aspnetForm', re.I)],
}

SPA_FRAMEWORK_INDICATORS = [
    (re.compile(r'__NEXT_DATA__|_next/static', re.I), "Next.js"),
    (re.compile(r'__NUXT__|_nuxt/', re.I), "Nuxt.js"),
    (re.compile(r'data-reactroot|_reactRoot|react\.(min\.)?js', re.I), "React"),
    (re.compile(r'ng-version|angular\.(min\.)?js|ng-app', re.I), "Angular"),
    (re.compile(r'vue(\.min)?\.js|vue-app', re.I), "Vue.js"),
    (re.compile(r'__svelte', re.I), "Svelte"),
    (re.compile(r'gatsby', re.I), "Gatsby"),
]


def detect_app_type(html, headers=None, url=""):
    """
    Classify a web application by analyzing its HTML and response headers.

    Returns dict with keys:
      type: 'spa' | 'traditional' | 'api' | 'static' | 'unknown'
      framework: str or None
      confidence: int 0-100
      details: dict with indicators found
    """
    result = {"type": "unknown", "framework": None, "confidence": 0, "details": {}}
    if not html:
        return result

    ct = (headers or {}).get("Content-Type", "").lower()
    html_lower = html.lower()

    # API-only: JSON/XML responses with no HTML
    if "json" in ct or "xml" in ct:
        if "<!DOCTYPE html" not in html[:200] and "<html" not in html[:200]:
            result["type"] = "api"
            result["confidence"] = 85
            result["details"]["content_type"] = ct
            return result

    # SPA detection
    spa_matches = [i for i in SPA_INDICATORS if i in html]
    if spa_matches:
        result["type"] = "spa"
        result["confidence"] = min(90, 50 + len(spa_matches) * 10)
        result["details"]["spa_indicators"] = spa_matches
        for pattern, name in SPA_FRAMEWORK_INDICATORS:
            if pattern.search(html):
                result["framework"] = name
                result["details"]["framework_match"] = name
                break
        return result

    # Traditional CMS detection
    cms_matches = []
    for name, patterns in APP_TYPE_CMS_INDICATORS.items():
        for pat in patterns:
            if pat.search(html_lower):
                cms_matches.append(name)
                break
    if cms_matches:
        result["type"] = "traditional"
        result["framework"] = cms_matches[0]
        result["confidence"] = 75
        result["details"]["cms"] = cms_matches
        return result

    # Server-side framework via headers
    server = (headers or {}).get("Server", "").lower()
    x_powered = (headers or {}).get("X-Powered-By", "").lower()
    header_hints = f"{server} {x_powered}"
    if "php" in header_hints:
        result["type"] = "traditional"
        result["framework"] = "PHP"
        result["confidence"] = 60
        return result
    if "asp.net" in header_hints or "iis" in header_hints:
        result["type"] = "traditional"
        result["framework"] = "ASP.NET"
        result["confidence"] = 60
        return result
    if "java" in header_hints or "tomcat" in header_hints or "jetty" in header_hints:
        result["type"] = "traditional"
        result["framework"] = "Java"
        result["confidence"] = 60
        return result

    # Static site heuristic: minimal JS, small HTML
    script_count = len(re.findall(r'<script[^>]*>', html, re.I))
    has_doctype = "<!DOCTYPE html" in html[:100]
    if has_doctype and script_count <= 2 and len(html) < 30000:
        result["type"] = "static"
        result["confidence"] = 45
        result["details"]["script_count"] = script_count
        return result

    # Fallback — has HTML but no strong signals
    result["type"] = "traditional"
    result["confidence"] = 25
    result["details"]["fallback_script_count"] = script_count
    return result
