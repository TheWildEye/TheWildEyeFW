import os
import re
import time
import queue
import threading
from urllib.parse import urlparse, urljoin

from bs4 import BeautifulSoup

_has_lxml = True
try:
    import lxml
except ImportError:
    _has_lxml = False
_PARSER = "lxml" if _has_lxml else "html.parser"

from core.engine import ReconModule, register_module
from core.utils import (
    normalize_url, get_domain, EMAIL_RE, BINARY_EXTS, is_spa,
    detect_technologies, random_ua, URLFilter, colored,
    strip_html_comments, extract_from_script_tags, API_ENDPOINT_RE,
    SECRET_RE, AWS_KEY_RE, JWT_RE, FIREBASE_RE, STRIPE_RE,
)
from core.renderer import HybridRenderer


@register_module
class CrawlerModule(ReconModule):
    name = "mailhunter"
    description = "Intelligent web crawler with JS rendering support"

    def run(self, target, js_render=None, **kwargs):
        self.setup(target)
        config = self.config

        parsed = urlparse(target)
        target_domain = parsed.netloc
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        max_urls = config.get("crawler", "max_urls", default=500)
        max_depth = kwargs.get("depth", config.get("crawler", "max_depth", default=3))
        extract_emails = config.get("crawler", "extract_emails", default=True)
        extract_links = config.get("crawler", "extract_links", default=True)
        extract_js = config.get("crawler", "extract_js", default=True)
        extract_forms = config.get("crawler", "extract_forms", default=True)
        extract_comments = config.get("crawler", "extract_comments", default=True)
        same_domain = config.get("crawler", "same_domain_only", default=True)
        js_render = js_render if js_render is not None else config.get("crawler", "js_render", default=False)
        config.data.setdefault("crawler", {})["js_render"] = js_render

        to_visit = queue.Queue()
        url_filter = URLFilter(target_domain=target_domain, same_domain=same_domain)
        lock = threading.Lock()
        _stop_event = threading.Event()

        _TRACKING_DOMAINS = {"google-analytics.com", "googletagmanager.com", "facebook.com",
                             "doubleclick.net", "gtag", "analytics", "tracking", "cdn.",
                             "cloudfront.net", "hotjar.com", "newrelic.com", "datadog",
                             "hubapi.com", "hscollectedforms.net", "hsforms.com", "hs-banner.com",
                             "gokwik.co", "gumlet.io", "ads.linkedin.com", "linkedin.com"}

        emails = {}       # email -> source_url
        forms = []
        js_files = set()
        technologies = set()
        api_endpoints = set()
        secrets_found = []
        comments_found = []
        all_urls = []
        depth_map = {}
        crawl_stats = {"errors": 0, "spa_detected": 0, "js_rendered": 0}

        renderer = HybridRenderer(config)
        session = renderer.static.session

        def enqueue(url, depth=0):
            if _stop_event.is_set():
                return
            valid = normalize_url(url, target)
            if not valid:
                return
            if depth > max_depth:
                return
            if url_filter.seen(valid):
                return
            if url_filter.mark_seen(valid):
                with lock:
                    depth_map[valid] = depth
                to_visit.put((valid, depth))

        enqueue(target, depth=0)

        def process_page(url, depth):
            nonlocal crawl_stats
            indent = "  " * depth
            self.log(f"{indent}[{url_filter.count()}] Crawling: {url}")

            result = renderer.fetch(url)
            if result is None or result.get("error"):
                with lock:
                    crawl_stats["errors"] += 1
                return

            html = result.get("html", "")
            final_url = result.get("url", url)
            title = result.get("title", "")
            renderer_used = result.get("renderer", "static")
            xhr_reqs = result.get("xhr_requests", [])

            if renderer_used == "playwright":
                with lock:
                    crawl_stats["js_rendered"] += 1

            # Check for SPA
            if is_spa(html):
                with lock:
                    crawl_stats["spa_detected"] += 1

            # Detect technologies
            techs = detect_technologies(html, {})
            with lock:
                technologies.update(techs)

            # Extract title
            if not title and html:
                m = re.search(r'<title>([^<]+)</title>', html, re.I)
                if m:
                    title = m.group(1).strip()

            # Extract emails — filter out version strings, build tags, non-email matches
            if extract_emails and html:
                _email_blacklist = re.compile(r'(?:example|test|domain|sample|yourname|localhost|acme|dummy)\.', re.I)
                found_emails = set(EMAIL_RE.findall(html))
                found_emails = {e for e in found_emails
                                if not re.search(r'@\d+\.\d+', e)
                                and not any(c in e for c in '{}[]<>|')
                                and not e.lower().endswith(('.png', '.jpg', '.jpeg', '.gif', '.svg', '.css', '.js'))
                                and not _email_blacklist.search(e)}
                soup = BeautifulSoup(html, _PARSER)
                for a in soup.find_all("a", href=True):
                    href = a["href"].strip()
                    if href.lower().startswith("mailto:"):
                        email_part = href[7:].split("?")[0]
                        if EMAIL_RE.match(email_part):
                            found_emails.add(email_part)
                for meta in soup.find_all("meta", attrs={"name": re.compile(r"author", re.I)}):
                    content = meta.get("content", "")
                    found_emails.update(EMAIL_RE.findall(content))
                with lock:
                    for e in found_emails:
                        if e not in emails:
                            emails[e] = url

            # Extract API endpoints from XHR requests (filter out analytics/tracking)
            for xhr in xhr_reqs:
                api_url = xhr.get("url", "")
                if api_url and not any(d in api_url for d in _TRACKING_DOMAINS):
                    parsed_u = urlparse(api_url)
                    if any(ext in parsed_u.path.lower() for ext in ["api", "graphql", "rest", "v1", "v2", "auth", "user", "payment"]) or parsed_u.path.count("/") >= 2:
                        with lock:
                            api_endpoints.add(api_url)

            # Extract API endpoints from inline scripts
            if html:
                script_text = extract_from_script_tags(html)
                api_matches = API_ENDPOINT_RE.findall(script_text)
                for match in api_matches:
                    clean = match.strip('"').strip("'")
                    if clean and not any(d in clean for d in _TRACKING_DOMAINS):
                        with lock:
                            api_endpoints.add(clean)

            # Extract secrets from inline scripts
            if html:
                script_text = extract_from_script_tags(html)
                for pattern, name in [
                    (AWS_KEY_RE, "AWS Key"), (JWT_RE, "JWT Token"),
                    (FIREBASE_RE, "Firebase URL"), (STRIPE_RE, "Stripe Key"),
                    (SECRET_RE, "Generic Secret"),
                ]:
                    for match in pattern.finditer(script_text):
                        with lock:
                            secrets_found.append({"type": name, "value": match.group(0)[:80], "url": url})

            # Extract forms
            if extract_forms and html:
                soup = BeautifulSoup(html, _PARSER)
                for form_tag in soup.find_all("form"):
                    form_info = {
                        "source_url": url,
                        "action": form_tag.get("action", ""),
                        "method": form_tag.get("method", "GET").upper(),
                        "inputs": [],
                    }
                    for inp in form_tag.find_all(["input", "textarea", "select"]):
                        inp_type = inp.get("type", "text")
                        inp_name = inp.get("name", "")
                        if inp_name:
                            form_info["inputs"].append({"type": inp_type, "name": inp_name})
                    if form_info["inputs"]:
                        with lock:
                            forms.append(form_info)

            # Extract HTML comments (security-relevant only)
            if extract_comments and html:
                html_comments = re.findall(r'<!--(.*?)-->', html, re.DOTALL)
                _interest = re.compile(r'\b(todo|fixme|hack|remove|password|secret|api|endpoint|key|token|'
                                       r'bug|deprecated|private|debug)\b', re.I)
                for comment in html_comments:
                    stripped = comment.strip()
                    if stripped and len(stripped) > 8 and _interest.search(stripped):
                        with lock:
                            comments_found.append(stripped[:200].strip())

            # Extract JS files
            if extract_js and html:
                soup = BeautifulSoup(html, _PARSER)
                for script in soup.find_all("script", src=True):
                    js_src = script["src"].strip()
                    js_url = normalize_url(js_src, target)
                    if js_url and get_domain(js_url) == target_domain:
                        with lock:
                            js_files.add(js_url)

            # Extract links
            if extract_links and html:
                soup = BeautifulSoup(html, _PARSER)
                for a in soup.find_all("a", href=True):
                    href = a["href"].strip()
                    if href.startswith(("mailto:", "tel:", "#", "javascript:", "ftp:")):
                        continue
                    link = normalize_url(href, url)
                    if link and url_filter.is_valid(link):
                        link_domain = get_domain(link)
                        if same_domain and link_domain != target_domain and not link_domain.endswith("." + target_domain):
                            continue
                        enqueue(link, depth + 1)

            with lock:
                url_filter.mark_visited(url)
                all_urls.append({"url": url, "title": title, "depth": depth, "renderer": renderer_used})

        # Worker threads
        num_workers = min(config.get("general", "max_threads", default=10), 20)
        threads = []

        def worker():
            while not _stop_event.is_set():
                try:
                    item = to_visit.get(timeout=1)
                except queue.Empty:
                    return
                if item is None:
                    to_visit.task_done()
                    return
                url, depth = item
                process_page(url, depth)
                to_visit.task_done()
                if url_filter.count() >= max_urls:
                    _stop_event.set()
                    break

        for _ in range(num_workers):
            t = threading.Thread(target=worker, daemon=True)
            t.start()
            threads.append(t)

        interrupted = False
        try:
            to_visit.join()
        except KeyboardInterrupt:
            self.log("Interrupted by user", "yellow")
            _stop_event.set()
            interrupted = True

        try:
            for _ in threads:
                try:
                    to_visit.put_nowait(None)
                except queue.Full:
                    pass
            for t in threads:
                t.join(timeout=2)
        except KeyboardInterrupt:
            interrupted = True

        renderer.close()

        # Collect results
        try:
            self.results["target"] = target
            self.results["domain"] = target_domain
            self.results["total_urls_crawled"] = url_filter.count()
            self.results["technologies_detected"] = sorted(technologies) if technologies else ["None detected"]
            self.results["emails_found"] = [{"email": e, "source": s} for e, s in sorted(emails.items())] if emails else []
            self.results["email_domains"] = sorted(set(e.split("@")[1] for e in emails)) if emails else []
            self.results["js_files_found"] = sorted(js_files) if js_files else []
            self.results["forms_discovered"] = forms if forms else []
            self.results["forms_count"] = len(forms)
            self.results["api_endpoints_discovered"] = sorted(api_endpoints) if api_endpoints else []
            self.results["secrets_found"] = secrets_found if secrets_found else []
            self.results["html_comments_found"] = comments_found if comments_found else []
            self.results["crawl_stats"] = crawl_stats
        except KeyboardInterrupt:
            interrupted = True

        # Display summary
        try:
            header = "CRAWL SUMMARY (PARTIAL — INTERRUPTED)" if interrupted else "CRAWL SUMMARY"
            print(f"\n{colored('='*60, 'cyan')}")
            print(f"{colored(header, 'bold')}")
            print(f"{colored('='*60, 'cyan')}")
            print(f"  Target:        {target}")
            print(f"  URLs crawled:  {url_filter.count()}")

            if technologies:
                print(f"\n{colored('[!] TECHNOLOGIES DETECTED:', 'bold')}")
                for t in sorted(technologies):
                    print(f"    {colored('+', 'green')} {t}")

            if emails:
                print(f"\n{colored('[!] EMAILS FOUND:', 'bold')}")
                for e, src in sorted(emails.items()):
                    print(f"    {colored(e, 'cyan')}  ({src})")

            if js_files:
                print(f"\n{colored('[!] JS FILES:', 'bold')}")
                for j in sorted(js_files):
                    print(f"    {colored(j, 'yellow')}")

            if forms:
                print(f"\n{colored('[!] FORMS DISCOVERED:', 'bold')}")
                for f_item in forms:
                    src = f_item.get('source_url', 'unknown')
                    print(f"    {colored('FORM', 'cyan')} action={f_item.get('action','')} method={f_item.get('method','GET')} inputs={len(f_item.get('inputs',[]))}  (page: {src})")

            if api_endpoints:
                print(f"\n{colored('[!] API ENDPOINTS DISCOVERED:', 'bold')}")
                for ep in sorted(api_endpoints):
                    print(f"    {colored(ep, 'magenta')}")

            if secrets_found:
                print(f"\n{colored('[!] POTENTIAL SECRETS:', 'bold')}")
                for s in secrets_found:
                    print(f"    {colored('[!]', 'red')} {s}")

            if comments_found:
                print(f"\n{colored('[!] HTML COMMENTS:', 'bold')}")
                for c in comments_found:
                    print(f"    {colored('<!--', 'gray')} {c} {colored('-->', 'gray')}")

            print(f"\n  Crawl stats:   {crawl_stats['js_rendered']} JS rendered / {crawl_stats['spa_detected']} SPA / {crawl_stats['errors']} errors")
        except KeyboardInterrupt:
            pass

        self.teardown()
        return self.results
