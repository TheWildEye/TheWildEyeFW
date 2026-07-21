import re
import hashlib
import requests
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

from core.engine import ReconModule, register_module
from core.utils import random_ua, colored, TECH_PATTERNS, SPA_INDICATORS


@register_module
class TechDetectModule(ReconModule):
    name = "techhunter"
    description = "Technology fingerprinting - detects CMS, frameworks, libraries, CDN, analytics"

    def run(self, target):
        self.setup(target)

        session = requests.Session()
        session.headers["User-Agent"] = random_ua()
        timeout = self.config.get("general", "timeout", default=10)

        technologies = {}
        headers = {}
        html_content = ""
        final_url = target
        status = 0

        self.log(f"Fingerprinting technologies for {target}")

        try:
            resp = session.get(target, timeout=timeout, allow_redirects=True)
            html_content = resp.text
            headers = dict(resp.headers)
            final_url = resp.url
            status = resp.status_code
        except Exception as e:
            self.error(f"Failed to fetch {target}: {e}")
            self.results["error"] = str(e)
            self.teardown()
            return self.results

        html_lower = html_content.lower()
        headers_text = " ".join(f"{k}:{v}" for k, v in headers.items()).lower()

        # Only search in HTML tags/attributes and headers, not body text content
        tag_text = " ".join(re.findall(r'<[^>]+>', html_lower)) + " " + headers_text
        script_text = " ".join(re.findall(r'<script[^>]*>.*?</script>', html_lower, re.DOTALL))
        combined = tag_text + " " + script_text + " " + headers_text

        for name, pattern in TECH_PATTERNS:
            if pattern.search(combined):
                technologies[name] = {"source": "pattern_match"}

        for indicator in SPA_INDICATORS:
            if indicator in html_content:
                if "SPA Framework" not in technologies:
                    technologies["SPA Framework"] = {"source": "indicator"}
                break

        server = headers.get("Server", "")
        if server:
            technologies["Server"] = {"source": "header", "value": server}
        x_powered = headers.get("X-Powered-By", "")
        if x_powered:
            technologies["X-Powered-By"] = {"source": "header", "value": x_powered}

        common_checks = {
            "/wp-admin": "WordPress Admin", "/wp-json": "WordPress REST API",
            "/administrator": "Joomla", "/user/login": "Drupal Login",
            "/graphql": "GraphQL", "/swagger.json": "Swagger/OpenAPI",
            "/api-docs": "API Docs", "/.env": "Env File",
            "/robots.txt": "robots.txt", "/sitemap.xml": "Sitemap",
            "/.git/HEAD": "Git Exposed", "/.DS_Store": "macOS Metadata",
        }

        _root_hash = hashlib.md5(html_content.encode()).hexdigest()

        def check_path(path, name):
            try:
                check_url = f"{final_url.rstrip('/')}{path}"
                cr = session.get(check_url, timeout=3, allow_redirects=False)
                if cr.status_code in (200, 301, 302, 403, 401):
                    if cr.status_code == 200 and hashlib.md5(cr.content).hexdigest() == _root_hash:
                        return None
                    return (name, cr.status_code, path)
            except Exception:
                pass
            return None

        with ThreadPoolExecutor(max_workers=8) as exe:
            fut = {exe.submit(check_path, p, n): p for p, n in common_checks.items()}
            for f in as_completed(fut):
                r = f.result()
                if r:
                    technologies[r[0]] = {"source": "url_check", "status": r[1], "path": r[2]}

        parsed = urlparse(final_url)
        if ".php" in parsed.path or re.search(r'\.php(?:[?/]|$)', final_url, re.I):
            technologies["PHP"] = {"source": "inference"}
        if ".aspx" in parsed.path or re.search(r'\.aspx?(?:[?/]|$)', final_url, re.I):
            technologies["ASP.NET"] = {"source": "inference"}
        if ".jsp" in parsed.path or re.search(r'\.jsp(?:[?/]|$)', final_url, re.I):
            technologies["Java/JSP"] = {"source": "inference"}

        self.results["target"] = target
        self.results["final_url"] = final_url
        self.results["status_code"] = status
        self.results["technologies"] = technologies
        self.results["technologies_list"] = sorted(technologies.keys())

        print(f"\n{colored('='*60, 'blue')}")
        print(f"{colored('TECH DETECTION SUMMARY', 'bold')}")
        print(f"{colored('='*60, 'blue')}")
        print(f"  Target:       {target}")
        print(f"  Final URL:    {final_url}")
        print(f"  Status:       {status}")
        print(f"  Technologies: {len(technologies)} found")
        for name, info in sorted(technologies.items()):
            src = info.get("source", "")
            if src == "url_check":
                st = info.get("status", "")
                p = info.get("path", "")
                extra = f" {colored(f'[{st}]', 'yellow')} {p}"
            else:
                extra = f" ({info.get('value', src)})"
            print(f"    {colored('[+]', 'green')} {name}{extra}")

        session.close()
        self.teardown()
        return self.results
