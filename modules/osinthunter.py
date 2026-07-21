import re
import json
import hashlib
import requests
from urllib.parse import urlparse, quote
from concurrent.futures import ThreadPoolExecutor, as_completed

from core.engine import ReconModule, register_module
from core.utils import colored, random_ua


SOCIAL_PLATFORMS = [
    ("GitHub", "https://github.com/{}"),
    ("Twitter/X", "https://twitter.com/{}"),
    ("Instagram", "https://www.instagram.com/{}"),
    ("Reddit", "https://www.reddit.com/user/{}"),
    ("LinkedIn", "https://www.linkedin.com/in/{}"),
    ("YouTube", "https://www.youtube.com/@{}"),
    ("Medium", "https://medium.com/@{}"),
    ("Dev.to", "https://dev.to/{}"),
    ("Twitch", "https://www.twitch.tv/{}"),
    ("Pinterest", "https://www.pinterest.com/{}"),
    ("TikTok", "https://www.tiktok.com/@{}"),
    ("Keybase", "https://keybase.io/{}"),
    ("Telegram", "https://t.me/{}"),
    ("Facebook", "https://www.facebook.com/{}"),
    ("HackerNews", "https://news.ycombinator.com/user?id={}"),
    ("ProductHunt", "https://www.producthunt.com/@{}"),
    ("Behance", "https://www.behance.net/{}"),
    ("Dribbble", "https://dribbble.com/{}"),
    ("Hashnode", "https://hashnode.com/@{}"),
    ("CodePen", "https://codepen.io/{}"),
    ("Replit", "https://replit.com/@{}"),
    ("GitLab", "https://gitlab.com/{}"),
    ("BitBucket", "https://bitbucket.org/{}"),
    ("VK", "https://vk.com/{}"),
    ("Patreon", "https://www.patreon.com/{}"),
    ("BuyMeACoffee", "https://www.buymeacoffee.com/{}"),
    ("Chess.com", "https://www.chess.com/member/{}"),
    ("AngelList", "https://angel.co/u/{}"),
    ("Flickr", "https://www.flickr.com/people/{}"),
    ("StackOverflow", "https://stackoverflow.com/users/{}"),
]


def _is_email(val):
    return bool(re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', val.strip()))


def _is_domain(val):
    val = val.strip().lower()
    if val.startswith(("http://", "https://")):
        val = urlparse(val).netloc
    return bool(re.match(r'^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?\.[a-z]{2,}$', val))


def _is_username(val):
    val = val.strip()
    return bool(re.match(r'^[a-zA-Z0-9_\-\.]{3,50}$', val)) and not _is_email(val) and not _is_domain(val)


def _clean_target(val):
    val = val.strip()
    if val.startswith(("http://", "https://")):
        val = urlparse(val).netloc
    return val.split("/")[0].split("?")[0]


NOT_FOUND_SIGNALS = ["page not found", "doesn't exist", "no one here", "this page isn't available",
                     "couldn't find", "not found", "page doesn't exist", "no user", "user not found",
                     "this account doesn", "could not find", "the page you requested was not found",
                     "404", "page is not available", "this profile is not available",
                     "this page does not exist", "no profile found"]


def _check_url(url, timeout=4):
    try:
        r = requests.get(url, timeout=timeout, allow_redirects=False, headers={"User-Agent": random_ua()})
        if r.status_code != 200:
            return r.status_code, r
        body_lower = (r.text[:2000] if r.text else "").lower()
        if any(signal in body_lower for signal in NOT_FOUND_SIGNALS):
            return 404, r
        return r.status_code, r
    except Exception:
        return None, None


@register_module
class OSINTHunterModule(ReconModule):
    name = "osinthunter"
    description = "OSINT recon - email, username & domain intelligence"

    def run(self, target):
        self.setup(target)
        target_clean = _clean_target(target)

        if _is_email(target_clean):
            self.log(f"Email OSINT on {target_clean}")
            results = self._email_osint(target_clean)
        elif _is_domain(target_clean):
            self.log(f"Domain OSINT on {target_clean}")
            results = self._domain_osint(target_clean)
        elif _is_username(target_clean):
            self.log(f"Username OSINT on {target_clean}")
            results = self._username_osint(target_clean)
        else:
            self.log(f"Username OSINT on {target_clean}")
            results = self._username_osint(target_clean)

        self.results = results
        self._display(results, target_clean)
        self.teardown()
        return self.results

    def _gravatar(self, email):
        md5 = hashlib.md5(email.lower().encode()).hexdigest()
        url = f"https://www.gravatar.com/avatar/{md5}.json"
        _, resp = _check_url(url)
        if resp and resp.status_code == 200:
            try:
                data = resp.json()
                entry = data.get("entry", [{}])[0]
                accounts = []
                for a in entry.get("accounts", []):
                    if a.get("url"):
                        accounts.append({"platform": a.get("shortname", ""), "url": a["url"]})
                return {
                    "profile_url": f"https://www.gravatar.com/{md5}",
                    "avatar_url": f"https://www.gravatar.com/avatar/{md5}?s=500",
                    "display_name": entry.get("displayName", ""),
                    "location": entry.get("currentLocation", ""),
                    "accounts": accounts,
                }
            except Exception:
                pass
        return None

    def _decode_ddg_url(self, url):
        m = re.search(r'uddg=([^&]+)', url)
        if m:
            from urllib.parse import unquote
            return unquote(m.group(1))
        return url

    def _duckduckgo_search(self, email):
        try:
            r = requests.get(
                f"https://api.duckduckgo.com/?q={quote(email)}&format=json&no_html=1",
                timeout=8,
                headers={"User-Agent": random_ua()},
            )
            if r.status_code == 200:
                data = r.json()
                results = []
                for topic in data.get("RelatedTopics", []):
                    if "FirstURL" in topic:
                        results.append(topic["FirstURL"])
                    elif "Topics" in topic:
                        for sub in topic["Topics"]:
                            if "FirstURL" in sub:
                                results.append(sub["FirstURL"])
                if data.get("AbstractURL"):
                    results.append(data["AbstractURL"])
                return list(dict.fromkeys(results))[:15] if results else None
        except Exception:
            pass
        return None

    def _leakcheck(self, email):
        try:
            r = requests.get(
                f"https://leakcheck.io/api/public?check={quote(email)}",
                timeout=8,
                headers={"User-Agent": random_ua(), "Accept": "application/json"},
            )
            if r.status_code == 200:
                data = r.json()
                if data.get("found"):
                    return {"breaches": data.get("sources", []), "passwords": data.get("passwords", [])}
        except Exception:
            pass
        return None

    def _github_email_search(self, email):
        try:
            r = requests.get(
                f"https://api.github.com/search/commits?q=author-email:{quote(email)}",
                timeout=8,
                headers={"User-Agent": random_ua(), "Accept": "application/vnd.github.cloak-preview+json"},
            )
            if r.status_code == 200:
                data = r.json()
                items = data.get("items", [])
                if items:
                    repos = {}
                    for item in items[:20]:
                        repo_url = item.get("repository", {}).get("html_url", "")
                        author = item.get("commit", {}).get("author", {}).get("name", "")
                        date = item.get("commit", {}).get("author", {}).get("date", "")[:10]
                        if repo_url:
                            repos[repo_url] = {"author": author, "date": date, "url": repo_url}
                    return list(repos.values()) if repos else None
        except Exception:
            pass
        return None

    def _email_osint(self, email):
        results = {"target": email, "type": "email"}

        g = self._gravatar(email)
        if g:
            results["gravatar"] = g

        lc = self._leakcheck(email)
        if lc:
            results["leakcheck"] = lc

        ddg = self._duckduckgo_search(email)
        if ddg:
            results["web_presence"] = ddg

        github = self._github_email_search(email)
        if github:
            results["github_commits"] = github

        return results

    def _bulk_username_check(self, username):
        found = []
        with ThreadPoolExecutor(max_workers=10) as exe:
            fut_map = {}
            for platform, url_template in SOCIAL_PLATFORMS:
                url = url_template.format(username)
                fut_map[exe.submit(_check_url, url, 4)] = (platform, url)
            for f in as_completed(fut_map):
                try:
                    status, _ = f.result(timeout=5)
                    if status and status == 200:
                        platform, url = fut_map[f]
                        found.append({"platform": platform, "url": url})
                except Exception:
                    pass
        return found if found else None

    def _username_osint(self, username):
        results = {"target": username, "type": "username"}
        self.log(f"Checking {len(SOCIAL_PLATFORMS)} platforms for username \"{username}\"")
        profiles = self._bulk_username_check(username)
        if profiles:
            results["profiles"] = profiles
        return results

    def _domain_osint(self, domain):
        results = {"target": domain, "type": "domain"}
        emails_found = set()
        social_links = []
        techs = []

        try:
            r = requests.get(f"https://{domain}", timeout=8, headers={"User-Agent": random_ua()}, allow_redirects=True)
            html = r.text

            for m in re.finditer(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', html):
                e = m.group(0).lower()
                if not e.endswith((".png", ".jpg", ".jpeg", ".gif", ".svg", ".css", ".js", ".ico")):
                    emails_found.add(e)

            social_pats = [
                (r'facebook\.com/([a-zA-Z0-9.]+)', "Facebook"),
                (r'twitter\.com/([a-zA-Z0-9_]+)', "Twitter/X"),
                (r'instagram\.com/([a-zA-Z0-9_.]+)', "Instagram"),
                (r'linkedin\.com/(?:company|in|school)/([a-zA-Z0-9\-]+)', "LinkedIn"),
                (r'youtube\.com/(?:@|c|channel|user)/([a-zA-Z0-9_\-]+)', "YouTube"),
                (r'github\.com/([a-zA-Z0-9\-]+)', "GitHub"),
                (r'medium\.com/@([a-zA-Z0-9\-]+)', "Medium"),
                (r't\.me/([a-zA-Z0-9_]+)', "Telegram"),
                (r'discord\.gg/([a-zA-Z0-9]+)', "Discord"),
                (r'tiktok\.com/@([a-zA-Z0-9_.]+)', "TikTok"),
            ]
            for pat, platform in social_pats:
                for m in re.finditer(pat, html, re.I):
                    url = m.group(0)
                    if not url.startswith("http"):
                        url = f"https://{url}"
                    social_links.append({"platform": platform, "url": url.rstrip("/")})

            seen = set()
            social_links = [s for s in social_links if not (s["url"].lower() in seen or seen.add(s["url"].lower()))]

            tech_pats = [
                (r'react(\.min)?\.js|__NEXT_DATA__|data-reactroot', "React"),
                (r'ng-version|angular\.js', "Angular"),
                (r'vue(\.min)?\.js|__NUXT__', "Vue.js"),
                (r'jquery\.js', "jQuery"),
                (r'bootstrap(\.min)?\.(js|css)', "Bootstrap"),
                (r'tailwindcss|@tailwind', "Tailwind CSS"),
                (r'wp-content|wp-admin|wp-json', "WordPress"),
                (r'shopify', "Shopify"),
                (r'cloudflare|cf-ray', "Cloudflare"),
                (r'google\-analytics\.com|gtag\(', "Google Analytics"),
                (r'js\.stripe\.com', "Stripe"),
                (r'myshopify\.com', "Shopify"),
                (r'intercom\.io', "Intercom"),
                (r'zendesk\.com', "Zendesk"),
                (r'hotjar\.com', "Hotjar"),
            ]
            for pat, name in tech_pats:
                if re.search(pat, html, re.I):
                    techs.append(name)
        except Exception:
            pass

        if emails_found:
            results["emails"] = sorted(emails_found)
        if social_links:
            results["social_links"] = social_links
        if techs:
            results["technologies"] = sorted(set(techs))
        return results

    def _display(self, results, target):
        ttype = results.get("type", "unknown")
        print(f"\n{colored('='*60, 'blue')}")
        print(f"{colored('OSINT HUNTER', 'bold')}")
        print(f"{colored('='*60, 'blue')}")
        print(f"  Target:              {target}")
        print(f"  Type:                {ttype.upper()}")
        print()

        if ttype == "email":
            self._display_email(results)
        elif ttype == "username":
            self._display_username(results)
        elif ttype == "domain":
            self._display_domain(results)

    def _display_email(self, r):
        lc = r.get("leakcheck")
        if lc:
            breaches = lc.get("breaches", [])
            passwords = lc.get("passwords", [])
            if breaches:
                print(f"{colored('  Data Breaches (LeakCheck)', 'red')} ({len(breaches)} sources)")
                seen = set()
                for b in breaches:
                    name = b.get("name", str(b))[:50]
                    date = b.get("date", "")
                    if name not in seen:
                        seen.add(name)
                        if date:
                            print(f"    {name:45s} {date}")
                        else:
                            print(f"    {name}")
                if len(breaches) > len(seen):
                    print(f"    ... and {len(breaches) - len(seen)} more")
            if passwords:
                pw_sample = [p[:30] for p in passwords[:5] if isinstance(p, str)]
                print(f"\n    Passwords exposed: {len(passwords)} total")
                if pw_sample:
                    for p in pw_sample:
                        print(f"    Password: {p}")
            print()

        g = r.get("gravatar")
        if g:
            print(f"{colored('  Gravatar Profile', 'cyan')}")
            print(f"    Name:              {g.get('display_name', 'N/A')}")
            print(f"    Avatar:            {g['avatar_url']}")
            if g.get("location"):
                print(f"    Location:          {g['location']}")
            if g.get("accounts"):
                print(f"    Linked Accounts ({len(g['accounts'])}):")
                for a in g["accounts"]:
                    print(f"      {a['platform']:15s} {a['url']}")
            print()

        web = r.get("web_presence")
        if web:
            print(f"{colored('  Web Presence', 'yellow')} ({len(web)} results)")
            for w in web:
                print(f"    {w}")
            print()

        github = r.get("github_commits")
        if github:
            print(f"{colored('  GitHub Activity', 'green')} ({len(github)} repos)")
            seen_repos = set()
            for repo in github:
                rname = repo['url'].split('/')[-1]
                if rname not in seen_repos:
                    seen_repos.add(rname)
                    print(f"    {repo['author']:20s} {repo['url']} ({repo['date']})")
            print()

        if not lc and not tt and not g and not web and not github:
            print(f"  {colored('[-] No data found for this email', 'yellow')}")

    def _display_username(self, r):
        profiles = r.get("profiles")
        if profiles:
            print(f"{colored('  Registered Accounts', 'green')} ({len(profiles)}/{len(SOCIAL_PLATFORMS)} checked)")
            for p in profiles:
                print(f"    {p['platform']:20s} {p['url']}")
        else:
            print(f"  {colored('[-] No profiles found for this username', 'yellow')}")

    def _display_domain(self, r):
        emails = r.get("emails")
        if emails:
            print(f"{colored('  Emails Found', 'cyan')} ({len(emails)})")
            for e in emails:
                print(f"    {e}")
            print()

        social = r.get("social_links")
        if social:
            print(f"{colored('  Social Links', 'green')} ({len(social)})")
            for s in social:
                print(f"    {s['platform']:15s} {s['url']}")
            print()

        tech = r.get("technologies")
        if tech:
            print(f"{colored('  Technologies Detected', 'magenta')} ({len(tech)})")
            print(f"    {', '.join(tech)}")
            print()

        if not emails and not social and not tech:
            print(f"  {colored('[-] No data found for this domain', 'yellow')}")
