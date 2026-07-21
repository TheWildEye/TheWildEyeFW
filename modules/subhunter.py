import re
import socket
import json
import hashlib
import concurrent.futures
import urllib3
import requests
from urllib.parse import urlparse
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from core.engine import ReconModule, register_module
from core.utils import colored


PASSIVE_SOURCES = {
    "crt.sh": "https://crt.sh/?q=%25.{domain}&output=json",
    "AlienVault OTX": "https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns",
    "UrlScan.io": "https://urlscan.io/api/v1/search/?q=domain:{domain}",
}

COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "admin", "api", "dev", "test", "staging",
    "blog", "cdn", "static", "assets", "img", "css", "js", "files",
    "download", "support", "help", "docs", "wiki", "status",
    "portal", "app", "web", "webmail", "smtp", "imap", "pop3",
    "autodiscover", "cpanel", "whm", "ns1", "ns2", "ns3", "mx",
    "remote", "vpn", "secure", "login", "register", "account",
    "dashboard", "monitor", "analytics", "tracking", "stats",
    "git", "jenkins", "jira", "confluence", "svn",
    "cloud", "s3", "bucket", "storage", "backup", "db", "database",
    "redis", "mongo", "mysql", "postgres", "elastic", "kibana",
    "docker", "k8s", "kubernetes", "swarm", "rancher",
    "stage", "preprod", "production", "prod", "sandbox",
    "demo", "internal", "corp", "office", "employee",
    "chat", "meet", "team", "project", "community", "forum",
    "shop", "store", "cart", "checkout", "payment", "billing",
    "info", "news", "media", "tv", "video", "player",
    "m", "mobile", "iphone", "android", "api",
    "graphql", "socket", "ws", "wss", "broker",
    "alpha", "beta", "gamma", "delta", "release",
    "ns", "ns0", "ns4", "dns", "dns1", "dns2",
    "proxy", "gateway", "router", "switch", "firewall",
    "ldap", "radius", "tacacs", "kerberos",
    "oracle", "mssql", "sql", "mysql", "mariadb",
    "tomcat", "jboss", "websphere", "weblogic",
    "cdn", "img", "static", "assets", "media", "uploads",
    "mail2", "mail3", "relay", "smtp2",
    "mx1", "mx2", "mailgw", "mailgateway",
]


@register_module
class SubfinderModule(ReconModule):
    name = "subhunter"
    description = "Subdomain enumeration via crt.sh, passive DNS sources + DNS bruteforce"

    def run(self, target):
        self.setup(target)

        if target.startswith(("http://", "https://")):
            target = urlparse(target).netloc
        target = target.split("/")[0].split(":")[0].strip()
        domain = target.replace("www.", "")

        self.log(f"Subdomain enumeration for {domain}")
        subdomains = set()
        source_stats = {}

        # Passive sources
        for source_name, url_template in PASSIVE_SOURCES.items():
            try:
                self.log(f"Querying {source_name}...")
                url = url_template.replace("{domain}", domain)
                resp = requests.get(url, timeout=15,
                    headers={"User-Agent": "Mozilla/5.0"})
                if resp.status_code != 200:
                    continue
                count_before = len(subdomains)

                if source_name == "crt.sh":
                    data = resp.json()
                    for entry in data:
                        name = entry.get("name_value", "")
                        for sub in name.split("\n"):
                            sub = sub.strip().lower().lstrip("*.")
                            if not sub or "null" == sub:
                                continue
                            if sub.endswith(f".{domain}") or sub == domain:
                                subdomains.add(sub)
                    source_stats[source_name] = {"found": len(subdomains) - count_before, "status": resp.status_code}

                elif source_name == "AlienVault OTX":
                    data = resp.json()
                    for entry in data.get("passive_dns", []):
                        sub = entry.get("hostname", "").lower().strip()
                        if sub.endswith(f".{domain}") or sub == domain:
                            subdomains.add(sub)
                    source_stats[source_name] = {"found": len(subdomains) - count_before, "status": resp.status_code}

                elif source_name == "UrlScan.io":
                    data = resp.json()
                    for result in data.get("results", []):
                        page = result.get("page", {})
                        sub = page.get("domain", "").lower().strip()
                        if sub.endswith(f".{domain}") or sub == domain:
                            subdomains.add(sub)
                    source_stats[source_name] = {"found": len(subdomains) - count_before, "status": resp.status_code}

                self.log(f"  {source_name}: +{len(subdomains) - count_before} subs")

            except Exception as e:
                source_stats[source_name] = {"error": str(e)[:60]}
                self.error(f"{source_name} failed: {str(e)[:120]}")

        # DNS bruteforce — establish catch-all fingerprint first, then check subs
        _root_hashes = set()
        for _scheme in ("https", "http"):
            try:
                _rr = requests.get(f"{_scheme}://{domain}", timeout=8, allow_redirects=False,
                                   headers={"User-Agent": "Mozilla/5.0"}, verify=False)
                if _rr.status_code not in (404, 0, 502, 503) and len(_rr.content) > 50:
                    _root_hashes.add(hashlib.md5(_rr.content).hexdigest())
            except Exception:
                pass

        # Probe a non-existent subdomain to fingerprint wildcard catch-all pages
        import random as _rnd
        _fake_sub = f"xyznonexistent{_rnd.randint(10000,99999)}"
        for _scheme in ("https", "http"):
            try:
                _cr = requests.get(f"{_scheme}://{_fake_sub}.{domain}", timeout=5, allow_redirects=False,
                                   headers={"User-Agent": "Mozilla/5.0"}, verify=False)
                if _cr.status_code not in (404, 0, 502, 503) and len(_cr.content) > 50:
                    _root_hashes.add(hashlib.md5(_cr.content).hexdigest())
            except Exception:
                pass

        if len(_root_hashes) > 2:
            self.log(f"  Wildcard DNS detected ({len(_root_hashes)} unique page fingerprints)")

        def check_sub(sub):
            fqdn = f"{sub}.{domain}"
            try:
                socket.getaddrinfo(fqdn, None, socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP)
                for _scheme in ("https", "http"):
                    try:
                        r = requests.get(f"{_scheme}://{fqdn}", timeout=5, allow_redirects=False,
                                         headers={"User-Agent": "Mozilla/5.0"}, verify=False)
                        if r.status_code in (404, 0, 502, 503):
                            continue
                        if _root_hashes and hashlib.md5(r.content).hexdigest() in _root_hashes:
                            continue
                        return fqdn
                    except requests.exceptions.ConnectionError:
                        continue
                    except Exception:
                        continue
                return None
            except Exception:
                return None

        self.log(f"DNS bruteforce with {len(COMMON_SUBDOMAINS)} subs...")
        count_before = len(subdomains)
        interrupted = False
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=50) as exe:
                fut = {exe.submit(check_sub, s): s for s in COMMON_SUBDOMAINS}
                for f in concurrent.futures.as_completed(fut):
                    r = f.result()
                    if r:
                        subdomains.add(r)
        except KeyboardInterrupt:
            interrupted = True
        source_stats["DNS Bruteforce"] = {"found": len(subdomains) - count_before}

        # Certificate details from crt.sh
        certs = []
        try:
            resp = requests.get(
                f"https://crt.sh/?q=%25.{domain}&output=json",
                timeout=15, headers={"User-Agent": "Mozilla/5.0"})
            if resp.status_code == 200:
                data = resp.json()
                seen_certs = set()
                for entry in data[:200]:
                    cn = entry.get("common_name", "")
                    cert_key = f"{cn}|{entry.get('not_after', '')}"
                    if cn and cert_key not in seen_certs:
                        seen_certs.add(cert_key)
                        certs.append({
                            "common_name": cn,
                            "issuer": (entry.get("issuer_name") or "")[:80],
                            "not_after": (entry.get("not_after") or "")[:19],
                        })
        except Exception:
            pass

        subdomains.discard(domain)
        subdomains.discard(f"www.{domain}")
        sorted_subs = sorted(subdomains, key=lambda x: (x.count("."), x))

        self.results["interrupted"] = interrupted
        self.results["domain"] = domain
        self.results["source_stats"] = source_stats
        self.results["subdomains"] = sorted_subs
        self.results["subdomains_count"] = len(sorted_subs)
        self.results["certificates"] = certs[:50]

        header = "SUBFINDER SUMMARY (PARTIAL — INTERRUPTED)" if interrupted else "SUBFINDER SUMMARY"
        print(f"\n{colored('='*60, 'cyan')}")
        print(f"{colored(header, 'bold')}")
        print(f"{colored('='*60, 'cyan')}")
        print(f"  Domain:     {domain}")
        print(f"  Subdomains: {len(sorted_subs)}")
        for src, stats in source_stats.items():
            count = stats.get("found", "?")
            status = stats.get("status", stats.get("error", "done"))
            print(f"    {colored('[>]', 'cyan')} {src}: {count} (status: {status})")

        if sorted_subs:
            for s in sorted_subs:
                print(f"    {colored('[+]', 'green')} {s}")

        if certs:
            print(f"\n  Certificates ({len(certs)} unique):")
            for c in certs:
                print(f"    CN: {c['common_name']} | expires: {c['not_after']}")

        self.teardown()
        return self.results
