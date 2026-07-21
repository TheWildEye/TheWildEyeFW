import sys
import re
import socket
import ssl
import time
import concurrent.futures
import shutil
import subprocess
import json

from core.engine import ReconModule, register_module
from core.utils import colored


_DOMAIN_RE = re.compile(r"^[a-zA-Z0-9.\-]+$")


def _sanitize_domain(domain):
    if not _DOMAIN_RE.match(domain):
        raise ValueError(f"Invalid domain: {domain}")
    return domain


WHOIS_SERVERS = {
    "com": "whois.verisign-grs.com",
    "net": "whois.verisign-grs.com",
    "org": "whois.pir.org",
    "in": "whois.registry.in",
    "io": "whois.nic.io",
    "co": "whois.nic.co",
    "info": "whois.afilias.net",
    "uk": "whois.nic.uk",
    "de": "whois.denic.de",
    "ca": "whois.cira.ca",
    "au": "whois.auda.org.au",
    "fr": "whois.nic.fr",
    "br": "whois.registro.br",
    "jp": "whois.jprs.jp",
    "ru": "whois.tcinet.ru",
    "cn": "whois.cnnic.cn",
    "app": "whois.nic.google",
    "dev": "whois.nic.google",
    "ai": "whois.nic.ai",
    "cloud": "whois.nic.cloud",
    "live": "whois.nic.live",
    "tech": "whois.nic.tech",
    "xyz": "whois.nic.xyz",
    "online": "whois.nic.online",
    "site": "whois.nic.site",
    "shop": "whois.nic.shop",
    "store": "whois.nic.store",
    "me": "whois.nic.me",
    "us": "whois.nic.us",
    "eu": "whois.eu",
    "pro": "whois.nic.pro",
    "name": "whois.nic.name",
    "mobi": "whois.nic.mobi",
    "biz": "whois.nic.biz",
    "email": "whois.nic.email",
    "agency": "whois.nic.agency",
    "work": "whois.nic.work",
    "press": "whois.nic.press",
    "design": "whois.nic.design",
    "cc": "whois.nic.cc",
    "tv": "whois.nic.tv",
}

SOCK_RECV = 4096
WHOIS_TIMEOUT = 8

RDAP_SERVERS = {
    "com": "https://rdap.verisign.com/com/v1",
    "net": "https://rdap.verisign.com/net/v1",
    "org": "https://rdap.publicinterestregistry.org",
    "in": "https://rdap.registry.in",
    "io": "https://rdap.nic.io",
    "co": "https://rdap.nic.co",
    "info": "https://rdap.afilias.net/rdap",
    "uk": "https://rdap.nic.uk",
    "de": "https://rdap.denic.de",
    "ca": "https://rdap.cira.ca",
    "au": "https://rdap.auda.org.au",
    "fr": "https://rdap.nic.fr",
    "br": "https://rdap.registro.br",
    "jp": "https://rdap.nic.ad.jp",
    "ru": "https://rdap.nic.ru",
    "cn": "https://rdap.cnnic.cn",
    "app": "https://rdap.nic.google",
    "dev": "https://rdap.nic.google",
    "ai": "https://rdap.nic.ai",
    "cloud": "https://rdap.nic.cloud",
    "live": "https://rdap.nic.live",
    "tech": "https://rdap.nic.tech",
    "xyz": "https://rdap.nic.xyz",
    "online": "https://rdap.nic.online",
    "site": "https://rdap.nic.site",
    "shop": "https://rdap.nic.shop",
    "store": "https://rdap.nic.store",
    "me": "https://rdap.nic.me",
    "us": "https://rdap.nic.us",
    "eu": "https://rdap.eu",
    "pro": "https://rdap.nic.pro",
    "name": "https://rdap.nic.name",
    "mobi": "https://rdap.afilias.net/rdap",
    "biz": "https://rdap.nic.biz",
    "email": "https://rdap.nic.email",
    "cc": "https://rdap.nic.cc",
    "tv": "https://rdap.nic.tv",
}


def _rdap_lookup(domain):
    try:
        tld = domain.rsplit(".", 1)[-1].lower()
        server = RDAP_SERVERS.get(tld)
        if not server:
            return None
        import requests
        url = f"{server}/domain/{domain}"
        resp = requests.get(url, timeout=8, headers={"Accept": "application/rdap+json"})
        if resp.status_code != 200:
            return None
        return resp.json()
    except Exception:
        return None


def _rdap_extract_vcard(vcard_array, field):
    if not vcard_array or len(vcard_array) < 2:
        return ""
    for item in vcard_array[1]:
        if len(item) >= 4 and str(item[0]).lower() == field.lower():
            return str(item[3])
    return ""


def _rdap_entity_name(entity):
    vcard = entity.get("vcardArray")
    if vcard:
        fn = _rdap_extract_vcard(vcard, "fn")
        org = _rdap_extract_vcard(vcard, "org")
        return fn or org or ""
    return entity.get("handle", "")


def _rdap_entity_email(entity):
    vcard = entity.get("vcardArray")
    if vcard:
        return _rdap_extract_vcard(vcard, "email")
    return ""


def _rdap_parse(data, domain):
    info = {}
    for entity in data.get("entities", []):
        roles = [r.lower() for r in entity.get("roles", [])]
        name = _rdap_entity_name(entity)
        email = _rdap_entity_email(entity)
        if "registrant" in roles:
            info["registrant_name"] = name
            if email:
                info["registrant_email"] = email
        if "administrative" in roles:
            info["admin_name"] = name
            if email:
                info["admin_email"] = email
        if "technical" in roles:
            info["tech_name"] = name
            if email:
                info["tech_email"] = email
        if "abuse" in roles:
            info["abuse_email"] = email
    for event in data.get("events", []):
        action = event.get("eventAction", "")
        date = event.get("eventDate", "")
        if action == "registration":
            info["created"] = date
        elif action == "expiration":
            info["expires"] = date
        elif action in ("last changed", "last update"):
            info["updated"] = date
    ns = [n.get("ldhName", "") for n in data.get("nameservers", []) if n.get("ldhName")]
    if ns:
        info["name_servers"] = sorted(set(n.lower().rstrip(".") for n in ns))
    statuses = data.get("status", [])
    if statuses:
        info["domain_status"] = [s.lower() for s in statuses]
    dnssec = data.get("secureDNS", {}).get("delegationSigned")
    if dnssec is not None:
        info["dnssec"] = "signed" if dnssec else "unsigned"
    return info


def _nslookup_record(domain, qtype):
    results = []
    try:
        _sanitize_domain(domain)
        flag = f"-type={qtype}" if sys.platform == "win32" else f"-query={qtype}"
        out = subprocess.check_output(
            ["nslookup", flag, domain], stderr=subprocess.DEVNULL, text=True, timeout=5
        )
        lines = out.splitlines()
        i = 0
        while i < len(lines):
            stripped = lines[i].strip()
            if qtype == "A" and "Name:" in stripped:
                i += 1
                continue
            if qtype == "A" and stripped.startswith("Address"):
                parts = stripped.split(":", 1)
                if len(parts) > 1:
                    addr = parts[1].strip()
                    if addr and addr != domain and ":" not in addr:
                        results.append(addr)
            elif qtype == "AAAA" and stripped.startswith("Address"):
                parts = stripped.split(":", 1)
                if len(parts) > 1:
                    addr = parts[1].strip()
                    if addr and addr != domain:
                        results.append(addr)
            elif qtype == "MX":
                if "MX preference" in stripped:
                    parts = stripped.split(", ")
                    if len(parts) > 1:
                        results.append(parts[1].replace("mail exchanger =", "").strip())
            elif qtype == "NS" and "nameserver" in stripped:
                parts = stripped.split("=", 1)
                if len(parts) > 1:
                    results.append(parts[1].strip().rstrip("."))
            elif qtype == "TXT":
                if "text =" in stripped:
                    if i + 1 < len(lines):
                        nxt = lines[i + 1].strip()
                        m = re.search(r'"(.+?)"', nxt)
                        if m:
                            results.append(m.group(1))
                            i += 1
                elif stripped.startswith('"') and stripped.endswith('"'):
                    m = re.search(r'"(.+?)"', stripped)
                    if m:
                        results.append(m.group(1))
            elif qtype == "SOA":
                if (stripped and not stripped.startswith(("Server:", "Address:"))
                        and "canonical name" not in stripped
                        and "unrecognized" not in stripped.lower()):
                    results.append(stripped)
            i += 1
    except Exception:
        pass
    return results


@register_module
class WhoisHunterModule(ReconModule):
    name = "whoishunter"
    description = "WHOIS recon engine - registrar, DNS, MX, SSL, reverse DNS"

    def run(self, target):
        self.setup(target)

        if target.startswith(("http://", "https://")):
            target = target.split("://", 1)[1].split("/")[0]
        target = target.split("/")[0].split(":")[0].strip()

        self.log(f"Running WHOIS recon on {target}")

        def safe_recv(sock):
            buf = []
            try:
                while True:
                    d = sock.recv(SOCK_RECV)
                    if not d:
                        break
                    buf.append(d)
            except Exception:
                pass
            return b"".join(buf).decode(errors="ignore")

        def get_tld(domain):
            parts = domain.rsplit(".", 2)
            if len(parts) >= 2:
                return parts[-1].lower()
            return ""

        def try_whois_socket(server, query):
            try:
                ip = socket.getaddrinfo(server, 43)[0][4][0]
                s = socket.create_connection((ip, 43), WHOIS_TIMEOUT)
                s.settimeout(WHOIS_TIMEOUT)
                s.sendall((query.replace("\r", "").replace("\n", "") + "\r\n").encode())
                data = safe_recv(s)
                s.close()
                return data
            except Exception as e:
                return f"[ERROR] {e}"

        def do_whois(domain):
            tld = get_tld(domain)
            servers = []
            if tld and tld in WHOIS_SERVERS:
                servers.append(WHOIS_SERVERS[tld])
            servers += ["whois.iana.org", "whois.ripe.net", "whois.crsnic.net"]
            seen = set()
            full_resp = ""
            referrals = []
            for s in servers:
                if s in seen:
                    continue
                seen.add(s)
                resp = try_whois_socket(s, domain)
                if resp and not resp.startswith("[ERROR]"):
                    full_resp += f"\n--- {s} ---\n{resp}\n"
                    for line in resp.splitlines():
                        low = line.lower()
                        if "whois server:" in low or "refer:" in low:
                            try:
                                ref = line.split(":", 1)[1].strip().split()[0]
                                if ref and ref not in seen:
                                    seen.add(ref)
                                    referrals.append(ref)
                                    resp2 = try_whois_socket(ref, domain)
                                    if resp2 and not resp2.startswith("[ERROR]"):
                                        full_resp += f"\n--- {ref} (referral) ---\n{resp2}\n"
                            except Exception:
                                pass
                    if full_resp.strip():
                        return full_resp.strip()
            if shutil.which("whois"):
                try:
                    _sanitize_domain(domain)
                    sys_whois = subprocess.check_output(
                        ["whois", domain], stderr=subprocess.DEVNULL, text=True, timeout=WHOIS_TIMEOUT
                    )
                    return sys_whois
                except (ValueError, Exception):
                    pass
            return "[ERROR] All WHOIS attempts failed"

        def resolve_dns(domain):
            A, AAAA = [], []
            try:
                for fam, _, _, _, addr in socket.getaddrinfo(domain, None):
                    if fam == socket.AF_INET:
                        A.append(addr[0])
                    elif fam == socket.AF_INET6:
                        AAAA.append(addr[0])
            except Exception:
                pass
            return sorted(set(A)), sorted(set(AAAA))

        def get_ssl_info(domain):
            try:
                ctx = ssl.create_default_context()
                with socket.create_connection((domain, 443), WHOIS_TIMEOUT) as s:
                    with ctx.wrap_socket(s, server_hostname=domain) as ss:
                        cert = ss.getpeercert()
                        cn = None
                        for t in cert.get("subject", ()):
                            for k, v in t:
                                if k.lower() in ("commonname", "cn"):
                                    cn = v
                        sans = [t[1] for t in cert.get("subjectAltName", ()) if t[0].lower() == "dns"]
                        issuer = dict(cert.get("issuer", []))
                        issuer_org = ""
                        for tup in cert.get("issuer", ()):
                            for k, v in tup:
                                if k.lower() in ("organizationname", "o"):
                                    issuer_org = v
                        valid_from = cert.get("notBefore", "")
                        valid_until = cert.get("notAfter", "")
                        return {
                            "cn": cn,
                            "sans": sans,
                            "issuer": issuer_org,
                            "valid_from": valid_from,
                            "valid_until": valid_until,
                        }
            except Exception:
                return None

        def get_dns_records(domain):
            out = {}
            for qtype in ["A", "AAAA", "MX", "NS", "TXT", "SOA"]:
                out[qtype] = _nslookup_record(domain, qtype)
            return out

        def rdns(ip):
            try:
                return socket.gethostbyaddr(ip)[0]
            except Exception:
                return None

        def parse_whois_deep(text):
            info = {
                "registrar": "Unknown",
                "registrar_url": "",
                "registrar_abuse_email": "",
                "registrar_abuse_phone": "",
                "registrant_name": "",
                "registrant_org": "",
                "registrant_email": "",
                "registrant_phone": "",
                "registrant_address": "",
                "admin_name": "",
                "admin_org": "",
                "admin_email": "",
                "tech_name": "",
                "tech_email": "",
                "created": "Unknown",
                "expires": "Unknown",
                "updated": "Unknown",
                "name_servers": [],
                "dnssec": "Unknown",
                "domain_status": [],
                "whois_server": "",
                "referral_url": "",
            }
            if not text or text.startswith("[ERROR]"):
                return info

            def _find(pat, text, flags=re.I):
                m = re.search(pat, text, flags)
                return m.group(1).strip() if m else ""

            info["registrar"] = _find(r"(?:Registrar|Sponsoring Registrar):\s*(.+)", text)
            info["registrar_url"] = _find(r"(?:Registrar URL|Registrar Website):\s*(.+)", text)
            info["registrar_abuse_email"] = _find(r"(?:Registrar Abuse Contact Email|Abuse Email):\s*(.+)", text)
            info["registrar_abuse_phone"] = _find(r"(?:Registrar Abuse Contact Phone|Abuse Phone):\s*(.+)", text)

            info["registrant_name"] = _find(r"(?:Registrant Name|Registrant):\s*(.+)", text)
            info["registrant_org"] = _find(r"(?:Registrant Organization|org):\s*(.+)", text)
            info["registrant_email"] = _find(r"(?:Registrant Email|Registrant E-mail):\s*(.+)", text)
            info["registrant_phone"] = _find(r"(?:Registrant Phone|Registrant Telephone):\s*(.+)", text)

            addr_lines = []
            for al in ["Registrant Street", "Registrant City", "Registrant State/Province", "Registrant Postal Code", "Registrant Country"]:
                v = _find(rf"{re.escape(al)}:\s*(.+)", text)
                if v:
                    addr_lines.append(v)
            if addr_lines:
                info["registrant_address"] = ", ".join(addr_lines)

            info["admin_name"] = _find(r"(?:Admin Name|Administrative Contact):\s*(.+)", text)
            info["admin_org"] = _find(r"(?:Admin Organization):\s*(.+)", text)
            info["admin_email"] = _find(r"(?:Admin Email|Admin E-mail):\s*(.+)", text)

            info["tech_name"] = _find(r"(?:Tech Name|Technical Contact):\s*(.+)", text)
            info["tech_email"] = _find(r"(?:Tech Email|Tech E-mail):\s*(.+)", text)

            info["created"] = _find(r"(?:Creation Date|Created On|created|domain_date|Created):\s*(.+)", text)
            info["expires"] = _find(r"(?:Registry Expiry Date|Expiration Date|Expiry Date|expire|paid-till|Expiration):\s*(.+)", text)
            info["updated"] = _find(r"(?:Updated Date|Last Updated|changed|last_updated|Modified):\s*(.+)", text)

            ns_list = re.findall(r"(?:Name Server|nserver):\s*(.+)", text, re.I)
            if ns_list:
                info["name_servers"] = sorted(set(n.strip().lower().rstrip(".") for n in ns_list))

            info["dnssec"] = _find(r"(?:DNSSEC|dnssec|signed):\s*(.+)", text)

            status_list = re.findall(r"(?:Domain Status|Status):\s*(.+)", text, re.I)
            info["domain_status"] = [s.strip().lower() for s in status_list if s.strip()]

            info["whois_server"] = _find(r"(?:Whois Server|WHOIS Server):\s*(.+)", text)
            info["referral_url"] = _find(r"(?:Referral URL|Referral):\s*(.+)", text)

            return info

        results = {"target": target}
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as exe:
            f_whois = exe.submit(do_whois, target)
            f_rdap = exe.submit(_rdap_lookup, target)
            f_dns = exe.submit(resolve_dns, target)
            f_ssl = exe.submit(get_ssl_info, target)
            f_dns_records = exe.submit(get_dns_records, target)

            whois_raw = f_whois.result()
            results["whois_raw"] = whois_raw
            results["whois_raw_length"] = len(whois_raw or "")
            results["structured"] = parse_whois_deep(whois_raw)
            rdap_data = f_rdap.result()
            if rdap_data:
                rdap_info = _rdap_parse(rdap_data, target)
                s = results["structured"]
                if s["registrant_name"] in ("", "Unknown") and rdap_info.get("registrant_name"):
                    s["registrant_name"] = rdap_info["registrant_name"]
                if s["registrant_email"] == "" and rdap_info.get("registrant_email"):
                    s["registrant_email"] = rdap_info["registrant_email"]
                if s["admin_name"] == "" and rdap_info.get("admin_name"):
                    s["admin_name"] = rdap_info["admin_name"]
                if s["admin_email"] == "" and rdap_info.get("admin_email"):
                    s["admin_email"] = rdap_info["admin_email"]
                if s["tech_name"] == "" and rdap_info.get("tech_name"):
                    s["tech_name"] = rdap_info["tech_name"]
                if s["tech_email"] == "" and rdap_info.get("tech_email"):
                    s["tech_email"] = rdap_info["tech_email"]
                if s["created"] in ("", "Unknown") and rdap_info.get("created"):
                    s["created"] = rdap_info["created"]
                if s["expires"] in ("", "Unknown") and rdap_info.get("expires"):
                    s["expires"] = rdap_info["expires"]
                if s["updated"] in ("", "Unknown") and rdap_info.get("updated"):
                    s["updated"] = rdap_info["updated"]
                if not s["name_servers"] and rdap_info.get("name_servers"):
                    s["name_servers"] = rdap_info["name_servers"]
                if not s["domain_status"] and rdap_info.get("domain_status"):
                    s["domain_status"] = rdap_info["domain_status"]
                if s["dnssec"] in ("", "Unknown") and rdap_info.get("dnssec"):
                    s["dnssec"] = rdap_info["dnssec"]
                if s["registrar"] in ("", "Unknown") and rdap_data.get("port43"):
                    s["registrar"] = rdap_data.get("port43", "")
                results["rdap_used"] = True
            else:
                results["rdap_used"] = False
            A, AAAA = f_dns.result()
            results["a_records"] = A
            results["aaaa_records"] = AAAA
            results["ssl"] = f_ssl.result()
            dns_records = f_dns_records.result()
            results["ns_records"] = dns_records.get("NS", [])
            results["mx_records"] = dns_records.get("MX", [])
            results["txt_records"] = dns_records.get("TXT", [])
            results["soa_record"] = dns_records.get("SOA", [])

        results["reverse_dns"] = {}
        for ip in A + AAAA:
            ptr = rdns(ip)
            if ptr:
                results["reverse_dns"][ip] = ptr

        def _is_real(v):
            if not v:
                return False
            s = str(v).lower().strip()
            if s in ("", "unknown", "none", "redacted for privacy"):
                return False
            if any(x in s for x in ("please query the rdds", "redact", "not disclosed", "data not", "unavailable", "whoisguard")):
                return False
            return True

        self.results = results
        s = results["structured"]
        whois_no_match = "No match for" in results.get("whois_raw", "")

        print(f"\n{colored('='*60, 'green')}")
        print(f"{colored('WHOIS SUMMARY', 'bold')}")
        print(f"{colored('='*60, 'green')}")
        print(f"  Target:              {target}")

        if whois_no_match:
            print(f"  {colored('[!] Domain not found in registry WHOIS database', 'yellow')}")

        if _is_real(s.get('registrar')):
            print(f"  Registrar:           {s['registrar']}")
        if _is_real(s.get('registrar_url')):
            print(f"  Registrar URL:       {s['registrar_url']}")
        if _is_real(s.get('registrar_abuse_email')):
            print(f"  Abuse Email:         {s['registrar_abuse_email']}")
        if _is_real(s.get('registrar_abuse_phone')):
            print(f"  Abuse Phone:         {s['registrar_abuse_phone']}")
        if _is_real(s.get('created')):
            print(f"  Created:             {s['created']}")
        if _is_real(s.get('expires')):
            print(f"  Expires:             {s['expires']}")
        if _is_real(s.get('updated')):
            print(f"  Updated:             {s['updated']}")
        if _is_real(s.get('dnssec')):
            print(f"  DNSSEC:              {s['dnssec']}")
        if _is_real(s.get('registrant_org')):
            print(f"  Registrant Org:      {s['registrant_org']}")

        all_ns = s.get("name_servers", [])
        if not all_ns:
            all_ns = results.get("ns_records", [])
        seen_ns = set()
        for ns in all_ns:
            clean_ns = ns.lower().strip().rstrip(".")
            parts = clean_ns.split()
            ns_name = parts[0] if parts else clean_ns
            if ns_name not in seen_ns:
                seen_ns.add(ns_name)
                print(f"  Name Server:         {ns}")

        if results.get("a_records"):
            for ip in results["a_records"]:
                ptr = results["reverse_dns"].get(ip, "")
                extra = f" -> {ptr}" if ptr else ""
                print(f"  A:                   {ip}{extra}")

        if results.get("aaaa_records"):
            for ip in results["aaaa_records"]:
                print(f"  AAAA:                {ip}")

        if results.get("mx_records"):
            for mx in sorted(results["mx_records"]):
                print(f"  MX:                  {mx}")

        if results.get("soa_record"):
            for soa in results["soa_record"]:
                print(f"  SOA:                 {soa}")

        if results.get("txt_records"):
            for txt in results["txt_records"]:
                print(f"  TXT:                 {txt}")

        if results.get("ssl"):
            ssl_data = results["ssl"]
            if _is_real(ssl_data.get('issuer')):
                print(f"  SSL Issuer:          {ssl_data['issuer']}")
            if ssl_data.get('cn'):
                print(f"  SSL CN:              {ssl_data['cn']}")
            for san in ssl_data.get('sans', []):
                print(f"  SSL SAN:             {san}")
            if _is_real(ssl_data.get('valid_until')):
                print(f"  SSL Expires:         {ssl_data['valid_until']}")

        if s.get("domain_status"):
            statuses = list(dict.fromkeys(s["domain_status"]))
            for st in statuses:
                print(f"  Domain Status:       {st}")

        if _is_real(s.get('whois_server')):
            print(f"  WHOIS Server:        {s['whois_server']}")

        if results.get("whois_raw_length", 0) > 100:
            raw = results["whois_raw"]
            ref_start = raw.find("--- ")
            domain_section = raw[ref_start:] if ref_start > 0 else raw
            if "No match for" in domain_section:
                print(f"\n  Raw WHOIS:")
                for line in domain_section.splitlines():
                    if "redacted" not in line.lower():
                        print(f"    {line}")
            else:
                ref_idx = domain_section.find("(referral)")
                if ref_idx > 0:
                    domain_section = domain_section[ref_idx:]
                print(f"\n  Domain WHOIS ({results['whois_raw_length']} bytes):")
                for line in domain_section.splitlines():
                    if "redacted" not in line.lower():
                        print(f"    {line}")

        self.teardown()
        return self.results
