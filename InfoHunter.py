#!/usr/bin/env python3
import re, socket, ssl, concurrent.futures, datetime, textwrap, subprocess, shutil, sys, ctypes

# Enable ANSI colors on Windows
if sys.platform.startswith("win"):
    try:
        h = ctypes.windll.kernel32.GetStdHandle(-11)
        mode = ctypes.c_uint()
        if ctypes.windll.kernel32.GetConsoleMode(h, ctypes.byref(mode)):
            ctypes.windll.kernel32.SetConsoleMode(h, ctypes.c_uint(mode.value | 0x0004))
    except:
        pass

BANNER = """
\033[92m
$$$$$$\            $$$$$$\           $$\   $$\                      $$\                         
\_$$  _|          $$  __$$\          $$ |  $$ |                     $$ |                        
  $$ |  $$$$$$$\  $$ /  \__|$$$$$$\  $$ |  $$ |$$\   $$\ $$$$$$$\ $$$$$$\    $$$$$$\   $$$$$$\  
  $$ |  $$  __$$\ $$$$\    $$  __$$\ $$$$$$$$ |$$ |  $$ |$$  __$$\\_$$  _|  $$  __$$\ $$  __$$\ 
  $$ |  $$ |  $$ |$$  _|   $$ /  $$ |$$  __$$ |$$ |  $$ |$$ |  $$ | $$ |    $$$$$$$$ |$$ |  \__|
  $$ |  $$ |  $$ |$$ |     $$ |  $$ |$$ |  $$ |$$ |  $$ |$$ |  $$ | $$ |$$\ $$   ____|$$ |      
$$$$$$\ $$ |  $$ |$$ |     \$$$$$$  |$$ |  $$ |\$$$$$$  |$$ |  $$ | \$$$$  |\$$$$$$$\ $$ |      
\______|\__|  \__|\__|      \______/ \__|  \__| \______/ \__|  \__|  \____/  \_______|\__|      
                                                                                                                                                                                                                                                                                              
 UNIFIED RECONNAISSANCE & OSINT FRAMEWORK - VYOM NAGPAL
\033[0m
"""

WHOIS_TIMEOUT = 8
SOCK_RECV = 4096
MAX_WORKERS = 6

WHOIS_SERVERS = {
    "com": "whois.verisign-grs.com",
    "net": "whois.verisign-grs.com",
    "org": "whois.pir.org",
    "in": "whois.registry.in",
    "io": "whois.nic.io",
    "co": "whois.nic.co",
    "info": "whois.afilias.net",
    "uk": "whois.nic.uk",
}

def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def safe_recv(sock):
    buf = []
    try:
        while True:
            d = sock.recv(SOCK_RECV)
            if not d: break
            buf.append(d)
    except Exception: pass
    return b"".join(buf).decode(errors="ignore")

def get_tld(domain):
    parts = domain.rsplit(".", 2)
    if len(parts) >= 2: return parts[-1].lower()
    return ""

def try_whois_socket(server, query, timeout=WHOIS_TIMEOUT):
    try:
        ip = socket.getaddrinfo(server, 43)[0][4][0]
    except Exception:
        ip = None
    try:
        if ip:
            s = socket.create_connection((ip, 43), timeout)
        else:
            s = socket.create_connection((server, 43), timeout)
        s.settimeout(timeout)
        s.sendall((query.replace("\r", "").replace("\n", "") + "\r\n").encode())
        data = safe_recv(s)
        s.close()
        return data
    except Exception as e:
        return f"[ERROR] whois {server} failed: {e}"

def parse_referral(text):
    if not text: return None
    for line in text.splitlines():
        low = line.lower()
        if "whois server:" in low or "refer:" in low:
            try: return line.split(":",1)[1].strip().split()[0]
            except: pass
    m = re.search(r"whois[^\s:;,]*\.[^\s:;,]+", text, re.I)
    if m: return m.group(0).strip()
    return None

def do_whois(domain):
    tld = get_tld(domain)
    servers = []
    if tld and tld in WHOIS_SERVERS: servers.append(WHOIS_SERVERS[tld])
    servers += ["whois.iana.org", "whois.ripe.net", "whois.crsnic.net", "whois.nic.io"]
    seen = set()
    for s in servers:
        if s in seen: continue
        seen.add(s)
        resp = try_whois_socket(s, domain)
        if resp and not resp.startswith("[ERROR]"):
            ref = parse_referral(resp)
            if ref and ref not in seen:
                resp2 = try_whois_socket(ref, domain)
                return resp + "\n\n--REFERRAL--\n\n" + resp2
            return resp
    if shutil.which("whois"):
        try:
            out = subprocess.check_output(["whois", "--", domain], stderr=subprocess.DEVNULL, text=True, timeout=WHOIS_TIMEOUT)
            return out
        except Exception as e:
            return f"[ERROR] system whois failed: {e}"
    return "[ERROR] All whois attempts failed"

def resolve(domain):
    A, AAAA = [], []
    try:
        for fam, _, _, _, addr in socket.getaddrinfo(domain, None):
            if fam == socket.AF_INET: A.append(addr[0])
            elif fam == socket.AF_INET6: AAAA.append(addr[0])
    except Exception: pass
    return sorted(set(A)), sorted(set(AAAA))

def get_mx(domain):
    # MX record resolution fallback via nslookup or system resolver if available.
    # Standard library socket can resolve it via platform-specific dns APIs or we can run nslookup
    # nslookup is highly cross-platform (Windows & Linux).
    mxs = []
    if shutil.which("nslookup"):
        try:
            out = subprocess.check_output(["nslookup", "-query=mx", domain], stderr=subprocess.DEVNULL, text=True, timeout=5)
            for line in out.splitlines():
                if "mail exchanger" in line:
                    parts = line.split("mail exchanger =")
                    if len(parts) > 1:
                        mxs.append(parts[1].strip())
        except Exception:
            pass
    return sorted(mxs)

def rdns(ip):
    try: return socket.gethostbyaddr(ip)[0]
    except Exception: return None

def ssl_info(domain):
    try:
        ctx = ssl.create_default_context()
        s = socket.create_connection((domain, 443), WHOIS_TIMEOUT)
        ss = ctx.wrap_socket(s, server_hostname=domain)
        cert = ss.getpeercert()
        ss.close()
        cn = None
        for it in cert.get("subject", ()):
            for k,v in it:
                if k.lower() in ("commonname","cn"): cn = v
        sans = [t[1] for t in cert.get("subjectAltName", ()) if t[0].lower()=="dns"]
        return {"cn": cn, "sans": sans}
    except Exception:
        try:
            A, _ = resolve(domain)
            if A:
                ip = A[0]
                try:
                    sock = socket.create_connection((ip, 443), WHOIS_TIMEOUT)
                    ctx = ssl.create_default_context()
                    ss = ctx.wrap_socket(sock, server_hostname=domain)
                    cert = ss.getpeercert(); ss.close()
                    cn = None
                    for it in cert.get("subject", ()):
                        for k,v in it:
                            if k.lower() in ("commonname","cn"): cn = v
                    sans = [t[1] for t in cert.get("subjectAltName", ()) if t[0].lower()=="dns"]
                    return {"cn": cn, "sans": sans}
                except Exception:
                    return None
        except Exception:
            return None
    return None

def parse_structured_whois(text):
    info = {
        "registrar": "Unknown",
        "created": "Unknown",
        "expires": "Unknown",
        "updated": "Unknown",
        "nservers": []
    }
    if not text:
        return info
    
    # Simple regex parsing patterns
    reg_m = re.search(r"Registrar:\s*(.+)", text, re.I)
    if reg_m: info["registrar"] = reg_m.group(1).strip()
    
    cr_m = re.search(r"Creation Date:\s*(.+)|Created On:\s*(.+)", text, re.I)
    if cr_m: info["created"] = (cr_m.group(1) or cr_m.group(2) or "").strip()
    
    ex_m = re.search(r"Registry Expiry Date:\s*(.+)|Expiration Date:\s*(.+)|Expiry Date:\s*(.+)", text, re.I)
    if ex_m: info["expires"] = (ex_m.group(1) or ex_m.group(2) or ex_m.group(3) or "").strip()
    
    up_m = re.search(r"Updated Date:\s*(.+)", text, re.I)
    if up_m: info["updated"] = up_m.group(1).strip()
    
    ns_matches = re.findall(r"Name Server:\s*(.+)", text, re.I)
    if ns_matches:
        info["nservers"] = sorted(list(set(ns.strip().lower() for ns in ns_matches)))
        
    return info

def recon(domain):
    out = {"target": domain, "time": now()}
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as exe:
        f1 = exe.submit(do_whois, domain)
        f2 = exe.submit(resolve, domain)
        f3 = exe.submit(ssl_info, domain)
        f4 = exe.submit(get_mx, domain)
        
        out["whois"] = f1.result()
        out["dns"] = f2.result()
        out["ssl"] = f3.result()
        out["mx"] = f4.result()
        
    out["rdns"] = {}
    A, AAAA = out["dns"]
    for ip in A + AAAA:
        out["rdns"][ip] = rdns(ip)
        
    # Structured summary
    out["structured"] = parse_structured_whois(out["whois"])
    return out

def display(r):
    print("\n" + "="*60)
    print(f"WHOIS Recon Report for {r['target']}  @ {r['time']}")
    print("="*60)
    
    print("\n[Structured WHOIS Details]")
    s = r["structured"]
    print(f"  Registrar : {s['registrar']}")
    print(f"  Created   : {s['created']}")
    print(f"  Expires   : {s['expires']}")
    print(f"  Updated   : {s['updated']}")
    if s["nservers"]:
        print(f"  NS Servers: {', '.join(s['nservers'])}")
    else:
        print("  NS Servers: Unknown")

    A, AAAA = r["dns"]
    print("\n[A Records]")
    for ip in A: print("  -", ip, "│ rDNS:", r["rdns"].get(ip))
    print("\n[AAAA Records]")
    for ip in AAAA: print("  -", ip, "│ rDNS:", r["rdns"].get(ip))
    
    print("\n[MX Records]")
    if r["mx"]:
        for mx in r["mx"]:
            print(f"  - {mx}")
    else:
        print("  No MX records resolved.")

    print("\n[SSL]")
    if r["ssl"]:
        print("  CN :", r["ssl"].get("cn"))
        print("  SAN:", ", ".join(r["ssl"].get("sans") or []))
    else:
        print("  No SSL or fetch failed")
        
    print("\n[WHOIS Raw Preview] (first 800 chars):")
    txt = (r["whois"] or "").strip()
    print(textwrap.indent(txt[:800], "  "))
    print("\n" + "="*60 + "\n")

if __name__ == "__main__":
    print(BANNER)
    target = input("Enter domain or host: ").strip()
    if target.startswith("http://") or target.startswith("https://"):
        target = target.split("://",1)[1].split("/")[0]
    print(f"\n[+] Running Recon for: {target}")
    res = recon(target)
    display(res)

    save = input("[?] Save results to file? (y/n): ").strip().lower()
    if save == 'y':
        import time
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        safe_domain = target.replace(".", "_")
        filename = f"whoishunt_{safe_domain}_{timestamp}.txt"
        try:
            with open(filename, "w", encoding="utf-8") as f:
                f.write(f"TheWildEye - WHOIS Recon Report\n")
                f.write(f"Target: {target}\n")
                f.write(f"Timestamp: {res['time']}\n")
                f.write("="*60 + "\n\n")
                
                f.write("[Structured Details]\n")
                s = res["structured"]
                f.write(f"  Registrar: {s['registrar']}\n")
                f.write(f"  Created:   {s['created']}\n")
                f.write(f"  Expires:   {s['expires']}\n")
                f.write(f"  Updated:   {s['updated']}\n")
                f.write(f"  Name Servers: {', '.join(s['nservers'])}\n\n")
                
                f.write("[DNS Records]\n")
                A, AAAA = res["dns"]
                f.write("  A:\n")
                for ip in A:
                    f.write(f"    - {ip} (rDNS: {res['rdns'].get(ip) or 'n/a'})\n")
                f.write("  AAAA:\n")
                for ip in AAAA:
                    f.write(f"    - {ip} (rDNS: {res['rdns'].get(ip) or 'n/a'})\n")
                f.write("\n")
                
                f.write("[MX Records]\n")
                for mx in res["mx"]:
                    f.write(f"  - {mx}\n")
                f.write("\n")
                
                f.write("[SSL Certificate]\n")
                if res["ssl"]:
                    f.write(f"  CN:  {res['ssl'].get('cn')}\n")
                    f.write(f"  SAN: {', '.join(res['ssl'].get('sans') or [])}\n\n")
                else:
                    f.write("  None/Error\n\n")
                
                f.write("[Raw WHOIS Output]\n")
                f.write(res["whois"] or "")
            print(f"[+] Results saved successfully to: {filename}")
        except Exception as err:
            print(f"[-] Failed to save file: {err}")
