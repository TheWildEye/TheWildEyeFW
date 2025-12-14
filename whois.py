#!/usr/bin/env python3
import socket, ssl, concurrent.futures, datetime, textwrap, subprocess, shutil, sys, ctypes

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
$$\\      $$\\ $$\\   $$\\  $$$$$$\\  $$$$$$\\  $$$$$$\\  
$$ | $\\  $$ |$$ |  $$ |$$  __$$\\ \\_$$  _|$$  __$$\\ 
$$ |$$$\\ $$ |$$ |  $$ |$$ /  $$ |  $$ |  $$ /  \\__|
$$ $$ $$\\$$ |$$$$$$$$ |$$ |  $$ |  $$ |  \\$$$$$$\\  
$$$$  _$$$$ |$$  __$$ |$$ |  $$ |  $$ |   \\____$$\\ 
$$$  / \\$$$ |$$ |  $$ |$$ |  $$ |  $$ |  $$\\   $$ |
$$  /   \\$$ |$$ |  $$ | $$$$$$  |$$$$$$\\ \\$$$$$$  |
\\__/     \\__|\\__|  \\__| \\______/ \\______| \\______/ 
                                                   
                                                   
                                                   
\033[0m
"""
""

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
    except: pass
    return b"".join(buf).decode(errors="ignore")

def get_tld(domain):
    parts = domain.rsplit(".", 2)
    if len(parts) >= 2: return parts[-1].lower()
    return ""

def try_whois_socket(server, query, timeout=WHOIS_TIMEOUT):
    try:
        ip = socket.getaddrinfo(server, 43)[0][4][0]
    except:
        ip = None
    try:
        if ip:
            s = socket.create_connection((ip, 43), timeout)
        else:
            s = socket.create_connection((server, 43), timeout)
        s.settimeout(timeout)
        s.sendall((query + "\r\n").encode())
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
    import re
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
            out = subprocess.check_output(["whois", domain], stderr=subprocess.DEVNULL, text=True, timeout=WHOIS_TIMEOUT)
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
    except: pass
    return sorted(set(A)), sorted(set(AAAA))

def rdns(ip):
    try: return socket.gethostbyaddr(ip)[0]
    except: return None

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
    except:
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
                except:
                    return None
        except:
            return None
    return None

def recon(domain):
    out = {"target": domain, "time": now()}
    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as exe:
        f1 = exe.submit(do_whois, domain)
        f2 = exe.submit(resolve, domain)
        f3 = exe.submit(ssl_info, domain)
        out["whois"] = f1.result()
        out["dns"] = f2.result()
        out["ssl"] = f3.result()
    out["rdns"] = {}
    A, AAAA = out["dns"]
    for ip in A + AAAA:
        out["rdns"][ip] = rdns(ip)
    return out

def display(r):
    print("\n" + "="*60)
    print(f"WHOIS Recon Report for {r['target']}  @ {r['time']}")
    print("="*60)
    A, AAAA = r["dns"]
    print("\n[A Records]")
    for ip in A: print("  -", ip, "│ rDNS:", r["rdns"].get(ip))
    print("\n[AAAA Records]")
    for ip in AAAA: print("  -", ip, "│ rDNS:", r["rdns"].get(ip))
    print("\n[SSL]")
    if r["ssl"]:
        print("  CN :", r["ssl"].get("cn"))
        print("  SAN:", ", ".join(r["ssl"].get("sans") or []))
    else:
        print("  No SSL or fetch failed")
    print("\n[WHOIS] (first 1200 chars):")
    txt = (r["whois"] or "").strip()
    print(textwrap.indent(txt[:1200], "  "))
    print("\n" + "="*60 + "\n")

if __name__ == "__main__":
    print(BANNER)
    target = input("Enter domain or host: ").strip()
    if target.startswith("http://") or target.startswith("https://"):
        target = target.split("://",1)[1].split("/")[0]
    print(f"\n[+] Running Recon for: {target}")
    res = recon(target)
    display(res)
