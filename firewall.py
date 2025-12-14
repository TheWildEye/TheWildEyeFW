#!/usr/bin/env python3
import re, socket, ssl, requests
from urllib.parse import urlparse, urljoin
from collections import Counter

TIMEOUT = 7
THRESHOLD = 8

VENDORS = {
 "Cloudflare": {
   "hdr":[r"cf-ray", r"server:\s*cloudflare"],
   "body":[r"cloudflare"],
   "cookie":[r"cfduid", r"cf_clearance"]
 },
 "AWS WAF / CloudFront": {
   "hdr":[r"x-amz-cf-id", r"x-amzn", r"via:\s*cloudfront"],
   "body":[r"cloudfront", r"aws"],
   "cookie":[r"awselb"]
 },
 "Fortinet": {
   "hdr":[r"forti", r"server:\s*forti"],
   "body":[r"fortinet", r"fortiweb", r"fortigate"],
   "cookie":[]
 },
 "Sophos": {
   "hdr":[r"sophos", r"x-sophos"],
   "body":[r"sophos"],
   "cookie":[]
 }
}

PROBES = [
 ("GET","/"),
 ("GET","/?test=<script>alert(1)</script>"),
 ("GET","/?id=' OR '1'='1"),
 ("POST","/"),
 ("HEAD","/")
]

def banner():
    print("\033[92m")
    print(r"""
$$\      $$\  $$$$$$\  $$$$$$$$\ $$\   $$\                      $$\                         
$$ | $\  $$ |$$  __$$\ $$  _____|$$ |  $$ |                     $$ |                        
$$ |$$$\ $$ |$$ /  $$ |$$ |      $$ |  $$ |$$\   $$\ $$$$$$$\ $$$$$$\    $$$$$$\   $$$$$$\  
$$ $$ $$\$$ |$$$$$$$$ |$$$$$\    $$$$$$$$ |$$ |  $$ |$$  __$$\\_$$  _|  $$  __$$\ $$  __$$\ 
$$$$  _$$$$ |$$  __$$ |$$  __|   $$  __$$ |$$ |  $$ |$$ |  $$ | $$ |    $$$$$$$$ |$$ |  \__|
$$$  / \$$$ |$$ |  $$ |$$ |      $$ |  $$ |$$ |  $$ |$$ |  $$ | $$ |$$\ $$   ____|$$ |      
$$  /   \$$ |$$ |  $$ |$$ |      $$ |  $$ |\$$$$$$  |$$ |  $$ | \$$$$  |\$$$$$$$\ $$ |      
\__/     \__|\__|  \__|\__|      \__|  \__| \______/ \__|  \__|  \____/  \_______|\__|      
                                                                                                                                                                                                                                                          
FIREWALL / WAF DETECTOR
""")
    print("\033[0m", end="")

def normalize(t):
    p=urlparse(t)
    if not p.scheme:
        t="https://"+t
        p=urlparse(t)
    return f"{p.scheme}://{p.netloc}".rstrip("/")

def resolve(host):
    try:
        a=socket.getaddrinfo(host,None)
        return sorted({i[4][0] for i in a})
    except:
        return []

def req(method,url,session):
    try:
        if method=="GET": return session.get(url,timeout=TIMEOUT,verify=True,allow_redirects=False)
        if method=="HEAD":return session.head(url,timeout=TIMEOUT,verify=True,allow_redirects=False)
        return session.post(url,data={"x":"1"},timeout=TIMEOUT,verify=True,allow_redirects=False)
    except:
        return None

def run_probes(base,session):
    arr=[]
    for m,p in PROBES:
        u=urljoin(base+"/",p.lstrip("/"))
        r=req(m,u,session)
        if not r:
            arr.append({"m":m,"u":u,"s":None,"h":"","b":"","c":""})
        else:
            h=" ".join([f"{k}:{v}" for k,v in r.headers.items()]).lower()
            b=(r.text or "").lower()
            c=" ".join(list(r.cookies.keys())).lower()
            arr.append({"m":m,"u":u,"s":r.status_code,"h":h,"b":b,"c":c})
    return arr

def passive(base):
    host=urlparse(base).hostname
    out={"dns":resolve(host),"cn":"","san":[]}
    try:
        ctx=ssl.create_default_context()
        with socket.create_connection((host,443),timeout=4) as s:
            with ctx.wrap_socket(s,server_hostname=host) as ss:
                cert=ss.getpeercert()
                for t in cert.get("subject",()):
                    for k,v in t:
                        if k.lower()=="commonname": out["cn"]=v.lower()
                for t in cert.get("subjectAltName",()):
                    if t[0]=="DNS": out["san"].append(t[1].lower())
    except:
        pass
    return out

def detect(base):
    session=requests.Session()
    probes=run_probes(base,session)
    passive_info=passive(base)
    scores=Counter()

    for p in probes:
        ht=p["h"]; bt=p["b"]; ct=p["c"]; st=p["s"]
        for vendor,data in VENDORS.items():
            pts=0
            if any(re.search(x,ht) for x in data["hdr"]): pts+=6
            if any(re.search(x,bt) for x in data["body"]): pts+=4
            if any(re.search(x,ct) for x in data["cookie"]): pts+=2
            if st in (403,406,429,501,503): pts+=3
            if pts>0: scores[vendor]+=pts

    comb=" ".join([passive_info["cn"]]+passive_info["san"])
    if "cloudflare" in comb: scores["Cloudflare"]+=6
    if "cloudfront" in comb or "amazon" in comb: scores["AWS WAF / CloudFront"]+=6
    if "forti" in comb: scores["Fortinet"]+=6
    if "sophos" in comb: scores["Sophos"]+=6

    detected=[(v,s) for v,s in scores.items() if s>=THRESHOLD]
    detected.sort(key=lambda x:x[1], reverse=True)
    return probes, passive_info, detected

def main():
    banner()
    t=input("Enter target URL: ").strip()
    if not t: return
    base=normalize(t)
    host=urlparse(base).hostname
    if not resolve(host):
        print("DNS resolution failed.")
        return
    print(f"\n[+] Scanning: {base}\n")
    probes,passive_info,detected=detect(base)

    for p in probes:
        print(f"[{p['m']}] {p['u']} -> {p['s']}")

    if detected:
        print("\n🔥 Detected:")
        for n,s in detected:
            print(f"   → {n} (score {s})")
    else:
        print("\n⚠ No WAF detected.")

    print("\n[+] Passive clues:")
    print(" DNS:", passive_info["dns"])
    print(" CN:", passive_info["cn"])
    print(" SAN:", passive_info["san"])
    print("\n✔ Done.\n")

if __name__=="__main__":
    main()
