#!/usr/bin/env python3
import threading
import queue
import re
import time
import random
import urllib.parse
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse

# ================= CONFIG =================

MAX_URLS    = 500      
MAX_THREADS = 20
TIMEOUT     = 6

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "Mozilla/5.0 (X11; Linux x86_64)",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)"
]

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", re.I)
BAD_EXTS = (".png", ".jpg", ".jpeg", ".webp", ".svg", ".gif", ".webex")

# ==========================================

to_visit = queue.Queue()
visited  = set()
queued   = set()
emails   = set()
lock     = threading.Lock()
count    = 0

session = requests.Session()

def enqueue(url):
    with lock:
        if (
            url not in visited and
            url not in queued and
            len(visited) + to_visit.qsize() < MAX_URLS
        ):
            queued.add(url)
            to_visit.put(url)

def worker():
    global count
    while True:
        url = to_visit.get()
        if url is None:
            to_visit.task_done()
            return

        with lock:
            queued.discard(url)
            visited.add(url)
            count += 1
            idx = count

        print(f"[{idx}] Crawling: {url}")

        try:
            session.headers["User-Agent"] = random.choice(USER_AGENTS)
            time.sleep(random.uniform(0.8, 1.6))

            resp = session.get(url, timeout=TIMEOUT)
            html = resp.text

            found = set(EMAIL_RE.findall(html))
            found = {e for e in found if not e.lower().endswith(BAD_EXTS)}
            with lock:
                emails.update(found)

            soup = BeautifulSoup(html, "lxml")

            for a in soup.find_all("a", href=True):
                href = a["href"].strip()

                if href.startswith(("mailto:", "tel:", "#", "javascript:", "ftp:")):
                    continue

                if href.startswith("/"):
                    link = BASE_URL + href
                elif href.startswith("http"):
                    link = href
                else:
                    link = urllib.parse.urljoin(url, href)

                if urlparse(link).netloc == TARGET_DOMAIN:
                    enqueue(link)

        except Exception:
            pass

        to_visit.task_done()

def main():
    global TARGET_DOMAIN, BASE_URL

    start = input("[+] Enter target URL (with http/https): ").strip()
    if not start.startswith(("http://", "https://")):
        print("[-] Include http:// or https://")
        return

    parsed = urlparse(start)
    TARGET_DOMAIN = parsed.netloc
    BASE_URL = f"{parsed.scheme}://{parsed.netloc}"

    enqueue(start)

    threads = []
    for _ in range(MAX_THREADS):
        t = threading.Thread(target=worker, daemon=True)
        t.start()
        threads.append(t)

    to_visit.join()

    for _ in threads:
        to_visit.put(None)
    for t in threads:
        t.join()

    print("\n[+] Emails Found:")
    if emails:
        for e in sorted(emails):
            print(" -", e)
    else:
        print("No emails found.")

    print(f"\n[+] Total URLs crawled: {len(visited)}")

if __name__ == "__main__":
    main()
