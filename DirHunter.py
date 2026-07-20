#!/usr/bin/env python3

import threading
import requests
import time
import sys
import os
from queue import Queue

BANNER = r"""
$$$$$$$\  $$\           $$\   $$\                      $$\                         
$$  __$$\ \__|          $$ |  $$ |                     $$ |                        
$$ |  $$ |$$\  $$$$$$\  $$ |  $$ |$$\   $$\ $$$$$$$\ $$$$$$\    $$$$$$\   $$$$$$\  
$$ |  $$ |$$ |$$  __$$\ $$$$$$$$ |$$ |  $$ |$$  __$$\\_$$  _|  $$  __$$\ $$  __$$\ 
$$ |  $$ |$$ |$$ |  \__|$$  __$$ |$$ |  $$ |$$ |  $$ | $$ |    $$$$$$$$ |$$ |  \__|
$$ |  $$ |$$ |$$ |      $$ |  $$ |$$ |  $$ |$$ |  $$ | $$ |$$\ $$   ____|$$ |      
$$$$$$$  |$$ |$$ |      $$ |  $$ |\$$$$$$  |$$ |  $$ | \$$$$  |\$$$$$$$\ $$ |      
\_______/ \__|\__|      \__|  \__| \______/ \__|  \__|  \____/  \_______|\__|      
                                                                                                                                                                                                                                               
Directory Hunting with HTTP Codes and Redirecting Links
UNIFIED RECONNAISSANCE & OSINT FRAMEWORK - VYOM NAGPAL
"""


def get_status(code):
    if code == 200:
        return f"✅ PUBLIC [{code}]"
    elif code in [301, 302]:
        return f"🔄 REDIRECT [{code}]"
    elif code == 403:
        return f"🔒 FORBIDDEN [{code}]"
    elif code == 401:
        return f"🔑 UNAUTHORIZED [{code}]"
    else:
        return f"ℹ️  {code}"


def worker(q, target, found_dirs, print_lock, stop_event, total_paths, start_time):
    while not q.empty() and not stop_event.is_set():
        try:
            path = q.get(timeout=0.5)
        except Exception:
            break
        url = f"{target}/{path}"
        try:
            res = requests.get(url, allow_redirects=False, timeout=5)
            status_code = res.status_code
            status = get_status(status_code)
            
            # Calculate content size
            content_length = len(res.content)
            if content_length >= 1024:
                size_str = f"{content_length / 1024:.1f} KB"
            else:
                size_str = f"{content_length} B"

            redirect_to = ""
            if status_code in [301, 302]:
                location = res.headers.get("Location", "Unknown")
                if location == url or location == f"{url}/":
                    redirect_to = "↻ same"
                else:
                    redirect_to = location

            with print_lock:
                sys.stdout.write("\r\033[K")
                if status_code in [200, 301, 302, 403, 401]:
                    line = f"{status:<20} /{path:<25} → {url} ({size_str})"
                    print(line)
                    if redirect_to:
                        print(f"   ↪️  Redirects to: {redirect_to}")
                    found_dirs.append((f"/{path}", url, status, redirect_to, size_str))
                else:
                    scanned = total_paths - q.qsize()
                    elapsed = time.time() - start_time
                    avg_time = elapsed / scanned if scanned > 0 else 0.1
                    eta = avg_time * q.qsize()
                    sys.stdout.write(
                        f"\r🔍 Scanning: /{path:<25} ⏳ ETA: {int(eta)}s"
                    )
                    sys.stdout.flush()
        except Exception:
            pass
        q.task_done()


def main():
    print("\033[1;92m" + BANNER + "\033[0m")

    target = input("🌐 Enter target URL (e.g., https://example.com): ").strip().rstrip("/")
    if not target:
        print("[-] No target provided. Exiting.")
        return

    # Resolve default wordlist path relative to this script's directory
    here = os.path.dirname(os.path.abspath(__file__))
    default_wordlist = os.path.join(here, "wordlists", "common.txt")

    wordlist_input = input(f"📄 Wordlist path [default: {os.path.relpath(default_wordlist, here) if os.path.exists(default_wordlist) else 'wordlists/common.txt'}]: ").strip()
    if wordlist_input:
        wordlist_path = os.path.abspath(wordlist_input)
    else:
        wordlist_path = default_wordlist

    if not os.path.exists(wordlist_path):
        print(f"❌ Wordlist not found at: {wordlist_path}")
        sys.exit(1)

    try:
        threads = int(input("🧵 Enter thread count (e.g., 10): ").strip())
        threads = max(1, min(threads, 50))
    except Exception:
        threads = 10

    with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
        lines = f.read().splitlines()
    paths = [line.strip() for line in lines if line.strip()]
    total_paths = len(paths)

    q = Queue()
    for path in paths:
        q.put(path)

    print_lock = threading.Lock()
    found_dirs = []
    stop_event = threading.Event()
    start_time = time.time()

    try:
        thread_list = []
        for _ in range(threads):
            t = threading.Thread(
                target=worker,
                args=(q, target, found_dirs, print_lock, stop_event, total_paths, start_time),
                daemon=True,
            )
            t.start()
            thread_list.append(t)

        while any(t.is_alive() for t in thread_list):
            time.sleep(0.1)

    except KeyboardInterrupt:
        stop_event.set()
        print("\n🛑 Stopping scan early...")

    duration = time.time() - start_time
    print("\n⏱️  Scan Duration: %.2f seconds" % duration)

    if found_dirs:
        print("\n📁 Found Directories:\n")
        print(f"{'STATUS':<20} {'DIRECTORY':<20} {'SIZE':<10} {'LINK':<50} {'REDIRECT'}")
        print("-" * 120)
        for path, url, status, redirect_to, size in found_dirs:
            redirect_str = redirect_to if redirect_to else "-"
            print(f"{status:<20} {path:<20} {size:<10} {url:<50} {redirect_str}")
    else:
        print("🚫 No directories found.")

    save = input("\n[?] Save results to file? (y/n): ").strip().lower()
    if save == 'y':
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        parsed_target = urllib.parse.urlparse(target)
        safe_host = (parsed_target.netloc or parsed_target.path).replace(".", "_").replace(":", "_")
        filename = f"dirhunter_{safe_host}_{timestamp}.txt"
        try:
            with open(filename, "w", encoding="utf-8") as f:
                f.write(f"TheWildEye - DirHunter Directory Bruteforcing Report\n")
                f.write(f"Target: {target}\n")
                f.write(f"Wordlist: {wordlist_path}\n")
                f.write(f"Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write("="*60 + "\n\n")
                if found_dirs:
                    f.write(f"{'STATUS':<20} {'DIRECTORY':<20} {'SIZE':<10} {'LINK':<50} {'REDIRECT'}\n")
                    f.write("-" * 120 + "\n")
                    for path, url, status, redirect_to, size in found_dirs:
                        redirect_str = redirect_to if redirect_to else "-"
                        f.write(f"{status:<20} {path:<20} {size:<10} {url:<50} {redirect_str}\n")
                else:
                    f.write("No directories found.\n")
            print(f"[+] Results saved successfully to: {filename}")
        except Exception as err:
            print(f"[-] Failed to save file: {err}")


if __name__ == "__main__":
    main()
