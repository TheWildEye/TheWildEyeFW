

import threading, requests, time, sys, os
from queue import Queue


print("\033[1;92m")
print(r"""
$$$$$$$\  $$\           $$\   $$\                      $$\                         
$$  __$$\ \__|          $$ |  $$ |                     $$ |                        
$$ |  $$ |$$\  $$$$$$\  $$ |  $$ |$$\   $$\ $$$$$$$\ $$$$$$\    $$$$$$\   $$$$$$\  
$$ |  $$ |$$ |$$  __$$\ $$$$$$$$ |$$ |  $$ |$$  __$$\\_$$  _|  $$  __$$\ $$  __$$\ 
$$ |  $$ |$$ |$$ |  \__|$$  __$$ |$$ |  $$ |$$ |  $$ | $$ |    $$$$$$$$ |$$ |  \__|
$$ |  $$ |$$ |$$ |      $$ |  $$ |$$ |  $$ |$$ |  $$ | $$ |$$\ $$   ____|$$ |      
$$$$$$$  |$$ |$$ |      $$ |  $$ |\$$$$$$  |$$ |  $$ | \$$$$  |\$$$$$$$\ $$ |      
\_______/ \__|\__|      \__|  \__| \______/ \__|  \__|  \____/  \_______|\__|      

Directory Hunting with HTTP Codes and Redirecting Links                                                                  
""")
print("\033[0m")


target = input("🌐 Enter target URL (e.g., https://example.com): ").strip().rstrip('/')
wordlist_path = "wordlists/common.txt"
try:
    threads = int(input("🧵 Enter thread count (e.g., 10): ").strip())
except:
    threads = 10


q = Queue()
print_lock = threading.Lock()
found_dirs = []
stop_scan = False
start_time = time.time()
total_paths = 0

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
        return f"ℹ️ {code}"


def worker():
    while not q.empty() and not stop_scan:
        path = q.get()
        url = f"{target}/{path}"
        try:
            res = requests.get(url, allow_redirects=False, timeout=5)
            status_code = res.status_code
            status = get_status(status_code)
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
                    line = f"{status:<20} /{path:<25} → {url}"
                    print(line)
                    if redirect_to and redirect_to != "":
                        print(f"   ↪️  Redirects to: {redirect_to}")
                    found_dirs.append((f"/{path}", url, status, redirect_to))
                else:
                    scanned = total_paths - q.qsize()
                    elapsed = time.time() - start_time
                    avg_time = elapsed / scanned if scanned > 0 else 0.1
                    eta = avg_time * q.qsize()
                    sys.stdout.write(f"\r🔍 Scanning: /{path:<25} ⏳ ETA: {int(eta)}s")
                    sys.stdout.flush()
        except:
            pass
        q.task_done()


if not os.path.exists(wordlist_path):
    print(f"❌ Wordlist not found at {wordlist_path}")
    sys.exit(1)

with open(wordlist_path, 'r', encoding="utf-8", errors="ignore") as f:
    lines = f.read().splitlines()
    paths = [line.strip() for line in lines if line.strip()]
    total_paths = len(paths)
    for path in paths:
        q.put(path)


try:
    thread_list = []
    for _ in range(threads):
        t = threading.Thread(target=worker, daemon=True)
        t.start()
        thread_list.append(t)

    while any(t.is_alive() for t in thread_list):
        time.sleep(0.1)

except KeyboardInterrupt:
    stop_scan = True
    print("\n🛑 Stopping scan early...")


duration = time.time() - start_time
print("\n⏱️ Scan Duration: %.2f seconds" % duration)


if found_dirs:
    print("\n📁 Found Directories:\n")
    print(f"{'STATUS':<20} {'DIRECTORY':<20} {'LINK':<50} {'REDIRECT'}")
    print("-" * 110)
    for path, url, status, redirect_to in found_dirs:
        redirect_str = redirect_to if redirect_to else "-"
        print(f"{status:<20} {path:<20} {url:<50} {redirect_str}")
else:
    print("🚫 No directories found.")
