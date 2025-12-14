import os
import sys
import subprocess

HERE = os.path.abspath(os.path.dirname(__file__))

TIGERCRAWLER = os.path.join(HERE, "TigerCrawler.py")
TIGERHUNT    = os.path.join(HERE, "tigbuster.py")
TIGERWP      = os.path.join(HERE, "wp_enum.py")
TIGERWHOIS   = os.path.join(HERE, "whois.py")
TIGERWAF     = os.path.join(HERE, "firewall.py")

PY = sys.executable 

def file_exists(path):
    return os.path.isfile(path)

def run_subprocess(args):
    try:
        subprocess.run(args, check=False)
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user. Returning to menu.")
    except Exception as e:
        print(f"[!] Failed to run: {e}")

def run_tigercrawler():
    if not file_exists(TIGERCRAWLER):
        print(f"[!] Missing: {TIGERCRAWLER}")
        return
    run_subprocess([PY, TIGERCRAWLER])

def run_tigerhunt():
    if not file_exists(TIGERHUNT):
        print(f"[!] Missing: {TIGERHUNT}")
        return
    run_subprocess([PY, TIGERHUNT])

def run_tigerwp():
    if not file_exists(TIGERWP):
        print(f"[!] Missing: {TIGERWP}")
        return
    run_subprocess([PY, TIGERWP])

def run_tigerwhois():
    if not file_exists(TIGERWHOIS):
        print(f"[!] Missing: {TIGERWHOIS}")
        return
    run_subprocess([PY, TIGERWHOIS])

def run_tigerwaf():
    if not file_exists(TIGERWAF):
        print(f"[!] Missing: {TIGERWAF}")
        return
    run_subprocess([PY, TIGERWAF])

def show_menu():
    print("\033[92m" + r"""
$$$$$$$$\ $$\                 $$\      $$\ $$\ $$\       $$\ $$$$$$$$\                    
\__$$  __|$$ |                $$ | $\  $$ |\__|$$ |      $$ |$$  _____|                   
   $$ |   $$$$$$$\   $$$$$$\  $$ |$$$\ $$ |$$\ $$ | $$$$$$$ |$$ |     $$\   $$\  $$$$$$\  
   $$ |   $$  __$$\ $$  __$$\ $$ $$ $$\$$ |$$ |$$ |$$  __$$ |$$$$$\   $$ |  $$ |$$  __$$\ 
   $$ |   $$ |  $$ |$$$$$$$$ |$$$$  _$$$$ |$$ |$$ |$$ /  $$ |$$  __|  $$ |  $$ |$$$$$$$$ |
   $$ |   $$ |  $$ |$$   ____|$$$  / \$$$ |$$ |$$ |$$ |  $$ |$$ |     $$ |  $$ |$$   ____|
   $$ |   $$ |  $$ |\$$$$$$$\ $$  /   \$$ |$$ |$$ |\$$$$$$$ |$$$$$$$$\\$$$$$$$ |\$$$$$$$\ 
   \__|   \__|  \__| \_______|\__/     \__|\__|\__| \_______|\________|\____$$ | \_______|
                                                                      $$\   $$ |          
                                                                      \$$$$$$  |          
                                                                       \______/           
        UNIFIED RECONNAISSANCE & OSINT FRAMEWORK - VYOM NAGPAL
    """ + "\033[0m")

    print("\n1) TheCrawler")
    print("2) DirHunter")
    print("3) WPHunter")
    print("4) WhoisHunt")
    print("5) WAFHunter")
    print("0) Exit\n")

def main_loop():
    while True:
        try:
            show_menu()
            choice = input("Choose an option: ").strip()
            if choice == "1":
                run_tigercrawler()
            elif choice == "2":
                run_tigerhunt()
            elif choice == "3":
                run_tigerwp()
            elif choice == "4":
                run_tigerwhois()
            elif choice == "5":
                run_tigerwaf()
            elif choice == "0" or choice.lower() in ("q", "quit", "exit"):
                print("Exiting TheWildEye.")
                break
            else:
                print("Invalid choice. Pick 1, 2, 3, 4, 5 or 0.")
        except KeyboardInterrupt:
            print("\nInterrupted — returning to menu.")
        except Exception as e:
            print(f"Unexpected error: {e}")

if __name__ == "__main__":
    main_loop()
