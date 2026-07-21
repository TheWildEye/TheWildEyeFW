#!/usr/bin/env python3
import os
import sys
import signal

HERE = os.path.abspath(os.path.dirname(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

from core.config import Config
from core.engine import autodiscover_modules, get_module, list_modules
from core.utils import colored


_interrupted = False

def signal_handler(sig, frame):
    global _interrupted
    if _interrupted:
        sys.exit(0)
    _interrupted = True
    raise KeyboardInterrupt()

signal.signal(signal.SIGINT, signal_handler)
if hasattr(signal, "SIGTERM"):
    signal.signal(signal.SIGTERM, signal_handler)

BANNER = r"""
$$$$$$$$\ $$\                 $$\      $$\ $$\ $$\       $$\ $$$$$$$$\                    
\__$$  __|$$ |                $$ | $\  $$ |\__|$$ |      $$ |$$  _____|                   
   $$ |   $$$$$$$\   $$$$$$\  $$ |$$$\ $$ |$$\ $$ | $$$$$$$ |$$ |     $$\   $$\  $$$$$$\  
   $$ |   $$  __$$\ $$  __$$\ $$ $$ $$\ $$ |$$ |$$ |$$  __$$ |$$$$$\   $$ |  $$ |$$  __$$\ 
   $$ |   $$ |  $$ |$$$$$$$$ |$$$$  _$$$$ |$$ |$$ |$$ /  $$ |$$  __|  $$ |  $$ |$$$$$$$$ |
   $$ |   $$ |  $$ |$$   ____|$$$  / \$$$ |$$ |$$ |$$ |  $$ |$$ |     $$ |  $$ |$$   ____|
   $$ |   $$ |  $$ |\$$$$$$$\ $$  /   \$$ |$$ |$$ |\$$$$$$$ |$$$$$$$$\\$$$$$$$ |\$$$$$$$\ 
   \__|   \__|  \__| \_______|\__/     \__|\__|\__| \_______|\________|\____$$ | \_______|
                                                                       $$\   $$ |          
                                                                       \$$$$$$  |          
                                                                        \______/           
            UNIFIED RECONNAISSANCE & OSINT FRAMEWORK v2 - VYOM NAGPAL
"""

MENU_ITEMS = [
    ("mailhunter", "MailHunter   - Web crawler w/ JavaScript rendering"),
    ("dirhunter",     "DirHunter       - Smart directory & file discovery"),
    ("apihunter", "APIHunter   - Smart API endpoint discovery"),
    ("jsreaphunter",  "JSReapHunter    - JavaScript analysis + API extraction"),
    ("techhunter",    "TechHunter      - CMS/framework/library fingerprinting"),
    ("wphunter",      "WPHunter        - WordPress vulnerability scanner"),
    ("whoishunter",   "WhoisHunter     - Domain WHOIS recon engine"),
    ("wafhunter",     "WAFHunter       - Web firewall detection"),
    ("subhunter",     "SubHunter       - Subdomain enumeration"),
    ("osinthunter",   "OSINTHunter     - Email/username/domain OSINT recon"),
    ("all",           "All Modules     - Run every module on target"),
]

_module_names = [m[0] for m in MENU_ITEMS]


def banner():
    print(colored(BANNER, "green"))


def menu():
    print(f"\n{colored('='*58, 'cyan')}")
    print(f"{colored('  THEWILDEYE RECON & OSINT FRAMEWORK', 'bold')}")
    print(f"{colored('='*58, 'cyan')}")
    for i, (_, desc) in enumerate(MENU_ITEMS, 1):
        print(f"  {colored(f'{i:>2})', 'yellow')} {desc}")
    print(f"  {colored(' 0)', 'yellow')}  Exit")
    print()


def prompt(text, default=None):
    d = f" [{default}]" if default else ""
    val = input(f"  {colored('>>', 'green')} {text}{d}: ").strip()
    return val if val else (default or "")


def run_module(name, target, **kwargs):
    config = Config()
    mod_cls = get_module(name)
    if not mod_cls:
        print(f"  {colored('[!] Module not available', 'red')}")
        return
    m = mod_cls(config)
    m.output_formats = ["txt", "json"]
    interrupted = False
    try:
        m.run(target, **kwargs)
    except KeyboardInterrupt:
        print(f"\n  {colored('[!] Module interrupted', 'yellow')}")
        interrupted = True
    except Exception as e:
        print(f"\n  {colored(f'[!] Error: {e}', 'red')}")

    if interrupted:
        inp = input(f"  {colored('>>', 'green')} Save partial report? [R=yes, any key=discard]: ").strip().lower()
        if inp == "r":
            try:
                m.save_report(partial=True)
            except Exception:
                pass
    else:
        inp = input(f"  {colored('>>', 'green')} Save report? [R=yes, any key=continue]: ").strip().lower()
        if inp == "r":
            try:
                m.save_report()
            except Exception:
                pass


def _check_skip():
    """Check stdin for 's' or 'q' keypress without blocking (cross-platform)."""
    ch = None
    try:
        if sys.platform == "win32":
            import msvcrt
            if msvcrt.kbhit():
                ch = msvcrt.getch().decode().lower()
        else:
            import select
            if select.select([sys.stdin], [], [], 0)[0]:
                ch = sys.stdin.read(1).lower()
    except Exception:
        pass
    return ch


def run_all_modules(target, js_render=False):
    # Normalize: ensure target is always a full URL for modules that need it
    if not target.startswith(("http://", "https://")):
        target = "https://" + target
    from urllib.parse import urlparse
    domain = urlparse(target).netloc

    modules_to_run = [
        "techhunter", "wafhunter", "mailhunter", "jsreaphunter",
        "apihunter", "dirhunter", "wphunter", "whoishunter",
        "subhunter", "dorkhunter"
    ]

    print(f"\n  {colored('ALL MODULES MODE', 'bold')}")
    print(f"  Target: {target}")
    print(f"  Press {colored('S', 'yellow')} to skip a module, {colored('Q', 'red')} to quit")
    print()

    config = Config()

    total = len(modules_to_run)
    for idx, mod_name in enumerate(modules_to_run, 1):
        mod_cls = get_module(mod_name)
        if not mod_cls:
            continue

        url_target = target if mod_name in (
            "wphunter", "techhunter", "wafhunter", "mailhunter",
            "jsreaphunter", "apihunter", "dirhunter"
        ) else domain

        print(f"\n  {colored('='*50, 'cyan')}")
        print(f"  {colored(f'[{idx}/{total}] {mod_name.upper()}', 'bold')}")
        print(f"  {colored('='*50, 'cyan')}")

        skip = input(f"  {colored('>>', 'green')} Run? [Enter=yes, s=skip, q=quit all]: ").strip().lower()
        if skip == "q":
            print(f"  {colored('[!] All modules aborted', 'red')}")
            break
        if skip in ("s", "n", "no", "skip"):
            print(f"  {colored('[!] Skipped', 'yellow')}")
            continue
        if skip not in ("", "y", "yes", "run"):
            print(f"  {colored(f'[!] Unknown input \"{skip}\", running module...', 'yellow')}")

        m = mod_cls(config)
        m.output_formats = ["txt", "json"]

        mod_kwargs = {}
        if mod_name == "mailhunter":
            mod_kwargs["js_render"] = js_render
            mod_kwargs["depth"] = 3
        elif mod_name == "dirhunter":
            mod_kwargs["threads"] = 10
        elif mod_name == "jsreaphunter":
            mod_kwargs["api_fuzz"] = True
            mod_kwargs["max_fuzz"] = 500
        elif mod_name == "apihunter":
            mod_kwargs["max_seeds"] = 1000
            mod_kwargs["threads"] = 20

        interrupted = False
        try:
            m.run(url_target, **mod_kwargs)
        except KeyboardInterrupt:
            print(f"\n  {colored('[!] Stopped by user', 'yellow')}")
            interrupted = True
        except Exception as e:
            print(f"\n  {colored(f'[!] {mod_name} error: {e}', 'red')}")

        if interrupted:
            inp = input(f"  {colored('>>', 'green')} Save partial report? [R=yes, any key=discard]: ").strip().lower()
            if inp == "r":
                try:
                    m.save_report(partial=True)
                except Exception:
                    pass
            break
        else:
            inp = input(f"  {colored('>>', 'green')} Save report? [R=yes, any key=continue]: ").strip().lower()
            if inp == "r":
                try:
                    m.save_report()
                except Exception:
                    pass

    print(f"\n  {colored('='*50, 'green')}")
    print(f"  {colored('ALL MODULES COMPLETE', 'bold')}")
    print(f"  Reports: {os.path.join(HERE, 'reports')}")


def main():
    banner()
    autodiscover_modules()

    if len(sys.argv) > 1 and sys.argv[1] in _module_names:
        cmd = sys.argv[1]
        target = sys.argv[2] if len(sys.argv) > 2 else prompt("Enter target")
        run_module(cmd, target)
        return

    if len(sys.argv) > 1:
        print(f"  Usage: TheWildEye.py")
        print(f"         TheWildEye.py <module> <target>")
        print(f"  Modules: {', '.join(_module_names)}")
        return

    while True:
        menu()
        choice = input(f"  {colored('Select:', 'cyan')} ").strip()

        if choice == "0" or choice.lower() in ("q", "quit", "exit"):
            print(f"\n  {colored('Exiting. Goodbye!', 'green')}")
            break

        if not choice.isdigit() or int(choice) < 1 or int(choice) > len(MENU_ITEMS):
            print(f"  {colored('[!] Invalid choice', 'red')}")
            continue

        idx = int(choice) - 1
        name, desc = MENU_ITEMS[idx]
        print(f"\n  {colored('\u2500'*50, 'cyan')}")
        print(f"  {colored(desc, 'bold')}")
        print(f"  {colored('\u2500'*50, 'cyan')}")

        if name == "osinthunter":
            target = prompt("Enter email / username / domain")
        else:
            target = prompt("Enter target URL/domain")
        if not target:
            print(f"  {colored('[!] No target given', 'red')}")
            continue

        kwargs = {}

        if name == "mailhunter":
            js = prompt("Enable JS rendering? (y/N)", "n")
            kwargs["js_render"] = js.lower() == "y"
            depth = prompt("Max depth", "3")
            kwargs["depth"] = int(depth) if depth.isdigit() else 3

        elif name == "dirhunter":
            t = prompt("Threads", "10")
            kwargs["threads"] = int(t) if t.isdigit() else 10

        elif name == "apihunter":
            t = prompt("Threads", "20")
            kwargs["threads"] = int(t) if t.isdigit() else 20
            s = prompt("Max seed paths", "1000")
            kwargs["max_seeds"] = int(s) if s.isdigit() else 1000

        elif name == "jsreaphunter":
            fuzz = prompt("Enable API path fuzzing? (Y/n)", "y")
            kwargs["api_fuzz"] = fuzz.lower() != "n"
            mf = prompt("Max paths to fuzz", "500")
            kwargs["max_fuzz"] = int(mf) if mf.isdigit() else 500

        elif name == "all":
            js = prompt("Enable JS rendering for crawler? (y/N)", "n")
            kwargs["js_render"] = js.lower() == "y"

        print()
        config = Config()

        if name == "all":
            run_all_modules(target, js_render=kwargs.get("js_render", False))

        elif name == "osinthunter":
            run_module(name, target, **kwargs)
        else:
            run_module(name, target, **kwargs)

        input(f"\n  {colored('Press Enter to return to menu...', 'cyan')}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n  {colored('Goodbye!', 'green')}")
        sys.exit(1)
    except Exception as e:
        print(f"\n  {colored(f'Fatal: {e}', 'red')}")
        sys.exit(1)
