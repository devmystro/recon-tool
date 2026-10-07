import requests
from colorama import Fore, Style

SECURITY_HEADERS = [
    "Content-Security-Policy",
    "X-Frame-Options",
    "Strict-Transport-Security",
    "X-Content-Type-Options",
    "Referrer-Policy",
]

INFO_HEADERS = ["Server", "X-Powered-By", "Via", "X-Generator"]

def grab_http_headers(target, log_lines=None):
    if log_lines is None:
        log_lines = []

    print(Fore.CYAN + f"\n[*] HTTP Header Analysis" + Style.RESET_ALL)
    print(f"    Target: {target}\n")

    try:
        resp = requests.get(f"http://{target}", timeout=5)
        msg = f"[+] Status: {resp.status_code}"
        print(Fore.GREEN + msg)
        log_lines.append(msg)
        print()

        print(Fore.YELLOW + "    Version disclosure:" + Style.RESET_ALL)
        for h in INFO_HEADERS:
            if h in resp.headers:
                msg = f"[!] {h}: {resp.headers[h]}"
                print(Fore.YELLOW + msg)
                log_lines.append(msg)

        print()
        print(Fore.YELLOW + "    Security headers:" + Style.RESET_ALL)
        for h in SECURITY_HEADERS:
            if h in resp.headers:
                msg = f"[+] PRESENT  {h}"
                print(Fore.GREEN + msg)
            else:
                msg = f"[-] MISSING  {h}"
                print(Fore.RED + msg)
            log_lines.append(msg)

    except Exception as e:
        msg = f"[-] Could not connect: {e}"
        print(Fore.RED + msg)
        log_lines.append(msg)