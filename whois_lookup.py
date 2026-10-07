import socket
from colorama import Fore, Style

WHOIS_SERVER = "whois.iana.org"

def run_whois(target, log_lines=None):
    if log_lines is None:
        log_lines = []

    print(Fore.CYAN + f"\n[*] WHOIS Lookup" + Style.RESET_ALL)
    print(f"    Target: {target}\n")

    try:
        domain = target.split("//")[-1].split("/")[0]

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(5)
            s.connect((WHOIS_SERVER, 43))
            s.send((domain + "\r\n").encode())
            response = b""
            while True:
                data = s.recv(4096)
                if not data:
                    break
                response += data

        lines = response.decode("utf-8", errors="ignore").splitlines()

        interesting = ["refer", "organisation", "address", "country",
                       "registrar", "created", "expires", "nserver"]

        found_any = False
        for line in lines:
            for key in interesting:
                if line.lower().startswith(key):
                    msg = f"[+] {line.strip()}"
                    print(Fore.GREEN + msg)
                    log_lines.append(msg)
                    found_any = True
                    break

        if not found_any:
            msg = "[?] No useful WHOIS data returned"
            print(Fore.YELLOW + msg)
            log_lines.append(msg)

    except Exception as e:
        msg = f"[-] WHOIS failed: {e}"
        print(Fore.RED + msg)
        log_lines.append(msg)

    print(Fore.CYAN + "\n[*] WHOIS lookup complete" + Style.RESET_ALL)
    log_lines.append("WHOIS lookup complete")