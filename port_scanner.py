import socket
import concurrent.futures
from colorama import Fore, Style

COMMON_PORTS = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
    53: "dns", 80: "http", 110: "pop3", 143: "imap",
    443: "https", 445: "smb", 3306: "mysql",
    3389: "rdp", 5900: "vnc", 8080: "http-alt", 8443: "https-alt"
}

def scan_port(host, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.5)
            result = s.connect_ex((host, port))
            return port, result == 0
    except Exception:
        return port, False

def run_port_scan(target, start_port=1, end_port=1024, log_lines=None):
    if log_lines is None:
        log_lines = []

    print(Fore.CYAN + f"[*] Port Scanner" + Style.RESET_ALL)
    print(f"    Scanning ports {start_port} to {end_port} on {target}\n")

    try:
        ip = socket.gethostbyname(target)
        msg = f"    Resolved {target} -> {ip}"
        print(Fore.WHITE + msg)
        log_lines.append(msg)
    except socket.gaierror:
        msg = f"[-] Could not resolve {target}"
        print(Fore.RED + msg)
        log_lines.append(msg)
        return []

    print()
    open_ports = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as ex:
        results = list(ex.map(
            lambda p: scan_port(ip, p),
            range(start_port, end_port + 1)
        ))

    for port, is_open in results:
        service = COMMON_PORTS.get(port, "unknown")
        if is_open:
            open_ports.append(port)
            msg = f"[+] Port {port:<6} OPEN    {service}"
            print(Fore.GREEN + msg)
            log_lines.append(msg)

    summary = f"\n[*] {len(open_ports)} open port(s) found on {target}"
    print(Fore.CYAN + summary + Style.RESET_ALL)
    log_lines.append(summary)

    return open_ports