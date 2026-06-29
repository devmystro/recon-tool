import socket
import concurrent.futures

def scan_port(host, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.5)
            result = s.connect_ex((host, port))
            return port, result == 0
    except Exception:
        return port, False

def run_port_scan(target, start_port=1, end_port=1024):
    print(f'\n[*] Scanning {target} — ports {start_port} to {end_port}')
    try:
        ip = socket.gethostbyname(target)
        print(f'[*] Resolved to {ip}\n')
    except socket.gaierror:
        print(f'[-] Could not resolve {target}')
        return []
    open_ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as ex:
        results = list(ex.map(lambda p: scan_port(ip, p), range(start_port, end_port + 1)))
    for port, is_open in results:
        if is_open:
            open_ports.append(port)
            print(f'[+] Port {port:<6} OPEN')
    print(f'\n[*] Done — {len(open_ports)} open port(s) found')
    return open_ports