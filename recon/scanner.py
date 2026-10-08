"""
recon/scanner.py
Threaded TCP port scanner.
Returns structured PortResult objects rather than printing directly.
"""

import socket
import concurrent.futures
from typing import Optional

from .models import PortResult
from .utils import COMMON_PORTS, resolve, print_section, ok, fail, info


def grab_banner(ip: str, port: int, timeout: float) -> Optional[str]:
    """
    Attempt to grab a service banner by connecting and reading
    the first response. Sends a minimal HTTP HEAD for port 80/8080/8443.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, port))
            if port in (80, 8080, 8443, 443):
                s.send(b"HEAD / HTTP/1.0\r\n\r\n")
            data = s.recv(1024).decode("utf-8", errors="ignore").strip()
            # return just the first meaningful line
            for line in data.splitlines():
                line = line.strip()
                if line:
                    return line[:120]
    except Exception:
        pass
    return None


def _scan_single(ip: str, port: int, timeout: float, grab_banners: bool):
    """Scan one port. Returns a PortResult."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((ip, port))
            is_open = result == 0
    except Exception:
        is_open = False

    service = COMMON_PORTS.get(port, "unknown")
    banner = None

    if is_open and grab_banners:
        banner = grab_banner(ip, port, timeout)

    return PortResult(
        port=port,
        protocol="tcp",
        state="open" if is_open else "closed",
        service=service,
        banner=banner,
    )


def run_port_scan(
    target: str,
    start_port: int = 1,
    end_port: int = 1024,
    timeout: float = 0.5,
    workers: int = 100,
    grab_banners: bool = True,
) -> list[PortResult]:
    """
    Scan a range of TCP ports on target.
    Returns a list of PortResult objects for open ports only.
    """
    print_section(f"Port Scanner  |  {target}  |  ports {start_port}-{end_port}")

    ip = resolve(target)
    if not ip:
        fail(f"Could not resolve {target}")
        return []

    info(f"Resolved {target} -> {ip}")
    info(f"Scanning {end_port - start_port + 1} ports with {workers} threads\n")

    ports = range(start_port, end_port + 1)
    open_results = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {
            ex.submit(_scan_single, ip, port, timeout, grab_banners): port
            for port in ports
        }
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result.state == "open":
                open_results.append(result)

    # sort by port number for clean output
    open_results.sort(key=lambda r: r.port)

    # print results table
    print(f"  {'PORT':<10} {'STATE':<10} {'SERVICE':<14} BANNER")
    print(f"  {'-'*10} {'-'*10} {'-'*14} {'-'*30}")
    for r in open_results:
        banner_str = r.banner[:40] if r.banner else ""
        ok(f"{str(r.port) + '/tcp':<10} {r.state:<10} {r.service:<14} {banner_str}")

    print()
    info(f"{len(open_results)} open port(s) found")

    return open_results
