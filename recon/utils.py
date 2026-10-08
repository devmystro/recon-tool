"""
recon/utils.py
Shared helpers used across all modules.
"""

import socket
from colorama import Fore, Style


COMMON_PORTS = {
    21:   "ftp",
    22:   "ssh",
    23:   "telnet",
    25:   "smtp",
    53:   "dns",
    80:   "http",
    110:  "pop3",
    135:  "msrpc",
    139:  "netbios",
    143:  "imap",
    443:  "https",
    445:  "smb",
    993:  "imaps",
    995:  "pop3s",
    1433: "mssql",
    3306: "mysql",
    3389: "rdp",
    5432: "postgresql",
    5900: "vnc",
    6379: "redis",
    8080: "http-alt",
    8443: "https-alt",
    8888: "http-alt",
    9200: "elasticsearch",
    27017: "mongodb",
}


def resolve(target: str) -> str | None:
    """Resolve a hostname to an IP. Returns None on failure."""
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        return None


def parse_port_range(port_range: str) -> tuple[int, int]:
    """
    Parse a port range string like '1-1024'.
    Validates bounds and raises ValueError with a clear message.
    """
    try:
        parts = port_range.strip().split("-")
        if len(parts) != 2:
            raise ValueError
        start, end = int(parts[0]), int(parts[1])
        if not (1 <= start <= 65535 and 1 <= end <= 65535):
            raise ValueError("Ports must be between 1 and 65535")
        if start > end:
            raise ValueError("Start port must be less than or equal to end port")
        return start, end
    except (ValueError, AttributeError) as e:
        raise ValueError(
            f"Invalid port range '{port_range}'. Use format: 1-1024"
        ) from e


def print_section(title: str):
    print()
    print(Fore.CYAN + f"  {title}")
    print(Fore.CYAN + "  " + "-" * (len(title) + 2) + Style.RESET_ALL)


def ok(msg: str):
    print(Fore.GREEN + f"  [+] {msg}" + Style.RESET_ALL)


def warn(msg: str):
    print(Fore.YELLOW + f"  [!] {msg}" + Style.RESET_ALL)


def info(msg: str):
    print(Fore.CYAN + f"  [*] {msg}" + Style.RESET_ALL)


def fail(msg: str):
    print(Fore.RED + f"  [-] {msg}" + Style.RESET_ALL)
