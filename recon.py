"""
recon.py
Entry point for recon-tool v2.
A modular Python reconnaissance and attack-surface mapping framework.

Usage:
    python recon.py --target example.com --mode all --output
    python recon.py --target 192.168.56.20 --mode portscan --ports 1-65535
    python recon.py --target example.com --mode subdomains
"""

import argparse
import datetime
import sys

from colorama import init, Fore, Style

init(autoreset=True)

from recon.models import ScanReport
from recon.scanner import run_port_scan
from recon.dns import run_dns_lookup
from recon.http import run_http_recon
from recon.whois import run_whois
from recon.subdomains import run_subdomain_enum
from recon.reporting import save_reports
from recon.utils import parse_port_range, fail, info


BANNER = f"""
{Fore.GREEN}
  ██████  ███████  ██████  ██████  ███    ██
  ██   ██ ██      ██      ██    ██ ████   ██
  ██████  █████   ██      ██    ██ ██ ██  ██
  ██   ██ ██      ██      ██    ██ ██  ██ ██
  ██   ██ ███████  ██████  ██████  ██   ████
{Style.RESET_ALL}
  {Fore.YELLOW}Reconnaissance Framework v2  |  github.com/devmystro/recon-tool{Style.RESET_ALL}
  {Fore.RED}For authorised security testing only{Style.RESET_ALL}
"""

MODES = ["portscan", "dns", "http", "whois", "subdomains", "all"]


def print_header(target: str, mode: str, ports: str):
    print(BANNER)
    print(Fore.CYAN + "  " + "=" * 53)
    print(f"  {'Target':<10} {Fore.WHITE}{target}")
    print(f"  {Fore.CYAN}{'Mode':<10} {Fore.WHITE}{mode}")
    print(f"  {Fore.CYAN}{'Ports':<10} {Fore.WHITE}{ports}")
    print(f"  {Fore.CYAN}{'Time':<10} {Fore.WHITE}{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(Fore.CYAN + "  " + "=" * 53 + Style.RESET_ALL)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="recon.py",
        description="recon-tool v2 — Python reconnaissance framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Modes:
  portscan    TCP port scan with service detection and banner grabbing
  dns         DNS record enumeration (A, AAAA, CNAME, MX, NS, TXT, SOA)
  http        HTTP/HTTPS probing with header analysis and tech detection
  whois       WHOIS information gathering
  subdomains  Wordlist-based subdomain enumeration with HTTP probing
  all         Run every module in sequence

Examples:
  python recon.py --target scanme.nmap.org --mode all --output
  python recon.py --target example.com --mode portscan --ports 1-65535
  python recon.py --target example.com --mode subdomains
        """,
    )
    parser.add_argument("--target", required=True,
                        help="Target hostname or IP address")
    parser.add_argument("--mode", required=True, choices=MODES,
                        help="Module to run")
    parser.add_argument("--ports", default="1-1024",
                        help="Port range for portscan (default: 1-1024)")
    parser.add_argument("--timeout", type=float, default=0.5,
                        help="Socket timeout in seconds (default: 0.5)")
    parser.add_argument("--workers", type=int, default=100,
                        help="Thread pool size (default: 100)")
    parser.add_argument("--no-banners", action="store_true",
                        help="Skip banner grabbing during port scan")
    parser.add_argument("--output", action="store_true",
                        help="Save JSON and HTML reports to reports/")
    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()

    # Validate port range early
    try:
        start_port, end_port = parse_port_range(args.ports)
    except ValueError as e:
        fail(str(e))
        sys.exit(1)

    print_header(args.target, args.mode, args.ports)

    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    report = ScanReport(target=args.target, timestamp=timestamp)

    run_all = args.mode == "all"

    if args.mode == "portscan" or run_all:
        report.ports = run_port_scan(
            target=args.target,
            start_port=start_port,
            end_port=end_port,
            timeout=args.timeout,
            workers=args.workers,
            grab_banners=not args.no_banners,
        )

    if args.mode == "dns" or run_all:
        report.dns_records = run_dns_lookup(args.target)

    if args.mode == "subdomains" or run_all:
        report.subdomains = run_subdomain_enum(args.target)

    if args.mode == "http" or run_all:
        report.http = run_http_recon(args.target)

    if args.mode == "whois" or run_all:
        report.whois = run_whois(args.target)

    # Save reports
    if args.output:
        print()
        info("Saving reports...")
        save_reports(report)

    print()
    print(Fore.CYAN + "  " + "=" * 53)
    print(f"  {Fore.GREEN}Scan complete.  Target: {args.target}")
    print(Fore.CYAN + "  " + "=" * 53 + Style.RESET_ALL)
    print()


if __name__ == "__main__":
    main()
