import argparse
import datetime
import os
from colorama import init, Fore, Style

init(autoreset=True)

from port_scanner import run_port_scan
from dns_lookup import run_dns_lookup
from banner_grab import grab_http_headers
from whois_lookup import run_whois

BANNER = f"""
{Fore.GREEN}
  ██████  ███████  ██████  ██████  ███    ██
  ██   ██ ██      ██      ██    ██ ████   ██
  ██████  █████   ██      ██    ██ ██ ██  ██
  ██   ██ ██      ██      ██    ██ ██  ██ ██
  ██   ██ ███████  ██████  ██████  ██   ████
{Style.RESET_ALL}
{Fore.YELLOW}  Python Reconnaissance Tool  |  For authorised use only{Style.RESET_ALL}
"""

def print_header(target, mode):
    print(BANNER)
    print(Fore.CYAN + "=" * 55)
    print(f"  Target : {Fore.WHITE}{target}")
    print(f"  Mode   : {Fore.WHITE}{mode}")
    print(f"  Time   : {Fore.WHITE}{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(Fore.CYAN + "=" * 55 + Style.RESET_ALL)
    print()

def save_output(target, mode, log_lines):
    os.makedirs("reports", exist_ok=True)
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"reports/{target.replace('.', '_')}_{mode}_{timestamp}.txt"
    with open(filename, "w") as f:
        f.write(f"Recon Report\nTarget: {target}\nMode: {mode}\n")
        f.write(f"Date: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("=" * 55 + "\n\n")
        for line in log_lines:
            f.write(line + "\n")
    print(Fore.CYAN + f"\n[*] Report saved to {filename}" + Style.RESET_ALL)

def main():
    parser = argparse.ArgumentParser(
        description="recon.py - Python reconnaissance tool"
    )
    parser.add_argument("--mode", required=True,
                        choices=["portscan", "dns", "banner", "whois", "all"],
                        help="Module to run")
    parser.add_argument("--target", required=True,
                        help="Target hostname or IP address")
    parser.add_argument("--ports", default="1-1024",
                        help="Port range e.g. 1-1024")
    parser.add_argument("--output", action="store_true",
                        help="Save results to a report file in /reports")
    args = parser.parse_args()

    start, end = map(int, args.ports.split("-"))
    print_header(args.target, args.mode)

    log_lines = []

    if args.mode in ("portscan", "all"):
        results = run_port_scan(args.target, start, end, log_lines)

    if args.mode in ("dns", "all"):
        run_dns_lookup(args.target, log_lines)

    if args.mode in ("banner", "all"):
        grab_http_headers(args.target, log_lines)

    if args.mode in ("whois", "all"):
        run_whois(args.target, log_lines)

    if args.output:
        save_output(args.target, args.mode, log_lines)

if __name__ == "__main__":
    main()