import dns.resolver
from colorama import Fore, Style

def run_dns_lookup(target, log_lines=None):
    if log_lines is None:
        log_lines = []

    print(Fore.CYAN + f"\n[*] DNS Lookup" + Style.RESET_ALL)
    print(f"    Target: {target}\n")

    record_types = ["A", "AAAA", "MX", "NS", "TXT"]

    for rtype in record_types:
        try:
            answers = dns.resolver.resolve(target, rtype)
            for record in answers:
                msg = f"[+] {rtype:<6}  {record}"
                print(Fore.GREEN + msg)
                log_lines.append(msg)
        except dns.resolver.NoAnswer:
            pass
        except dns.resolver.NXDOMAIN:
            msg = f"[-] Domain {target} does not exist"
            print(Fore.RED + msg)
            log_lines.append(msg)
            break
        except Exception:
            pass

    print(Fore.CYAN + "\n[*] DNS lookup complete" + Style.RESET_ALL)
    log_lines.append("DNS lookup complete")