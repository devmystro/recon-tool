import dns.resolver

def run_dns_lookup(target):
    print(f'\n[*] DNS Lookup for: {target}\n')
    record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT']
    for rtype in record_types:
        try:
            answers = dns.resolver.resolve(target, rtype)
            for record in answers:
                print(f'[+] {rtype:<6} {record}')
        except dns.resolver.NoAnswer:
            pass
        except dns.resolver.NXDOMAIN:
            print(f'[-] Domain does not exist')
            break
        except Exception:
            pass
    print('\n[*] DNS lookup complete')