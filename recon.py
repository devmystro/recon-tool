import argparse
from port_scanner import run_port_scan
from dns_lookup import run_dns_lookup
from banner_grab import grab_http_headers

def main():
    parser = argparse.ArgumentParser(description='recon.py — Python recon tool')
    parser.add_argument('--mode', required=True,
                        choices=['portscan', 'dns', 'banner', 'all'])
    parser.add_argument('--target', required=True)
    parser.add_argument('--ports', default='1-1024')
    args = parser.parse_args()
    start, end = map(int, args.ports.split('-'))

    print('=' * 50)
    print(f' recon.py | {args.target} | mode: {args.mode}')
    print(' WARNING: only scan targets you own or have permission to test')
    print('=' * 50)

    if args.mode in ('portscan', 'all'):
        run_port_scan(args.target, start, end)
    if args.mode in ('dns', 'all'):
        run_dns_lookup(args.target)
    if args.mode in ('banner', 'all'):
        grab_http_headers(args.target)

if __name__ == '__main__':
    main()