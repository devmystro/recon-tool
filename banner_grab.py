import requests

SECURITY_HEADERS = [
    'Content-Security-Policy',
    'X-Frame-Options',
    'Strict-Transport-Security',
    'X-Content-Type-Options',
]

def grab_http_headers(target):
    print(f'\n[*] HTTP Header Analysis — {target}\n')
    try:
        resp = requests.get(f'http://{target}', timeout=5)
        print(f'[+] Status: {resp.status_code}\n')
        info_headers = ['Server', 'X-Powered-By', 'Via']
        for h in info_headers:
            if h in resp.headers:
                print(f'[!] {h}: {resp.headers[h]}  <- version exposed')
        print('')
        for h in SECURITY_HEADERS:
            if h in resp.headers:
                print(f'[+] PRESENT  {h}')
            else:
                print(f'[-] MISSING  {h}  <- report as finding')
    except Exception as e:
        print(f'[-] Error: {e}')