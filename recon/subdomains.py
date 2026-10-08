"""
recon/subdomains.py
Wordlist-based subdomain enumeration.
Resolves candidates via DNS, then HTTP-probes live hosts.
Returns structured SubdomainResult objects.
"""

import concurrent.futures
import socket

import requests

from .models import SubdomainResult
from .utils import print_section, ok, fail, warn, info


# Built-in wordlist — covers the most common subdomains
# Replace or extend this with a larger wordlist file for real assessments
DEFAULT_WORDLIST = [
    "www", "mail", "remote", "blog", "webmail", "server", "ns1", "ns2",
    "smtp", "secure", "vpn", "api", "dev", "staging", "app", "admin",
    "portal", "test", "ftp", "mx", "email", "cloud", "support", "help",
    "shop", "forum", "store", "mobile", "m", "static", "cdn", "media",
    "images", "img", "video", "download", "beta", "sandbox", "internal",
    "intranet", "extranet", "monitor", "status", "login", "auth", "docs",
    "git", "gitlab", "jenkins", "jira", "confluence", "ci", "build",
    "prod", "production", "uat", "qa", "preview", "demo", "old", "new",
    "v1", "v2", "api-v1", "api-v2", "dashboard", "panel", "cpanel",
    "mysql", "db", "database", "redis", "grafana", "kibana", "elastic",
]


def _resolve_subdomain(domain: str, word: str) -> SubdomainResult | None:
    """
    Try to resolve word.domain via DNS.
    Returns a SubdomainResult if the host resolves, None otherwise.
    """
    fqdn = f"{word}.{domain}"
    try:
        ip = socket.gethostbyname(fqdn)
        return SubdomainResult(subdomain=fqdn, ip=ip, alive=True)
    except socket.gaierror:
        return None


def _probe_http(result: SubdomainResult, timeout: int = 4) -> SubdomainResult:
    """
    Probe a live subdomain over HTTP/HTTPS.
    Fills in the HTTP status code.
    """
    for scheme in ("https", "http"):
        try:
            resp = requests.get(
                f"{scheme}://{result.subdomain}",
                timeout=timeout,
                allow_redirects=True,
                verify=False,
            )
            result.status = resp.status_code
            return result
        except Exception:
            continue
    result.status = None
    return result


def run_subdomain_enum(
    target: str,
    wordlist: list[str] | None = None,
    workers: int = 50,
    probe_http: bool = True,
) -> list[SubdomainResult]:
    """
    Enumerate subdomains of target using a wordlist.
    Resolves each candidate via DNS, then optionally HTTP-probes live hosts.
    Returns a list of SubdomainResult objects for live hosts only.
    """
    words = wordlist or DEFAULT_WORDLIST

    print_section(f"Subdomain Enumeration  |  {target}  |  {len(words)} candidates")
    info(f"Resolving with {workers} threads...")
    print()

    live = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {
            ex.submit(_resolve_subdomain, target, word): word
            for word in words
        }
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                live.append(result)

    if not live:
        warn("No live subdomains found")
        return []

    # HTTP probe live hosts
    if probe_http:
        info(f"HTTP probing {len(live)} live hosts...")
        # suppress SSL warnings for self-signed certs
        try:
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        except Exception:
            pass

        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as ex:
            live = list(ex.map(_probe_http, live))

    # Sort and print
    live.sort(key=lambda r: r.subdomain)
    for r in live:
        status_str = str(r.status) if r.status else "???"
        ip_str = r.ip or "unresolved"
        ok(f"{r.subdomain:<40} {ip_str:<18} HTTP {status_str}")

    print()
    info(f"{len(live)} live subdomain(s) found")
    return live
