"""
recon/http.py
HTTP/HTTPS reconnaissance module.
Detects status, server, title, redirect chain, technologies,
security headers (with severity ratings), and interesting paths.
Returns structured HTTPResult objects.
"""

import re
import requests

from .models import HTTPResult, HeaderFinding
from .utils import print_section, ok, fail, warn, info


# Suppress SSL warnings for self-signed certs
try:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except Exception:
    pass


# Security headers: key -> (severity_if_missing, description)
SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "HIGH",
        "Missing CSP increases risk of XSS and data injection attacks",
    ),
    "Strict-Transport-Security": (
        "HIGH",
        "Missing HSTS allows protocol downgrade and MITM attacks over HTTP",
    ),
    "X-Frame-Options": (
        "WARN",
        "Missing X-Frame-Options may allow clickjacking attacks",
    ),
    "X-Content-Type-Options": (
        "WARN",
        "Missing X-Content-Type-Options allows MIME-type sniffing",
    ),
    "Referrer-Policy": (
        "INFO",
        "No Referrer-Policy means referrer headers are sent by default",
    ),
    "Permissions-Policy": (
        "INFO",
        "No Permissions-Policy means browser features are unrestricted",
    ),
}

# Headers that expose version/technology info
INFO_HEADERS = [
    "Server", "X-Powered-By", "Via", "X-Generator",
    "X-AspNet-Version", "X-AspNetMvc-Version",
]

# Technology fingerprints: header value substring -> tech name
TECH_FINGERPRINTS = {
    "nginx":     "nginx",
    "apache":    "Apache",
    "iis":       "IIS",
    "php":       "PHP",
    "wordpress": "WordPress",
    "drupal":    "Drupal",
    "joomla":    "Joomla",
    "node":      "Node.js",
    "express":   "Express",
    "django":    "Django",
    "flask":     "Flask",
    "laravel":   "Laravel",
    "cloudflare":"Cloudflare",
}

# Paths worth checking for information disclosure
INTERESTING_PATHS = [
    "/robots.txt",
    "/sitemap.xml",
    "/.well-known/security.txt",
    "/security.txt",
    "/.git/HEAD",
    "/crossdomain.xml",
    "/clientaccesspolicy.xml",
    "/humans.txt",
]


def _detect_technologies(headers: dict, body: str) -> list[str]:
    """Fingerprint technologies from headers and page body."""
    techs = set()
    combined = " ".join(str(v).lower() for v in headers.values()) + body.lower()
    for keyword, tech in TECH_FINGERPRINTS.items():
        if keyword in combined:
            techs.add(tech)
    return sorted(techs)


def _extract_title(html: str) -> str | None:
    """Extract <title> from HTML."""
    match = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
    if match:
        return match.group(1).strip()[:100]
    return None


def _check_interesting_paths(base_url: str, timeout: int) -> list[str]:
    """Check for exposed interesting paths. Returns list of found paths."""
    found = []
    for path in INTERESTING_PATHS:
        try:
            resp = requests.get(
                base_url + path, timeout=timeout,
                allow_redirects=False, verify=False
            )
            if resp.status_code in (200, 301, 302):
                found.append(f"{path} [{resp.status_code}]")
        except Exception:
            pass
    return found


def probe_url(url: str, timeout: int = 6) -> HTTPResult | None:
    """
    Probe a single URL. Returns an HTTPResult or None on failure.
    """
    try:
        resp = requests.get(
            url, timeout=timeout,
            allow_redirects=True, verify=False,
        )
    except Exception:
        return None

    headers = dict(resp.headers)
    body = resp.text[:50000]

    # Redirect chain
    redirect = None
    if resp.history:
        redirect = resp.url

    # Page title
    title = _extract_title(body)

    # Server header
    server = headers.get("Server") or headers.get("server")

    # Technology detection
    techs = _detect_technologies(headers, body)

    # Security header analysis
    header_findings = []
    for h, (severity, detail) in SECURITY_HEADERS.items():
        if h in headers:
            header_findings.append(HeaderFinding(header=h, severity="PASS", detail="Present"))
        else:
            header_findings.append(HeaderFinding(header=h, severity=severity, detail=detail))

    # Interesting paths
    base_url = url.rstrip("/")
    interesting = _check_interesting_paths(base_url, timeout=3)

    return HTTPResult(
        url=url,
        status=resp.status_code,
        server=server,
        title=title,
        redirect=redirect,
        technologies=techs,
        header_findings=header_findings,
        interesting=interesting,
    )


def run_http_recon(target: str, timeout: int = 6) -> list[HTTPResult]:
    """
    Probe HTTP and HTTPS for a target.
    Returns a list of HTTPResult objects (one per scheme that responds).
    """
    print_section(f"HTTP Reconnaissance  |  {target}")

    results = []

    for scheme in ("https", "http"):
        url = f"{scheme}://{target}"
        info(f"Probing {url} ...")
        result = probe_url(url, timeout=timeout)

        if not result:
            fail(f"No response from {url}")
            continue

        results.append(result)

        # Print summary
        ok(f"Status  : {result.status}")
        if result.title:
            ok(f"Title   : {result.title}")
        if result.server:
            warn(f"Server  : {result.server}  <- version exposed")
        if result.redirect:
            info(f"Redirect: {result.redirect}")
        if result.technologies:
            ok(f"Tech    : {', '.join(result.technologies)}")

        # Security headers
        print()
        print("         Security Headers:")
        for finding in result.header_findings:
            if finding.severity == "PASS":
                ok(f"PASS  {finding.header}")
            elif finding.severity == "HIGH":
                fail(f"HIGH  {finding.header}  <- {finding.detail}")
            elif finding.severity == "WARN":
                warn(f"WARN  {finding.header}  <- {finding.detail}")
            else:
                info(f"INFO  {finding.header}  <- {finding.detail}")

        # Interesting paths
        if result.interesting:
            print()
            print("         Interesting paths found:")
            for path in result.interesting:
                warn(f"  {path}")

        print()

    return results
