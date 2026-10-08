"""
recon/whois.py
WHOIS lookup module.
Queries whois.iana.org for referral, then follows to the correct
registrar WHOIS server. Returns a structured WhoisResult.
"""

import socket
import re

from .models import WhoisResult
from .utils import print_section, ok, fail, warn, info


IANA_WHOIS = "whois.iana.org"


def _raw_whois(server: str, query: str, timeout: int = 5) -> str:
    """Send a WHOIS query to server and return the raw response."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((server, 43))
            s.send((query.strip() + "\r\n").encode("utf-8"))
            response = b""
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                response += chunk
        return response.decode("utf-8", errors="ignore")
    except Exception as e:
        raise ConnectionError(f"WHOIS query to {server} failed: {e}") from e


def _extract_field(raw: str, keys: list[str]) -> str | None:
    """Extract the first matching field value from raw WHOIS text."""
    for line in raw.splitlines():
        for key in keys:
            if line.lower().startswith(key.lower() + ":"):
                value = line.split(":", 1)[-1].strip()
                if value and value.lower() not in ("", "redacted for privacy"):
                    return value
    return None


def run_whois(target: str) -> WhoisResult:
    """
    Perform a WHOIS lookup on target domain.
    Returns a WhoisResult object.
    """
    domain = target.replace("https://", "").replace("http://", "").split("/")[0]
    print_section(f"WHOIS Lookup  |  {domain}")

    result = WhoisResult(domain=domain)

    try:
        # Step 1: query IANA for the correct registrar WHOIS server
        info(f"Querying {IANA_WHOIS}...")
        iana_raw = _raw_whois(IANA_WHOIS, domain)

        # Find referral server
        refer_match = re.search(r"refer:\s+(.+)", iana_raw, re.IGNORECASE)
        whois_server = refer_match.group(1).strip() if refer_match else IANA_WHOIS

        # Step 2: query the actual registrar WHOIS server
        if whois_server != IANA_WHOIS:
            info(f"Following referral to {whois_server}...")
            raw = _raw_whois(whois_server, domain)
        else:
            raw = iana_raw

        # Extract structured fields
        result.registrar = _extract_field(raw, [
            "Registrar", "registrar", "Registrar Name"
        ])
        result.organisation = _extract_field(raw, [
            "Registrant Organization", "org", "Organisation", "Organization"
        ])
        result.country = _extract_field(raw, [
            "Registrant Country", "country", "Country"
        ])
        result.created = _extract_field(raw, [
            "Creation Date", "created", "Registered"
        ])
        result.expires = _extract_field(raw, [
            "Registry Expiry Date", "expires", "Expiry Date", "Expiration Date"
        ])

        # Nameservers
        nameservers = re.findall(r"(?:Name Server|nserver):\s+(.+)", raw, re.IGNORECASE)
        result.nameservers = [ns.strip().lower() for ns in nameservers][:8]

        # Print results
        fields = {
            "Registrar":    result.registrar,
            "Organisation": result.organisation,
            "Country":      result.country,
            "Created":      result.created,
            "Expires":      result.expires,
        }
        for label, value in fields.items():
            if value:
                ok(f"{label:<14} {value}")
            else:
                info(f"{label:<14} Not disclosed")

        if result.nameservers:
            ok(f"Nameservers    {', '.join(result.nameservers)}")

    except ConnectionError as e:
        fail(str(e))
    except Exception as e:
        warn(f"WHOIS lookup incomplete: {e}")

    return result
