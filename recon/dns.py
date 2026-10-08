"""
recon/dns.py
DNS enumeration module.
Queries multiple record types and returns structured DNSResult objects.
"""

import dns.resolver
import dns.zone
import dns.query
import dns.exception

from .models import DNSResult
from .utils import print_section, ok, fail, warn, info


RECORD_TYPES = ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA"]


def run_dns_lookup(target: str) -> list[DNSResult]:
    """
    Enumerate DNS records for target.
    Returns a list of DNSResult objects.
    Also attempts a zone transfer (AXFR) and reports the result.
    """
    print_section(f"DNS Enumeration  |  {target}")

    results = []

    for rtype in RECORD_TYPES:
        try:
            answers = dns.resolver.resolve(target, rtype, lifetime=5)
            for record in answers:
                value = str(record).strip()
                results.append(DNSResult(record_type=rtype, value=value))
                ok(f"{rtype:<6}  {value}")

        except dns.resolver.NoAnswer:
            pass
        except dns.resolver.NXDOMAIN:
            fail(f"Domain {target} does not exist (NXDOMAIN)")
            return results
        except dns.resolver.Timeout:
            warn(f"{rtype:<6}  Timed out")
        except dns.exception.DNSException as e:
            warn(f"{rtype:<6}  {type(e).__name__}")

    # Zone transfer attempt
    print()
    info("Attempting zone transfer (AXFR)...")
    try:
        ns_answers = dns.resolver.resolve(target, "NS", lifetime=5)
        for ns in ns_answers:
            ns_str = str(ns).rstrip(".")
            try:
                zone = dns.zone.from_xfr(dns.query.xfr(ns_str, target, timeout=5))
                warn(f"ZONE TRANSFER SUCCEEDED via {ns_str} — server is misconfigured!")
                for name in zone.nodes:
                    warn(f"  {name}.{target}")
            except Exception:
                ok(f"Zone transfer refused by {ns_str} (expected)")
    except Exception:
        info("Could not enumerate NS records for AXFR check")

    print()
    info(f"{len(results)} DNS record(s) found")
    return results
