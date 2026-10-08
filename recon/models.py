"""
recon/models.py
Structured data models for all scan results.
All modules return these objects rather than printing directly.
"""

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class PortResult:
    port: int
    protocol: str
    state: str          # open / closed / filtered
    service: str        # http, ssh, ftp etc.
    banner: Optional[str] = None

    def to_dict(self):
        return {
            "port": self.port,
            "protocol": self.protocol,
            "state": self.state,
            "service": self.service,
            "banner": self.banner,
        }


@dataclass
class DNSResult:
    record_type: str    # A, AAAA, MX, NS, TXT, SOA, CNAME
    value: str

    def to_dict(self):
        return {"type": self.record_type, "value": self.value}


@dataclass
class SubdomainResult:
    subdomain: str
    ip: Optional[str] = None
    status: Optional[int] = None    # HTTP status if probed
    alive: bool = False

    def to_dict(self):
        return {
            "subdomain": self.subdomain,
            "ip": self.ip,
            "status": self.status,
            "alive": self.alive,
        }


@dataclass
class HeaderFinding:
    header: str
    severity: str       # PASS / INFO / WARN / HIGH
    detail: str

    def to_dict(self):
        return {
            "header": self.header,
            "severity": self.severity,
            "detail": self.detail,
        }


@dataclass
class HTTPResult:
    url: str
    status: int
    server: Optional[str] = None
    title: Optional[str] = None
    redirect: Optional[str] = None
    technologies: list = field(default_factory=list)
    header_findings: list = field(default_factory=list)     # list[HeaderFinding]
    interesting: list = field(default_factory=list)         # robots.txt, etc.

    def to_dict(self):
        return {
            "url": self.url,
            "status": self.status,
            "server": self.server,
            "title": self.title,
            "redirect": self.redirect,
            "technologies": self.technologies,
            "header_findings": [h.to_dict() for h in self.header_findings],
            "interesting": self.interesting,
        }


@dataclass
class WhoisResult:
    domain: str
    registrar: Optional[str] = None
    organisation: Optional[str] = None
    country: Optional[str] = None
    created: Optional[str] = None
    expires: Optional[str] = None
    nameservers: list = field(default_factory=list)
    raw_fields: list = field(default_factory=list)

    def to_dict(self):
        return {
            "domain": self.domain,
            "registrar": self.registrar,
            "organisation": self.organisation,
            "country": self.country,
            "created": self.created,
            "expires": self.expires,
            "nameservers": self.nameservers,
        }


@dataclass
class ScanReport:
    target: str
    timestamp: str
    ports: list = field(default_factory=list)           # list[PortResult]
    dns_records: list = field(default_factory=list)     # list[DNSResult]
    subdomains: list = field(default_factory=list)      # list[SubdomainResult]
    http: list = field(default_factory=list)            # list[HTTPResult]
    whois: Optional[WhoisResult] = None

    def to_dict(self):
        return {
            "target": self.target,
            "timestamp": self.timestamp,
            "ports": [p.to_dict() for p in self.ports],
            "dns_records": [d.to_dict() for d in self.dns_records],
            "subdomains": [s.to_dict() for s in self.subdomains],
            "http": [h.to_dict() for h in self.http],
            "whois": self.whois.to_dict() if self.whois else None,
        }
