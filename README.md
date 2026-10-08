# recon-tool v2

A modular Python reconnaissance and attack-surface mapping framework built for security assessments and penetration testing.

Developed to understand and implement the underlying mechanics of reconnaissance tooling at the socket, protocol and HTTP level — rather than simply wrapping existing tools.

---

## Features

| Module | What it does |
|---|---|
| `portscan` | Concurrent threaded TCP scanner with service identification and banner grabbing |
| `dns` | Full DNS enumeration (A, AAAA, CNAME, MX, NS, TXT, SOA) with zone transfer attempt |
| `http` | HTTP/HTTPS probing with tech detection, redirect chain, security header analysis (severity-rated) and interesting path discovery |
| `subdomains` | Wordlist-based subdomain enumeration with DNS resolution and HTTP probing |
| `whois` | WHOIS lookup via IANA referral chain |
| `all` | Runs every module in sequence and produces a full attack-surface report |

Outputs to terminal (coloured), JSON, and HTML report.

---

## Architecture

```
Target
  |
  +-- Port Scanner   -> open ports, service names, banners
  |
  +-- DNS            -> A/AAAA/MX/NS/TXT/SOA records, zone transfer check
  |
  +-- Subdomains     -> wordlist resolution + HTTP probing
  |
  +-- HTTP           -> status, title, server, techs, security headers, paths
  |
  +-- WHOIS          -> registrar, org, country, nameservers
  |
  +-- Report Builder
        |
        +-- Terminal (coloured)
        +-- report.json
        +-- report.html
```

---

## Installation

```bash
git clone https://github.com/devmystro/recon-tool.git
cd recon-tool
pip install -r requirements.txt
```

---

## Usage

```bash
# Full reconnaissance with output saved
python recon.py --target scanme.nmap.org --mode all --output

# Port scan only, custom range
python recon.py --target 192.168.56.20 --mode portscan --ports 1-65535

# DNS enumeration
python recon.py --target example.com --mode dns

# Subdomain enumeration
python recon.py --target example.com --mode subdomains

# HTTP analysis
python recon.py --target example.com --mode http

# WHOIS lookup
python recon.py --target example.com --mode whois
```

### All flags

```
--target      Target hostname or IP address (required)
--mode        Module to run: portscan | dns | http | whois | subdomains | all
--ports       Port range for portscan, default: 1-1024
--timeout     Socket timeout in seconds, default: 0.5
--workers     Thread pool size, default: 100
--no-banners  Skip banner grabbing
--output      Save JSON and HTML reports to reports/
```

---

## Output

Reports are saved to `reports/<target>/<timestamp>/`:

```
reports/
  scanme_nmap_org/
    20241015_143022/
      report.json
      report.html
```

The HTML report includes a summary dashboard, open port table, DNS records, subdomains, HTTP findings with severity-rated security header analysis, and WHOIS data.

---

## Security header severity ratings

Rather than treating every missing header as a finding, headers are rated by impact:

| Severity | Meaning |
|---|---|
| HIGH | Missing header directly increases attack surface |
| WARN | Missing header removes a browser-side mitigation |
| INFO | Missing header is a best-practice gap, low direct impact |
| PASS | Header is present and correctly configured |

---

## Technical implementation

**Port scanner** uses `socket.connect_ex()` at the TCP level with a configurable `ThreadPoolExecutor` (default 100 workers). Results are structured `PortResult` objects rather than raw print statements, allowing them to be consumed by the reporting layer independently of the terminal.

**DNS module** uses `dnspython` to query seven record types and attempts a zone transfer (AXFR) against each discovered nameserver. Zone transfer success is flagged as a misconfiguration finding.

**Subdomain enumerator** resolves candidates from a built-in wordlist via `socket.gethostbyname()`, then HTTP-probes live hosts to capture status codes.

**HTTP module** sends GET requests with redirect following, extracts page title via regex, fingerprints technologies from headers and body content, and checks seven security headers with per-header severity ratings. Also checks a set of interesting paths (robots.txt, .git/HEAD, security.txt etc.).

**WHOIS module** queries `whois.iana.org` for the registrar referral, then follows to the correct WHOIS server for structured field extraction.

**Reporting** serialises all results via dataclass `.to_dict()` methods to JSON, and generates a self-contained dark-theme HTML report with a summary dashboard.

---

## Legal

Only scan targets you own or have explicit written permission to test.

Unauthorised scanning is illegal under the Computer Misuse Act 1990 (UK) and equivalent legislation in other jurisdictions.

This tool is built for educational purposes and authorised security assessments only.
