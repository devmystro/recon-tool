# recon.py

A Python reconnaissance tool covering port scanning, DNS enumeration,
and HTTP security header analysis. Built to understand what tools like
Nmap and dig do at the socket and protocol level.

## Usage

python recon.py --mode [portscan|dns|banner|all] --target TARGET --ports 1-1024

## Modules

| Module   | What it does                              |
|----------|-------------------------------------------|
| portscan | Threaded TCP connect scan                 |
| dns      | A, MX, NS, TXT record enumeration         |
| banner   | HTTP header and security audit            |
| all      | Runs every module in sequence             |

## Requirements

pip install dnspython requests

## Legal

Only scan targets you own or have explicit written permission to test.
Unauthorised scanning is illegal under the Computer Misuse Act 1990 (UK).
