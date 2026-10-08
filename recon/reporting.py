"""
recon/reporting.py
Generates JSON and HTML reports from a ScanReport object.
Saves to reports/<target>/<timestamp>/
"""

import json
import os
import datetime

from .models import ScanReport
from .utils import info, ok


def _severity_colour(sev: str) -> str:
    return {
        "PASS": "#3fb950",
        "HIGH": "#f85149",
        "WARN": "#d29922",
        "INFO": "#79c0ff",
    }.get(sev, "#8b949e")


def _severity_badge(sev: str) -> str:
    colour = _severity_colour(sev)
    return (
        f'<span style="background:{colour};color:#0d1117;'
        f'font-size:11px;font-weight:600;padding:2px 8px;'
        f'border-radius:10px;">{sev}</span>'
    )


def generate_html(report: ScanReport) -> str:
    """Build a self-contained HTML report string."""

    ts = report.timestamp

    # Port rows
    port_rows = ""
    for p in report.ports:
        banner = p.banner or ""
        port_rows += (
            f"<tr><td>{p.port}/tcp</td><td>"
            f"<span class='open'>open</span></td>"
            f"<td>{p.service}</td><td class='muted'>{banner}</td></tr>"
        )
    if not port_rows:
        port_rows = "<tr><td colspan='4' class='muted'>No open ports found</td></tr>"

    # DNS rows
    dns_rows = ""
    for d in report.dns_records:
        dns_rows += f"<tr><td>{d.record_type}</td><td>{d.value}</td></tr>"
    if not dns_rows:
        dns_rows = "<tr><td colspan='2' class='muted'>No records found</td></tr>"

    # Subdomain rows
    sub_rows = ""
    for s in report.subdomains:
        status = str(s.status) if s.status else "???"
        ip = s.ip or ""
        sub_rows += (
            f"<tr><td>{s.subdomain}</td>"
            f"<td>{ip}</td>"
            f"<td>{status}</td></tr>"
        )
    if not sub_rows:
        sub_rows = "<tr><td colspan='3' class='muted'>No subdomains found</td></tr>"

    # HTTP sections
    http_html = ""
    for h in report.http:
        header_rows = ""
        for hf in h.header_findings:
            badge = _severity_badge(hf.severity)
            detail = hf.detail if hf.severity != "PASS" else ""
            header_rows += (
                f"<tr><td>{hf.header}</td>"
                f"<td>{badge}</td>"
                f"<td class='muted'>{detail}</td></tr>"
            )

        interesting_html = ""
        if h.interesting:
            items = "".join(f"<li>{p}</li>" for p in h.interesting)
            interesting_html = f"<p class='label'>Interesting Paths</p><ul>{items}</ul>"

        techs = ", ".join(h.technologies) if h.technologies else "None detected"
        redirect = h.redirect or "None"
        server = h.server or "Not disclosed"

        http_html += f"""
        <div class="card">
          <div class="card-title">{h.url}</div>
          <div class="meta-grid">
            <div><span class="label">Status</span><span class="val">{h.status}</span></div>
            <div><span class="label">Server</span><span class="val">{server}</span></div>
            <div><span class="label">Title</span><span class="val">{h.title or 'N/A'}</span></div>
            <div><span class="label">Technologies</span><span class="val">{techs}</span></div>
            <div><span class="label">Redirect</span><span class="val">{redirect}</span></div>
          </div>
          <p class="label" style="margin-top:1rem">Security Headers</p>
          <table>
            <thead><tr><th>Header</th><th>Status</th><th>Detail</th></tr></thead>
            <tbody>{header_rows}</tbody>
          </table>
          {interesting_html}
        </div>
        """

    # WHOIS section
    whois_html = ""
    if report.whois:
        w = report.whois
        whois_html = f"""
        <div class="card">
          <div class="card-title">WHOIS — {w.domain}</div>
          <div class="meta-grid">
            <div><span class="label">Registrar</span><span class="val">{w.registrar or 'N/A'}</span></div>
            <div><span class="label">Organisation</span><span class="val">{w.organisation or 'N/A'}</span></div>
            <div><span class="label">Country</span><span class="val">{w.country or 'N/A'}</span></div>
            <div><span class="label">Created</span><span class="val">{w.created or 'N/A'}</span></div>
            <div><span class="label">Expires</span><span class="val">{w.expires or 'N/A'}</span></div>
            <div><span class="label">Nameservers</span><span class="val">{', '.join(w.nameservers) or 'N/A'}</span></div>
          </div>
        </div>
        """

    # Summary stats
    high_count = sum(
        1 for h in report.http
        for hf in h.header_findings
        if hf.severity == "HIGH"
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Recon Report — {report.target}</title>
<style>
  :root {{
    --bg: #0d1117; --surface: #161b22; --border: #30363d;
    --text: #e6edf3; --muted: #8b949e; --green: #3fb950;
    --yellow: #d29922; --red: #f85149; --blue: #79c0ff;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ background: var(--bg); color: var(--text); font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; font-size: 14px; line-height: 1.6; padding: 2rem; }}
  .header {{ border-bottom: 1px solid var(--border); padding-bottom: 1.5rem; margin-bottom: 2rem; }}
  .header h1 {{ font-size: 22px; font-weight: 600; color: var(--green); }}
  .header p {{ color: var(--muted); font-size: 13px; margin-top: 4px; }}
  .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(130px, 1fr)); gap: 12px; margin-bottom: 2rem; }}
  .stat {{ background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 1rem; text-align: center; }}
  .stat .num {{ font-size: 28px; font-weight: 700; color: var(--green); }}
  .stat .lbl {{ font-size: 12px; color: var(--muted); margin-top: 4px; }}
  .stat.warn .num {{ color: var(--yellow); }}
  .stat.danger .num {{ color: var(--red); }}
  h2 {{ font-size: 16px; font-weight: 600; margin: 2rem 0 1rem; color: var(--blue); border-left: 3px solid var(--blue); padding-left: 10px; }}
  .card {{ background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 1.25rem; margin-bottom: 1rem; }}
  .card-title {{ font-size: 15px; font-weight: 600; margin-bottom: 1rem; color: var(--green); }}
  table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
  th {{ text-align: left; color: var(--muted); font-weight: 500; padding: 6px 8px; border-bottom: 1px solid var(--border); }}
  td {{ padding: 6px 8px; border-bottom: 1px solid #21262d; }}
  tr:last-child td {{ border-bottom: none; }}
  .open {{ color: var(--green); font-weight: 600; }}
  .muted {{ color: var(--muted); }}
  .meta-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 8px; }}
  .label {{ color: var(--muted); font-size: 12px; display: block; }}
  .val {{ font-weight: 500; }}
  p.label {{ color: var(--muted); font-size: 12px; margin-bottom: 6px; }}
  ul {{ padding-left: 1.2rem; color: var(--yellow); font-size: 13px; }}
  footer {{ margin-top: 3rem; padding-top: 1rem; border-top: 1px solid var(--border); color: var(--muted); font-size: 12px; text-align: center; }}
</style>
</head>
<body>

<div class="header">
  <h1>Reconnaissance Report</h1>
  <p>Target: {report.target} &nbsp;|&nbsp; Generated: {ts} &nbsp;|&nbsp; Tool: recon-tool v2</p>
  <p style="margin-top:6px;color:#f85149;">This report is for authorised security testing only.</p>
</div>

<div class="stats">
  <div class="stat"><div class="num">{len(report.ports)}</div><div class="lbl">Open Ports</div></div>
  <div class="stat"><div class="num">{len(report.dns_records)}</div><div class="lbl">DNS Records</div></div>
  <div class="stat"><div class="num">{len(report.subdomains)}</div><div class="lbl">Live Subdomains</div></div>
  <div class="stat"><div class="num">{len(report.http)}</div><div class="lbl">HTTP Services</div></div>
  <div class="stat {'danger' if high_count > 0 else ''}"><div class="num">{high_count}</div><div class="lbl">High Severity Headers</div></div>
</div>

<h2>Open Ports</h2>
<div class="card">
  <table>
    <thead><tr><th>Port</th><th>State</th><th>Service</th><th>Banner</th></tr></thead>
    <tbody>{port_rows}</tbody>
  </table>
</div>

<h2>DNS Records</h2>
<div class="card">
  <table>
    <thead><tr><th>Type</th><th>Value</th></tr></thead>
    <tbody>{dns_rows}</tbody>
  </table>
</div>

<h2>Subdomains</h2>
<div class="card">
  <table>
    <thead><tr><th>Subdomain</th><th>IP Address</th><th>HTTP Status</th></tr></thead>
    <tbody>{sub_rows}</tbody>
  </table>
</div>

<h2>HTTP Reconnaissance</h2>
{http_html}

<h2>WHOIS</h2>
{whois_html if whois_html else '<div class="card"><p class="muted">No WHOIS data collected</p></div>'}

<footer>Generated by recon-tool v2 &nbsp;|&nbsp; github.com/devmystro/recon-tool &nbsp;|&nbsp; Authorised use only</footer>

</body>
</html>"""


def save_reports(report: ScanReport, output_dir: str = "reports") -> dict[str, str]:
    """
    Save both JSON and HTML reports to reports/<target>/<timestamp>/
    Returns dict with paths to both files.
    """
    safe_target = report.target.replace(".", "_").replace("/", "_")
    ts_slug = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    folder = os.path.join(output_dir, safe_target, ts_slug)
    os.makedirs(folder, exist_ok=True)

    # JSON
    json_path = os.path.join(folder, "report.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(report.to_dict(), f, indent=2, default=str)

    # HTML
    html_path = os.path.join(folder, "report.html")
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(generate_html(report))

    ok(f"JSON report  -> {json_path}")
    ok(f"HTML report  -> {html_path}")

    return {"json": json_path, "html": html_path}
