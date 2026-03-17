"""
html_report.py — Generates a professional HTML security report

This is what the analyst (or recruiter) actually sees.
A clean, colour-coded, professional report covering all findings.
"""

import os
from datetime import datetime

# Severity colour mapping
SEVERITY_COLORS = {
    "CRITICAL": "#dc2626",   # red
    "HIGH":     "#ea580c",   # orange
    "MEDIUM":   "#d97706",   # amber
    "LOW":      "#65a30d",   # green
    "INFO":     "#2563eb",   # blue
}

SEVERITY_BG = {
    "CRITICAL": "#fef2f2",
    "HIGH":     "#fff7ed",
    "MEDIUM":   "#fffbeb",
    "LOW":      "#f7fee7",
    "INFO":     "#eff6ff",
}

def severity_badge(severity):
    color = SEVERITY_COLORS.get(severity, "#6b7280")
    bg    = SEVERITY_BG.get(severity, "#f9fafb")
    return (
        f'<span style="background:{bg};color:{color};'
        f'padding:2px 10px;border-radius:12px;'
        f'font-size:12px;font-weight:700;'
        f'border:1px solid {color};">{severity}</span>'
    )

def fmt_bytes(b):
    """Format bytes into human readable string."""
    if b < 1024:
        return f"{b} B"
    elif b < 1024 ** 2:
        return f"{b/1024:.1f} KB"
    elif b < 1024 ** 3:
        return f"{b/1024**2:.1f} MB"
    else:
        return f"{b/1024**3:.1f} GB"

def generate_report(results):
    """
    Build full HTML report from all analyser results.
    Saves to reports/ directory and returns the file path.
    """

    os.makedirs("reports", exist_ok=True)
    timestamp   = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_path = f"reports/pcap_report_{timestamp}.html"

    # Pull data from results
    filename    = results.get("file", "unknown.pcap")
    total_pkts  = results.get("total_packets", 0)
    sessions    = results.get("sessions", {})
    creds       = results.get("credentials", {})
    portscans   = results.get("portscans", {})
    dns         = results.get("dns", {})
    protocols   = results.get("protocols", {})
    iocs        = results.get("iocs", {})
    now         = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # --- Count total alerts across all modules ---
    total_critical = (
        creds.get("critical_count", 0) +
        sum(1 for d in portscans.get("detections", []) if d.get("severity") == "CRITICAL") +
        sum(1 for a in dns.get("alerts", [])       if a.get("severity") == "CRITICAL") +
        iocs.get("malicious_count", 0)
    )

    total_alerts = (
        creds.get("total_found", 0) +
        portscans.get("total_detected", 0) +
        dns.get("total_alerts", 0) +
        len(protocols.get("alerts", [])) +
        iocs.get("malicious_count", 0) +
        iocs.get("suspicious_count", 0)
    )

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>PCAP Analysis Report — {os.path.basename(filename)}</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    background: #0f172a;
    color: #e2e8f0;
    line-height: 1.6;
  }}
  .header {{
    background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%);
    border-bottom: 2px solid #dc2626;
    padding: 20px;
  }}
  .header h1 {{
    font-size: 28px;
    font-weight: 800;
    color: #f8fafc;
    letter-spacing: -0.5px;
  }}
  .header h1 span {{ color: #dc2626; }}
  .header .meta {{
    margin-top: 8px;
    font-size: 13px;
    color: #94a3b8;
  }}
  .container {{ padding: 16px 20px; max-width: 1400px; margin: 0 auto; }}

  /* Summary cards */
  .cards {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
    gap: 16px;
    margin-bottom: 32px;
  }}
  .card {{
    background: #1e293b;
    border: 1px solid #334155;
    border-radius: 12px;
    padding: 20px;
    text-align: center;
  }}
  .card .number {{
    font-size: 36px;
    font-weight: 800;
    line-height: 1;
  }}
  .card .label {{
    font-size: 12px;
    color: #94a3b8;
    margin-top: 6px;
    text-transform: uppercase;
    letter-spacing: 0.5px;
  }}
  .card.red    .number {{ color: #dc2626; }}
  .card.orange .number {{ color: #ea580c; }}
  .card.blue   .number {{ color: #3b82f6; }}
  .card.green  .number {{ color: #22c55e; }}
  .card.purple .number {{ color: #a855f7; }}

  /* Sections */
  .section {{
    background: #1e293b;
    border: 1px solid #334155;
    border-radius: 12px;
    margin-bottom: 24px;
    overflow: hidden;
  }}
  .section-header {{
    padding: 16px 24px;
    background: #263548;
    border-bottom: 1px solid #334155;
    display: flex;
    align-items: center;
    gap: 10px;
  }}
  .section-header h2 {{
    font-size: 16px;
    font-weight: 700;
    color: #f1f5f9;
  }}
  .section-header .count {{
    background: #374151;
    color: #9ca3af;
    font-size: 12px;
    padding: 2px 8px;
    border-radius: 10px;
  }}
  .section-body {{ padding: 20px 24px; overflow-x: auto; }}

  /* Tables */
  table {{
    width: 100%;
    min-width: 600px;
    border-collapse: collapse;
    font-size: 13px;
  }}
  th {{
    text-align: left;
    padding: 10px 12px;
    background: #0f172a;
    color: #64748b;
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    border-bottom: 1px solid #334155;
  }}
  td {{
    padding: 10px 12px;
    border-bottom: 1px solid #1e293b;
    color: #cbd5e1;
    vertical-align: top;
  }}
  tr:last-child td {{ border-bottom: none; }}
  tr:hover td {{ background: #263548; }}

  /* Alert rows */
  .alert-row {{ border-left: 3px solid #dc2626; }}
  .alert-row td:first-child {{ padding-left: 14px; }}

  /* Protocol bar */
  .proto-bar {{
    height: 8px;
    background: #3b82f6;
    border-radius: 4px;
    min-width: 4px;
  }}

  /* Credential finding */
  .cred-box {{
    background: #0f172a;
    border: 1px solid #dc2626;
    border-radius: 8px;
    padding: 14px 18px;
    margin-bottom: 10px;
    font-family: 'Courier New', monospace;
    font-size: 13px;
  }}
  .cred-box .cred-header {{
    font-size: 11px;
    color: #94a3b8;
    margin-bottom: 6px;
    text-transform: uppercase;
    letter-spacing: 0.5px;
  }}
  .cred-value {{ color: #fca5a5; font-weight: 600; }}

  /* IOC box */
  .ioc-box {{
    background: #0f172a;
    border-radius: 8px;
    padding: 14px 18px;
    margin-bottom: 10px;
    border-left: 4px solid #dc2626;
  }}
  .ioc-ip {{
    font-family: monospace;
    font-size: 16px;
    font-weight: 700;
    color: #f87171;
  }}
  .ioc-meta {{
    font-size: 12px;
    color: #94a3b8;
    margin-top: 4px;
  }}
  .confidence-bar-wrap {{
    background: #1e293b;
    border-radius: 4px;
    height: 6px;
    margin-top: 8px;
    width: 200px;
  }}
  .confidence-bar {{
    height: 6px;
    border-radius: 4px;
    background: #dc2626;
  }}

  .empty {{ color: #4b5563; font-size: 14px; padding: 16px 0; }}
  .tag {{
    display: inline-block;
    background: #1e3a5f;
    color: #93c5fd;
    font-size: 11px;
    padding: 2px 8px;
    border-radius: 4px;
    margin: 2px;
    font-family: monospace;
  }}
  .footer {{
    text-align: center;
    padding: 32px;
    color: #334155;
    font-size: 12px;
    border-top: 1px solid #1e293b;
    margin-top: 16px;
  }}
</style>
</head>
<body>

<div class="header">
  <h1>🔍 PCAP <span>Analysis Report</span></h1>
  <div class="meta">
    File: <strong style="color:#e2e8f0">{os.path.basename(filename)}</strong>
    &nbsp;|&nbsp; Generated: {now}
    &nbsp;|&nbsp; Tool: pcap-analyser v1.0
    &nbsp;|&nbsp; Analyst: Darshith Thalipady Nagesh
  </div>
</div>

<div class="container">

  <!-- Summary Cards -->
  <div class="cards">
    <div class="card blue">
      <div class="number">{total_pkts:,}</div>
      <div class="label">Total Packets</div>
    </div>
    <div class="card blue">
      <div class="number">{sessions.get('total_sessions', 0)}</div>
      <div class="label">Sessions</div>
    </div>
    <div class="card red">
      <div class="number">{total_critical}</div>
      <div class="label">Critical Findings</div>
    </div>
    <div class="card orange">
      <div class="number">{total_alerts}</div>
      <div class="label">Total Alerts</div>
    </div>
    <div class="card red">
      <div class="number">{creds.get('critical_count', 0)}</div>
      <div class="label">Credentials Found</div>
    </div>
    <div class="card orange">
      <div class="number">{portscans.get('total_detected', 0)}</div>
      <div class="label">Port Scans</div>
    </div>
    <div class="card purple">
      <div class="number">{iocs.get('malicious_count', 0)}</div>
      <div class="label">Malicious IPs</div>
    </div>
    <div class="card green">
      <div class="number">{protocols.get('unique_protocols', 0)}</div>
      <div class="label">Protocols</div>
    </div>
  </div>

  <!-- CREDENTIALS -->
  <div class="section">
    <div class="section-header">
      <h2>🔑 Plaintext Credentials</h2>
      <span class="count">{creds.get('total_found', 0)} found</span>
    </div>
    <div class="section-body">"""

    findings = creds.get("findings", [])
    if findings:
        for f in findings:
            html += f"""
      <div class="cred-box">
        <div class="cred-header">
          {severity_badge(f['severity'])}
          &nbsp; {f['protocol']} &nbsp;|&nbsp;
          {f['src_ip']} → {f['dst_ip']}
        </div>
        <div><span style="color:#94a3b8">{f['type']}:</span>
          <span class="cred-value"> {f['value']}</span>
        </div>
      </div>"""
    else:
        html += '<div class="empty">✓ No plaintext credentials found</div>'

    html += """
    </div>
  </div>

  <!-- PORT SCANS -->
  <div class="section">
    <div class="section-header">
      <h2>🔎 Port Scan Detections</h2>
      <span class="count">{} detected</span>
    </div>
    <div class="section-body">""".format(portscans.get("total_detected", 0))

    detections = portscans.get("detections", [])
    if detections:
        html += """
      <table>
        <thead>
          <tr>
            <th>Source IP</th>
            <th>Scan Type</th>
            <th>Ports Hit</th>
            <th>Targets</th>
            <th>Sample Ports</th>
            <th>Severity</th>
            <th>MITRE</th>
          </tr>
        </thead>
        <tbody>"""
        for d in detections:
            ports_preview = ", ".join(str(p) for p in d["ports"][:8])
            if len(d["ports"]) > 8:
                ports_preview += f" +{len(d['ports'])-8} more"
            targets = ", ".join(d["target_ips"][:3])
            html += f"""
          <tr class="alert-row">
            <td><code style="color:#93c5fd">{d['src_ip']}</code></td>
            <td><strong>{d['scan_type']}</strong></td>
            <td><strong style="color:#f87171">{d['ports_hit']}</strong></td>
            <td>{targets}</td>
            <td><span style="font-family:monospace;font-size:12px;color:#94a3b8">{ports_preview}</span></td>
            <td>{severity_badge(d['severity'])}</td>
            <td><span class="tag">{d['mitre']}</span></td>
          </tr>"""
        html += "</tbody></table>"
    else:
        html += '<div class="empty">✓ No port scans detected</div>'

    html += """
    </div>
  </div>

  <!-- DNS ANALYSIS -->
  <div class="section">
    <div class="section-header">
      <h2>🌐 DNS Analysis</h2>
      <span class="count">{} queries | {} alerts</span>
    </div>
    <div class="section-body">""".format(
        dns.get("total_queries", 0),
        dns.get("total_alerts", 0)
    )

    dns_alerts = dns.get("alerts", [])
    if dns_alerts:
        html += """
      <table>
        <thead>
          <tr>
            <th>Type</th><th>Source IP</th>
            <th>Domain</th><th>Detail</th>
            <th>Severity</th><th>MITRE</th>
          </tr>
        </thead><tbody>"""
        for a in dns_alerts:
            html += f"""
          <tr class="alert-row">
            <td><strong>{a['type']}</strong></td>
            <td><code style="color:#93c5fd">{a['src_ip']}</code></td>
            <td style="font-family:monospace;color:#fcd34d">{a['domain']}</td>
            <td style="color:#94a3b8;font-size:12px">{a['detail']}</td>
            <td>{severity_badge(a['severity'])}</td>
            <td><span class="tag">{a.get('mitre','—')}</span></td>
          </tr>"""
        html += "</tbody></table><br>"

    top_domains = dns.get("top_domains", [])
    if top_domains:
        html += """
      <strong style="font-size:13px;color:#94a3b8">
        TOP QUERIED DOMAINS
      </strong>
      <table style="margin-top:10px">
        <thead>
          <tr><th>Domain</th><th>Query Count</th></tr>
        </thead><tbody>"""
        for d in top_domains:
            html += f"""
          <tr>
            <td style="font-family:monospace;color:#fcd34d">{d['domain']}</td>
            <td>{d['count']}</td>
          </tr>"""
        html += "</tbody></table>"

    if not dns_alerts and not top_domains:
        html += '<div class="empty">No DNS traffic found</div>'

    html += """
    </div>
  </div>

  <!-- PROTOCOL BREAKDOWN -->
  <div class="section">
    <div class="section-header">
      <h2>📊 Protocol Breakdown</h2>
      <span class="count">{} protocols</span>
    </div>
    <div class="section-body">""".format(protocols.get("unique_protocols", 0))

    proto_alerts = protocols.get("alerts", [])
    if proto_alerts:
        for a in proto_alerts:
            html += f"""
      <div style="background:#0f172a;border-left:3px solid
        {SEVERITY_COLORS.get(a['severity'],'#6b7280')};
        padding:10px 16px;border-radius:4px;margin-bottom:10px;font-size:13px">
        {severity_badge(a['severity'])}
        &nbsp; <strong>{a['type']}</strong>: {a['protocol']}
        — <span style="color:#94a3b8">{a['detail']}</span>
      </div>"""

    breakdown = protocols.get("breakdown", [])
    if breakdown:
        html += """
      <table style="margin-top:12px">
        <thead>
          <tr>
            <th>Protocol</th><th>Packets</th>
            <th>Data</th><th>% Traffic</th>
            <th>Distribution</th><th>Flags</th>
          </tr>
        </thead><tbody>"""
        max_pct = max((p["percentage"] for p in breakdown), default=1)
        for p in breakdown:
            bar_w = int((p["percentage"] / max_pct) * 200) if max_pct else 0
            flags = ""
            if p.get("insecure"):
                flags += '<span class="tag" style="background:#4c1d1d;color:#fca5a5">INSECURE</span> '
            if p.get("ot"):
                flags += '<span class="tag" style="background:#1c3a5e;color:#93c5fd">OT/ICS</span>'
            html += f"""
          <tr>
            <td><strong>{p['protocol']}</strong></td>
            <td>{p['packets']:,}</td>
            <td>{fmt_bytes(p['bytes'])}</td>
            <td>{p['percentage']}%</td>
            <td><div class="proto-bar" style="width:{bar_w}px"></div></td>
            <td>{flags}</td>
          </tr>"""
        html += "</tbody></table>"

    html += """
    </div>
  </div>

  <!-- IOC / THREAT INTEL -->
  <div class="section">
    <div class="section-header">
      <h2>⚠️  Threat Intelligence (AbuseIPDB)</h2>
      <span class="count">{} checked | {} malicious | {} suspicious</span>
    </div>
    <div class="section-body">""".format(
        iocs.get("total_checked", 0),
        iocs.get("malicious_count", 0),
        iocs.get("suspicious_count", 0),
    )

    malicious  = iocs.get("malicious", [])
    suspicious = iocs.get("suspicious", [])
    combined   = malicious + suspicious

    if combined:
        for ioc in combined:
            bar_w    = int(ioc["confidence"] * 1.5)
            cats     = ", ".join(ioc.get("categories", [])) or "—"
            html += f"""
      <div class="ioc-box">
        <div class="ioc-ip">{ioc['ip']}</div>
        <div class="ioc-meta">
          {severity_badge(ioc['severity'])}
          &nbsp; Country: <strong>{ioc['country']}</strong>
          &nbsp;|&nbsp; ISP: {ioc['isp']}
          &nbsp;|&nbsp; Reports: <strong style="color:#f87171">{ioc['total_reports']}</strong>
          &nbsp;|&nbsp; Last seen: {ioc['last_reported']}
        </div>
        <div class="ioc-meta" style="margin-top:4px">
          Categories: <span style="color:#fcd34d">{cats}</span>
        </div>
        <div class="confidence-bar-wrap">
          <div class="confidence-bar" style="width:{bar_w}px"></div>
        </div>
        <div style="font-size:11px;color:#6b7280;margin-top:2px">
          Abuse confidence: {ioc['confidence']}%
        </div>
      </div>"""
    elif iocs.get("error"):
        html += f'<div class="empty">{iocs["error"]}</div>'
    elif iocs.get("note"):
        html += f'<div class="empty">{iocs["note"]}</div>'
    else:
        html += '<div class="empty">✓ No malicious IPs detected</div>'

    html += """
    </div>
  </div>

  <!-- TOP SESSIONS -->
  <div class="section">
    <div class="section-header">
      <h2>🔗 Top Sessions (by data volume)</h2>
      <span class="count">{} total sessions</span>
    </div>
    <div class="section-body">""".format(sessions.get("total_sessions", 0))

    top = sessions.get("top_talkers", [])
    if top:
        html += """
      <table>
        <thead>
          <tr>
            <th>Source</th><th>Destination</th>
            <th>Protocol</th><th>Packets</th><th>Data</th>
          </tr>
        </thead><tbody>"""
        for s in top:
            html += f"""
          <tr>
            <td><code style="color:#93c5fd">{s['src_ip']}:{s['src_port']}</code></td>
            <td><code style="color:#86efac">{s['dst_ip']}:{s['dst_port']}</code></td>
            <td>{s['protocol']}</td>
            <td>{s['packets']:,}</td>
            <td><strong>{fmt_bytes(s['bytes'])}</strong></td>
          </tr>"""
        html += "</tbody></table>"
    else:
        html += '<div class="empty">No sessions found</div>'

    html += f"""
    </div>
  </div>

</div>

<div class="footer">
  Generated by pcap-analyser v1.0 &nbsp;|&nbsp;
  Darshith Thalipady Nagesh &nbsp;|&nbsp;
  {now} &nbsp;|&nbsp;
  <span style="color:#dc2626">For authorised security research only</span>
</div>

</body>
</html>"""

    with open(report_path, "w") as f:
        f.write(html)

    return report_path
