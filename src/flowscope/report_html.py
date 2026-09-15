from __future__ import annotations

import html
from datetime import datetime, timezone
from typing import Any

from flowscope.models import AnalysisReport
from flowscope.report import meets_severity

_SEVERITY_CSS = {
    "critical": "#f85149",
    "high": "#db6d28",
    "medium": "#d29922",
    "low": "#3fb950",
}


def _esc(value: Any) -> str:
    return html.escape("" if value is None else str(value))


def _geo_label(ip: str, meta: dict[str, Any]) -> str:
    geo = (meta.get("geoip") or {}).get(ip) or {}
    if geo.get("country_code"):
        name = geo.get("country_name") or geo["country_code"]
        return f"{geo['country_code']} ({name})"
    if geo.get("network_label"):
        return str(geo["network_label"])
    if geo.get("is_private"):
        return "private"
    return "-"


def _table_rows(rows: list[str], empty: str, colspan: int) -> str:
    return "".join(rows) if rows else f'<tr><td colspan="{colspan}">{empty}</td></tr>'


def mitre_href(technique: str) -> str:
    if not technique:
        return "-"
    parts = technique.split(".")
    if len(parts) == 2:
        url = f"https://attack.mitre.org/techniques/{parts[0]}/{parts[1]}/"
    else:
        url = f"https://attack.mitre.org/techniques/{technique}/"
    return f'<a href="{_esc(url)}">{_esc(technique)}</a>'


def write_html(report: AnalysisReport, out_path: str, min_severity: str = "low") -> None:
    meta = report.meta
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    scored = [
        f for f in report.findings if f.score_delta > 0 and meets_severity(f, min_severity)
    ]
    info = [f for f in report.findings if f.score_delta <= 0]

    findings_rows = []
    for f in sorted(scored, key=lambda x: -x.score_delta):
        color = _SEVERITY_CSS.get(f.severity, "#8b949e")
        findings_rows.append(
            "<tr>"
            f"<td><span class='pill' style='background:{color}22;color:{color}'>{_esc(f.severity)}</span></td>"
            f"<td>{_esc(f.category)}</td>"
            f"<td class='mono'>{mitre_href(f.mitre or '')}</td>"
            f"<td>{_esc(f.title)}</td>"
            f"<td>{_esc(f.detail)}</td>"
            f"<td>{_esc(f.advice or '-')}</td>"
            f"<td class='num'>{f.score_delta}</td>"
            "</tr>"
        )

    info_rows = []
    for f in info:
        info_rows.append(
            "<tr>"
            f"<td>{_esc(f.category)}</td>"
            f"<td>{_esc(f.title)}</td>"
            f"<td>{_esc(f.detail)}</td>"
            f"<td class='mono'>{mitre_href(f.mitre or '')}</td>"
            "</tr>"
        )

    talker_rows = []
    for ip, pkts, byts in report.top_ips[:20]:
        talker_rows.append(
            f"<tr><td>{_esc(ip)}</td><td>{_geo_label(ip, meta)}</td>"
            f"<td class='num'>{pkts}</td><td class='num'>{byts}</td></tr>"
        )

    tcp_rows = []
    for c in report.tcp_connections[:20]:
        tcp_rows.append(
            f"<tr><td>{_esc(c.src)}:{c.sport} -> {_esc(c.dst)}:{c.dport}</td>"
            f"<td class='num'>{c.packets}</td><td class='num'>{c.syn_count}</td></tr>"
        )

    dns_rows = []
    for name, count in meta.get("top_dns_domains") or []:
        dns_rows.append(f"<tr><td>{_esc(name)}</td><td class='num'>{count}</td></tr>")

    http_rows = []
    for e in report.http_events[:20]:
        http_rows.append(
            f"<tr><td>{_esc(e.src)}</td><td>{_esc(e.method)}</td>"
            f"<td>{_esc(e.host or e.dst)}</td><td class='mono'>{_esc(e.uri)}</td></tr>"
        )

    tls_rows = []
    for e in report.tls_sni_events[:30]:
        tls_rows.append(
            "<tr>"
            f"<td>{_esc(e.src)}</td><td>{_geo_label(e.src, meta)}</td>"
            f"<td>{_esc(e.dst)}:{e.dport}</td><td>{_geo_label(e.dst, meta)}</td>"
            f"<td>{_esc(e.sni)}</td>"
            f"<td class='mono'>{_esc(e.ja3_hash)}</td>"
            f"<td class='mono'>{_esc(e.ja3s_hash)}</td>"
            f"<td class='mono'>{_esc(e.ja4)}</td>"
            "</tr>"
        )

    geo_enabled = (
        "yes (MaxMind MMDB)" if meta.get("geoip_enabled") else "builtin (private / TEST-NET labels only)"
    )

    doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>Flowscope — {_esc(report.pcap_path)}</title>
  <style>
    :root {{
      --bg: #0d1117; --panel: #161b22; --text: #e6edf3; --muted: #8b949e;
      --border: #30363d; --accent: #58a6ff;
    }}
    * {{ box-sizing: border-box; }}
    body {{ margin: 0; font-family: ui-sans-serif, system-ui, Segoe UI, sans-serif;
      background: var(--bg); color: var(--text); line-height: 1.5; }}
    header {{ padding: 1.5rem 2rem; border-bottom: 1px solid var(--border);
      background: linear-gradient(180deg, #161b22, #0d1117); }}
    h1 {{ margin: 0 0 .25rem; font-size: 1.5rem; }}
    .sub {{ color: var(--muted); font-size: .9rem; }}
    main {{ padding: 1.5rem 2rem 3rem; max-width: 1200px; margin: 0 auto; }}
    .cards {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 1rem; margin-bottom: 1.5rem; }}
    .card {{ background: var(--panel); border: 1px solid var(--border); border-radius: 8px; padding: 1rem; }}
    .card .label {{ color: var(--muted); font-size: .75rem; text-transform: uppercase; letter-spacing: .04em; }}
    .card .value {{ font-size: 1.4rem; font-weight: 600; margin-top: .25rem; }}
    .risk {{ color: #f85149; }}
    section {{ margin-top: 2rem; }}
    h2 {{ font-size: 1.1rem; margin-bottom: .75rem; color: var(--accent); }}
    table {{ width: 100%; border-collapse: collapse; font-size: .85rem;
      background: var(--panel); border: 1px solid var(--border); border-radius: 8px; overflow: hidden; }}
    th, td {{ padding: .5rem .65rem; border-bottom: 1px solid var(--border); text-align: left; vertical-align: top; }}
    th {{ background: #21262d; color: var(--muted); font-weight: 600; }}
    tr:last-child td {{ border-bottom: none; }}
    .num {{ text-align: right; font-variant-numeric: tabular-nums; }}
    .mono {{ font-family: ui-monospace, Consolas, monospace; font-size: .75rem; word-break: break-all; }}
    .pill {{ display: inline-block; padding: .1rem .45rem; border-radius: 4px; font-size: .75rem; font-weight: 600; }}
    a {{ color: var(--accent); text-decoration: none; }}
    a:hover {{ text-decoration: underline; }}
  </style>
</head>
<body>
  <header>
    <h1>Flowscope report</h1>
    <p class="sub">{_esc(report.pcap_path)} · generated {generated}</p>
  </header>
  <main>
    <div class="cards">
      <div class="card"><div class="label">Risk score</div><div class="value risk">{report.risk_score}/100</div></div>
      <div class="card"><div class="label">Packets</div><div class="value">{report.packet_count}</div></div>
      <div class="card"><div class="label">Duration</div><div class="value">{report.duration_seconds:.2f}s</div></div>
      <div class="card"><div class="label">Scored findings</div><div class="value">{meta.get('scored_finding_count', len(scored))}</div></div>
      <div class="card"><div class="label">TLS flows</div><div class="value">{meta.get('tls_client_hello_count', 0)}</div></div>
      <div class="card"><div class="label">GeoIP</div><div class="value" style="font-size:.95rem">{_esc(geo_enabled)}</div></div>
    </div>

    <section>
      <h2>Scored findings</h2>
      <table>
        <thead><tr><th>Severity</th><th>Category</th><th>MITRE</th><th>Title</th><th>Detail</th><th>Advice</th><th>Score</th></tr></thead>
        <tbody>{_table_rows(findings_rows, 'No scored findings', 7)}</tbody>
      </table>
    </section>

    <section>
      <h2>Informational</h2>
      <table>
        <thead><tr><th>Category</th><th>Title</th><th>Detail</th><th>MITRE</th></tr></thead>
        <tbody>{_table_rows(info_rows, 'None', 4)}</tbody>
      </table>
    </section>

    <section>
      <h2>Top talkers</h2>
      <table>
        <thead><tr><th>IP</th><th>Geo</th><th>Packets</th><th>Bytes</th></tr></thead>
        <tbody>{_table_rows(talker_rows, '-', 4)}</tbody>
      </table>
    </section>

    <section>
      <h2>Top DNS domains</h2>
      <table>
        <thead><tr><th>Name</th><th>Queries</th></tr></thead>
        <tbody>{_table_rows(dns_rows, 'No DNS queries', 2)}</tbody>
      </table>
    </section>

    <section>
      <h2>HTTP (cleartext)</h2>
      <table>
        <thead><tr><th>Source</th><th>Method</th><th>Host</th><th>URI</th></tr></thead>
        <tbody>{_table_rows(http_rows, 'No HTTP requests', 4)}</tbody>
      </table>
    </section>

    <section>
      <h2>TCP connections</h2>
      <table>
        <thead><tr><th>Flow</th><th>Packets</th><th>SYNs</th></tr></thead>
        <tbody>{_table_rows(tcp_rows, 'None', 3)}</tbody>
      </table>
    </section>

    <section>
      <h2>TLS (SNI / JA3 / JA3S / JA4)</h2>
      <table>
        <thead><tr><th>Client</th><th>Client geo</th><th>Server</th><th>Server geo</th>
        <th>SNI</th><th>JA3</th><th>JA3S</th><th>JA4</th></tr></thead>
        <tbody>{_table_rows(tls_rows, 'No TLS ClientHello observed', 8)}</tbody>
      </table>
    </section>

    <footer>
      Flowscope — educational PCAP analysis. GeoIP via MaxMind when <code>--geoip</code> is set.
    </footer>
  </main>
</body>
</html>
"""
    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write(doc)
