from __future__ import annotations

import json
from dataclasses import asdict
from typing import Any
import unicodedata

from rich.console import Console
from rich.table import Table
from rich.text import Text

from flowscope.models import AnalysisReport, Finding

SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def literal(value: object) -> Text:
    """Protocol metadata is text, never markup or terminal control traffic."""
    text = str(value)
    return Text("".join(
        character.encode("unicode_escape").decode("ascii")
        if unicodedata.category(character) in {"Cc", "Cf"} else character
        for character in text
    ))


def meets_severity(finding: Finding, min_severity: str) -> bool:
    return SEVERITY_RANK.get(finding.severity, 0) >= SEVERITY_RANK.get(min_severity, 1)


def report_to_dict(report: AnalysisReport) -> dict[str, Any]:
    data = asdict(report)
    data["dns_queries"] = data["dns_queries"][:500]
    data["http_events"] = data["http_events"][:200]
    data["tls_sni_events"] = data["tls_sni_events"][:200]
    return data


def write_json(report: AnalysisReport, out_path: str) -> None:
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(report_to_dict(report), f, indent=2, ensure_ascii=False)


def print_console(report: AnalysisReport, min_severity: str = "low") -> None:
    console = Console()
    console.print(Text.assemble("\n", ("Flowscope", "bold"), " — ", literal(report.pcap_path)))
    console.print(
        f"Packets: {report.packet_count} | Duration: {report.duration_seconds:.2f}s | "
        f"[bold red]Risk score: {report.risk_score}/100[/bold red]\n"
    )

    meta = report.meta
    console.print(
        f"TCP flows: {meta.get('tcp_connection_count', 0)} | "
        f"DNS: {meta.get('dns_query_count', 0)} | "
        f"HTTP: {meta.get('http_request_count', 0)} | "
        f"TLS: {meta.get('tls_client_hello_count', 0)} | "
        f"SYN: {meta.get('syn_count', 0)} | "
        f"Scored findings: {meta.get('scored_finding_count', 0)}\n"
    )

    if report.tls_sni_events:
        tsni = Table(title="TLS ClientHello (SNI / JA3)")
        tsni.add_column("Source")
        tsni.add_column("Destination")
        tsni.add_column("SNI")
        tsni.add_column("Version")
        tsni.add_column("JA3")
        tsni.add_column("JA3S")
        tsni.add_column("JA4")
        for e in report.tls_sni_events[:15]:
            ja3 = (
                (e.ja3_hash[:12] + "...")
                if e.ja3_hash and len(e.ja3_hash) > 12
                else (e.ja3_hash or "-")
            )
            ja3s = (
                (e.ja3s_hash[:12] + "...")
                if e.ja3s_hash and len(e.ja3s_hash) > 12
                else (e.ja3s_hash or "-")
            )
            ja4 = e.ja4 or "-"
            if len(ja4) > 24:
                ja4 = ja4[:24] + "..."
            tsni.add_row(
                e.src,
                f"{e.dst}:{e.dport}",
                literal(e.sni or "-"),
                e.tls_version,
                ja3,
                ja3s,
                ja4,
            )
        console.print(tsni)

        ja3_rows = [e for e in report.tls_sni_events if e.ja3_hash]
        if ja3_rows:
            tja3 = Table(title="JA3 fingerprints")
            tja3.add_column("JA3 hash")
            tja3.add_column("JA3 string (truncated)")
            seen: set[str] = set()
            for e in ja3_rows:
                if e.ja3_hash in seen:
                    continue
                seen.add(e.ja3_hash)
                snippet = (e.ja3_string or "")[:72]
                if e.ja3_string and len(e.ja3_string) > 72:
                    snippet += "..."
                tja3.add_row(e.ja3_hash, snippet or "-")
            console.print(tja3)

    geo = meta.get("geoip") or {}

    def _geo_short(ip: str) -> str:
        g = geo.get(ip) or {}
        if g.get("country_code"):
            return str(g["country_code"])
        if g.get("network_label"):
            return str(g["network_label"])[:18]
        if g.get("is_private"):
            return "private"
        return "-"

    t = Table(title="Top talkers (by packets)")
    t.add_column("IP")
    t.add_column("Geo")
    t.add_column("Packets", justify="right")
    t.add_column("Bytes", justify="right")
    for ip, pkts, byts in report.top_ips[:10]:
        t.add_row(literal(ip), literal(_geo_short(ip)), str(pkts), str(byts))
    console.print(t)

    t2 = Table(title="Top TCP connections")
    t2.add_column("Flow")
    t2.add_column("Packets", justify="right")
    t2.add_column("SYNs", justify="right")
    for c in report.tcp_connections[:10]:
        t2.add_row(f"{c.src}:{c.sport} -> {c.dst}:{c.dport}", str(c.packets), str(c.syn_count))
    console.print(t2)

    scored = [
        f for f in report.findings if f.score_delta > 0 and meets_severity(f, min_severity)
    ]
    info = [f for f in report.findings if f.score_delta <= 0]

    t3 = Table(title="Scored findings")
    t3.add_column("Severity")
    t3.add_column("Category")
    t3.add_column("MITRE")
    t3.add_column("Title")
    t3.add_column("+Score", justify="right")
    t3.add_column("Advice")
    for f in sorted(scored, key=lambda x: -x.score_delta):
        color = {"critical": "red", "high": "orange3", "medium": "yellow", "low": "green"}.get(
            f.severity, "white"
        )
        t3.add_row(
            f"[{color}]{f.severity}[/{color}]",
            literal(f.category),
            literal(f.mitre or "-"),
            literal(f.title),
            str(f.score_delta),
            literal((f.advice or "-")[:80]),
        )
    console.print(t3)

    for f in scored:
        if f.detail:
            mitre = f" [{f.mitre}]" if f.mitre else ""
            console.print(literal(f"  • [{f.category}]{mitre} {f.detail}"))
            if f.advice:
                console.print(literal(f"    advice: {f.advice}"))

    if info:
        t4 = Table(title="Informational")
        t4.add_column("Category")
        t4.add_column("Title")
        t4.add_column("MITRE")
        for f in info:
            t4.add_row(literal(f.category), literal(f.title), literal(f.mitre or "-"))
        console.print(t4)
