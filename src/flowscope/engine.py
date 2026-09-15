from __future__ import annotations

from pathlib import Path

from flowscope.detectors import run_detectors
from flowscope.geoip import enrich_with_geo
from flowscope.models import AnalysisReport
from flowscope.pcap_loader import load_pcap
from flowscope.scoring import aggregate_score, scored_finding_count


def analyze_pcap(path: str, geoip_mmdb: str | Path | None = None) -> AnalysisReport:
    parsed = load_pcap(path)
    duration = max(parsed.last_ts - parsed.first_ts, 0.0)
    findings, top_ips, meta, tcp_top = run_detectors(parsed)
    report = AnalysisReport(
        pcap_path=path,
        packet_count=parsed.packet_count,
        duration_seconds=duration,
        dns_queries=parsed.dns_queries,
        http_events=parsed.http_events,
        tls_sni_events=parsed.tls_sni_events,
        tcp_connections=tcp_top,
        top_ips=top_ips,
        findings=findings,
        risk_score=aggregate_score(findings),
        meta=meta,
    )
    report = enrich_with_geo(report, geoip_mmdb)
    report.meta["scored_finding_count"] = scored_finding_count(report.findings)
    report.risk_score = aggregate_score(report.findings)
    return report
