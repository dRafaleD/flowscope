from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class DnsQuery:
    ts: float
    src: str
    dst: str
    qname: str
    qtype: str
    rcode: int | None = None
    is_response: bool = False


@dataclass
class TlsSniEvent:
    ts: float
    src: str
    dst: str
    dport: int
    sni: str | None
    tls_version: str
    cipher_suites: int
    ja3_hash: str | None = None
    ja3_string: str | None = None
    ja4: str | None = None
    ja3s_hash: str | None = None
    ja3s_string: str | None = None
    server_tls_version: str | None = None


@dataclass
class HttpEvent:
    ts: float
    src: str
    dst: str
    method: str
    uri: str
    host: str
    has_body: bool


@dataclass
class TcpConnection:
    src: str
    sport: int
    dst: str
    dport: int
    packets: int = 0
    bytes: int = 0
    first_ts: float = 0.0
    last_ts: float = 0.0
    syn_count: int = 0


@dataclass
class Finding:
    category: str
    severity: str  # low | medium | high | critical
    title: str
    detail: str
    score_delta: int
    evidence: dict[str, Any] = field(default_factory=dict)
    mitre: str | None = None
    advice: str | None = None


@dataclass
class AnalysisReport:
    pcap_path: str
    packet_count: int
    duration_seconds: float
    dns_queries: list[DnsQuery] = field(default_factory=list)
    http_events: list[HttpEvent] = field(default_factory=list)
    tls_sni_events: list[TlsSniEvent] = field(default_factory=list)
    tcp_connections: list[TcpConnection] = field(default_factory=list)
    top_ips: list[tuple[str, int, int]] = field(default_factory=list)  # ip, packets, bytes
    findings: list[Finding] = field(default_factory=list)
    risk_score: int = 0
    meta: dict[str, Any] = field(default_factory=dict)
