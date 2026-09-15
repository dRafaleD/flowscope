from __future__ import annotations

import ipaddress
import math
import statistics
from collections import Counter, defaultdict
from typing import Any

from flowscope.ja3_catalog import label_for_ja3
from flowscope.models import Finding, TcpConnection, TlsSniEvent
from flowscope.pcap_loader import ParsedPcap

_COMMON_PORTS = {
    20, 21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 3306, 3389, 8080, 8443,
}

_DNS_BURST_THRESHOLD = 50  # queries in 10s window per source
_SCAN_UNIQUE_PORTS = 15
_SCAN_WINDOW_SEC = 30.0
_BEACON_MIN_PACKETS = 8
_BEACON_MAX_CV = 0.15
_BEACON_MIN_INTERVAL = 1.0
_DNS_ENTROPY_MIN_LEN = 24
_DNS_ENTROPY_THRESHOLD = 3.5

_ADVICE_BY_TITLE = {
    "High DNS query rate": "Hunt for DNS tunneling or a misconfigured client; rate-limit the source if unexpected.",
    "High NXDOMAIN rate": "NXDOMAIN bursts can indicate DGA malware; check the querying host.",
    "High-entropy DNS names": "High-entropy labels often mean encoding or tunneling; inspect the resolver logs.",
    "Possible vertical port scan": "Confirm this is an authorized scan; otherwise block the source at the firewall.",
    "Possible horizontal scan": "Same port across many hosts is typical reconnaissance; contain if unplanned.",
    "Uncommon destination port": "Verify the service on this port is expected for the destination.",
    "Beacon-like periodic traffic": "Regular intervals may be C2; correlate with SNI/JA3 and host process telemetry.",
    "TLS without SNI": "Unusual for browsers; review the client application.",
    "SNI hostname to IP destination": "Common with CDNs; confirm destination reputation and certificate name.",
    "One JA3 fingerprint to many destinations": "One TLS stack talking to many hosts; review for scanners or malware.",
    "Many distinct SNI values from one host": "High SNI diversity can be browsing or staging; baseline the host.",
    "TLS to foreign country": "Confirm a business reason for this destination country.",
}

_ADVICE_PREFIXES = (
    ("Plaintext credential risk", "Stop using cleartext auth; switch to TLS and rotate any captured credentials."),
)


def _attach_advice(findings: list[Finding]) -> list[Finding]:
    for finding in findings:
        if finding.score_delta <= 0 or finding.advice:
            continue
        finding.advice = _ADVICE_BY_TITLE.get(finding.title)
        if finding.advice:
            continue
        for prefix, text in _ADVICE_PREFIXES:
            if finding.title.startswith(prefix):
                finding.advice = text
                break
    return findings


def _top_ips(ip_stats: dict[str, tuple[int, int]], limit: int = 15) -> list[tuple[str, int, int]]:
    ranked = sorted(ip_stats.items(), key=lambda x: x[1][0], reverse=True)
    return [(ip, p, b) for ip, (p, b) in ranked[:limit]]


def _shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    length = len(text)
    return -sum((n / length) * math.log2(n / length) for n in counts.values())


def _detect_dns_flood(parsed: ParsedPcap, duration: float) -> list[Finding]:
    findings: list[Finding] = []
    queries = [q for q in parsed.dns_queries if not q.is_response]
    responses = [q for q in parsed.dns_queries if q.is_response]
    if not queries and not responses:
        return findings

    by_src: Counter[str] = Counter(q.src for q in queries)
    qps_by_src = {src: count / max(duration, 1.0) for src, count in by_src.items()}

    window = 10.0
    buckets: dict[str, list[float]] = defaultdict(list)
    for q in queries:
        buckets[q.src].append(q.ts)
    for src, times in buckets.items():
        times.sort()
        left = 0
        max_in_window = 0
        for right, t1 in enumerate(times):
            while times[left] < t1 - window:
                left += 1
            max_in_window = max(max_in_window, right - left + 1)
        if max_in_window >= _DNS_BURST_THRESHOLD:
            findings.append(
                Finding(
                    category="dns",
                    severity="high",
                    title="High DNS query rate",
                    detail=f"Source {src} sent {max_in_window} DNS queries within {window:.0f}s.",
                    score_delta=25,
                    evidence={"src": src, "max_in_window": max_in_window, "avg_qps": qps_by_src.get(src, 0)},
                    mitre="T1071.004",
                )
            )

    nx = parsed.dns_nxdomain_count
    if responses and nx / max(len(responses), 1) >= 0.4 and nx >= 10:
        findings.append(
            Finding(
                category="dns",
                severity="medium",
                title="High NXDOMAIN rate",
                detail=f"{nx}/{len(responses)} DNS responses were NXDOMAIN.",
                score_delta=15,
                evidence={"nxdomain": nx, "responses": len(responses)},
                mitre="T1071.004",
            )
        )

    high_entropy: list[str] = []
    for q in queries:
        labels = q.qname.replace(".", "")
        if len(q.qname) >= _DNS_ENTROPY_MIN_LEN and _shannon_entropy(labels.lower()) >= _DNS_ENTROPY_THRESHOLD:
            high_entropy.append(q.qname)
    unique_entropy = sorted(set(high_entropy))
    if len(unique_entropy) >= 5:
        findings.append(
            Finding(
                category="dns",
                severity="medium",
                title="High-entropy DNS names",
                detail=f"{len(unique_entropy)} distinct query names look encoded or tunneled.",
                score_delta=15,
                evidence={"sample": unique_entropy[:15]},
                mitre="T1071.004",
            )
        )

    top_domains = Counter(q.qname.lower() for q in queries).most_common(10)
    findings.append(
        Finding(
            category="dns",
            severity="low",
            title="DNS summary",
            detail=(
                f"{len(queries)} queries, {len(responses)} responses "
                f"({nx} NXDOMAIN) from {len(by_src)} clients."
            ),
            score_delta=0,
            evidence={"top_domains": top_domains, "queries_per_source": dict(by_src.most_common(10))},
        )
    )
    return findings


def _detect_port_scan(parsed: ParsedPcap) -> list[Finding]:
    findings: list[Finding] = []
    syn_map: dict[tuple[str, str], list[tuple[float, int]]] = defaultdict(list)
    for ts, src, dst, dport in parsed.syn_events:
        syn_map[(src, dst)].append((ts, dport))

    for (src, dst), events in syn_map.items():
        events.sort(key=lambda x: x[0])
        left = 0
        ports_in_window: dict[int, int] = {}
        for ts, dport in events:
            ports_in_window[dport] = ports_in_window.get(dport, 0) + 1
            while events[left][0] < ts - _SCAN_WINDOW_SEC:
                old_port = events[left][1]
                ports_in_window[old_port] -= 1
                if ports_in_window[old_port] <= 0:
                    del ports_in_window[old_port]
                left += 1
            if len(ports_in_window) >= _SCAN_UNIQUE_PORTS:
                findings.append(
                    Finding(
                        category="scan",
                        severity="high",
                        title="Possible vertical port scan",
                        detail=(
                            f"{src} probed {len(ports_in_window)} ports on {dst} "
                            f"within {_SCAN_WINDOW_SEC:.0f}s."
                        ),
                        score_delta=30,
                        evidence={"src": src, "dst": dst, "ports_sample": sorted(ports_in_window)[:25]},
                        mitre="T1046",
                    )
                )
                break

    horiz: dict[tuple[str, int], set[str]] = defaultdict(set)
    for ts, src, dst, dport in parsed.syn_events:
        horiz[(src, dport)].add(dst)
    for (src, dport), dsts in horiz.items():
        if len(dsts) >= 10:
            findings.append(
                Finding(
                    category="scan",
                    severity="medium",
                    title="Possible horizontal scan",
                    detail=f"{src} sent SYN to port {dport} on {len(dsts)} hosts.",
                    score_delta=20,
                    evidence={"src": src, "dport": dport, "dst_count": len(dsts)},
                    mitre="T1046",
                )
            )
    return findings


def _detect_unusual_ports(connections: dict[tuple[str, int, str, int], TcpConnection]) -> list[Finding]:
    findings: list[Finding] = []
    unusual: Counter[tuple[int, str]] = Counter()
    for conn in connections.values():
        if conn.dport not in _COMMON_PORTS and conn.dport > 1024:
            unusual[(conn.dport, conn.dst)] += conn.packets

    for (dport, dst), count in unusual.most_common(15):
        if count < 3:
            continue
        findings.append(
            Finding(
                category="ports",
                severity="low",
                title="Uncommon destination port",
                detail=f"Traffic to {dst}:{dport} ({count} packets).",
                score_delta=5,
                evidence={"dst": dst, "dport": dport, "packets": count},
            )
        )
    return findings[:10]


def _detect_beaconing(flow_timestamps: dict[tuple[str, str, int], list[float]]) -> list[Finding]:
    findings: list[Finding] = []
    for (src, dst, dport), times in flow_timestamps.items():
        unique = sorted(set(times))
        if len(unique) < _BEACON_MIN_PACKETS:
            continue
        intervals = [
            unique[i + 1] - unique[i]
            for i in range(len(unique) - 1)
            if unique[i + 1] - unique[i] >= _BEACON_MIN_INTERVAL
        ]
        if len(intervals) < _BEACON_MIN_PACKETS - 1:
            continue
        mean = statistics.mean(intervals)
        if mean < 5.0:
            continue
        try:
            stdev = statistics.stdev(intervals)
        except statistics.StatisticsError:
            continue
        cv = stdev / mean
        if cv <= _BEACON_MAX_CV:
            findings.append(
                Finding(
                    category="beacon",
                    severity="medium",
                    title="Beacon-like periodic traffic",
                    detail=(
                        f"{src} -> {dst}:{dport} shows regular intervals "
                        f"(mean {mean:.1f}s, CV {cv:.3f})."
                    ),
                    score_delta=20,
                    evidence={
                        "src": src,
                        "dst": dst,
                        "dport": dport,
                        "mean_interval_sec": round(mean, 2),
                        "cv": round(cv, 4),
                        "samples": len(unique),
                    },
                    mitre="T1071",
                )
            )
    return findings[:8]


def _detect_credentials(hits: list[dict]) -> list[Finding]:
    findings: list[Finding] = []
    seen: set[tuple[str, str, str]] = set()
    for h in hits:
        key = (h["proto"], h["src"], h["dst"])
        if key in seen:
            continue
        seen.add(key)
        sev = "critical" if h["proto"] in ("FTP", "TELNET", "HTTP-Basic") else "high"
        delta = 35 if sev == "critical" else 20
        findings.append(
            Finding(
                category="credentials",
                severity=sev,
                title=f"Plaintext credential risk ({h['proto']})",
                detail=f"{h['src']} -> {h['dst']}: {h['snippet']}",
                score_delta=delta,
                evidence=h,
                mitre="T1040",
            )
        )
        if len(findings) >= 20:
            break
    return findings


def _is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _detect_tls_sni(events: list[TlsSniEvent], dns_queries: list) -> list[Finding]:
    findings: list[Finding] = []
    if not events:
        return findings

    sni_counter = Counter((e.sni or "(no SNI)").lower() for e in events)
    version_counter = Counter(e.tls_version for e in events)
    ja3_counter = Counter(e.ja3_hash for e in events if e.ja3_hash)
    ja3s_counter = Counter(e.ja3s_hash for e in events if e.ja3s_hash)
    ja4_counter = Counter(e.ja4 for e in events if e.ja4)

    ja3_breakdown: list[dict] = []
    for ja3_hash, count in ja3_counter.most_common(20):
        label = label_for_ja3(ja3_hash)
        sample = next(e for e in events if e.ja3_hash == ja3_hash)
        ja3_breakdown.append(
            {
                "ja3_hash": ja3_hash,
                "count": count,
                "label": label,
                "ja3_string": sample.ja3_string,
            }
        )

    findings.append(
        Finding(
            category="tls",
            severity="low",
            title="TLS ClientHello / SNI summary",
            detail=f"{len(events)} ClientHello record(s) parsed (metadata only, no decryption).",
            score_delta=0,
            evidence={
                "top_sni": sni_counter.most_common(15),
                "tls_versions": dict(version_counter),
                "ja3_fingerprints": ja3_breakdown,
                "ja3s_fingerprints": [
                    {"ja3s_hash": h, "count": c} for h, c in ja3s_counter.most_common(15)
                ],
                "ja4_fingerprints": [
                    {"ja4": j, "count": c} for j, c in ja4_counter.most_common(15)
                ],
                "sessions": [
                    {
                        "src": e.src,
                        "dst": f"{e.dst}:{e.dport}",
                        "sni": e.sni,
                        "version": e.tls_version,
                        "ja3_hash": e.ja3_hash,
                        "ja3s_hash": e.ja3s_hash,
                        "ja4": e.ja4,
                    }
                    for e in events[:50]
                ],
            },
        )
    )

    for e in events:
        if e.ja3_hash and e.ja3s_hash:
            findings.append(
                Finding(
                    category="tls",
                    severity="low",
                    title="TLS handshake fingerprint pair",
                    detail=(
                        f"{e.src} -> {e.dst}:{e.dport} JA3={e.ja3_hash} / JA3S={e.ja3s_hash}"
                        + (f" / JA4={e.ja4}" if e.ja4 else "")
                    ),
                    score_delta=0,
                    evidence={
                        "ja3": e.ja3_hash,
                        "ja3s": e.ja3s_hash,
                        "ja4": e.ja4,
                        "sni": e.sni,
                    },
                    mitre="T1573",
                )
            )

    for ja3_hash, count in ja3_counter.items():
        label = label_for_ja3(ja3_hash)
        if label:
            findings.append(
                Finding(
                    category="tls",
                    severity="low",
                    title="JA3 catalog match",
                    detail=f"JA3 {ja3_hash} matched reference label: {label} ({count} session(s)).",
                    score_delta=0,
                    evidence={"ja3_hash": ja3_hash, "label": label, "count": count},
                )
            )

    for ja3s_hash, count in ja3s_counter.items():
        label = label_for_ja3(ja3s_hash)
        if label:
            findings.append(
                Finding(
                    category="tls",
                    severity="low",
                    title="JA3S catalog match",
                    detail=f"JA3S {ja3s_hash} matched reference label: {label} ({count} session(s)).",
                    score_delta=0,
                    evidence={"ja3s_hash": ja3s_hash, "label": label, "count": count},
                )
            )

    by_src_ja3: dict[tuple[str, str], set[str]] = defaultdict(set)
    for e in events:
        if e.ja3_hash:
            by_src_ja3[(e.src, e.ja3_hash)].add(f"{e.dst}:{e.dport}")
    for (src, ja3_hash), dsts in by_src_ja3.items():
        if len(dsts) >= 3:
            findings.append(
                Finding(
                    category="tls",
                    severity="medium",
                    title="One JA3 fingerprint to many destinations",
                    detail=f"{src} used JA3 {ja3_hash} toward {len(dsts)} different endpoints.",
                    score_delta=8,
                    evidence={"src": src, "ja3_hash": ja3_hash, "destinations": sorted(dsts)[:30]},
                    mitre="T1573",
                )
            )

    dns_names = {q.qname.lower().rstrip(".") for q in dns_queries if not q.is_response}
    for e in events:
        if not e.sni:
            findings.append(
                Finding(
                    category="tls",
                    severity="low",
                    title="TLS without SNI",
                    detail=f"{e.src} -> {e.dst}:{e.dport} ClientHello had no Server Name Indication.",
                    score_delta=5,
                    evidence={"src": e.src, "dst": e.dst, "dport": e.dport},
                    mitre="T1573",
                )
            )
            continue

        sni_norm = e.sni.lower().rstrip(".")
        if _is_ip_literal(e.dst) and not _is_ip_literal(sni_norm):
            findings.append(
                Finding(
                    category="tls",
                    severity="medium",
                    title="SNI hostname to IP destination",
                    detail=(
                        f"{e.src} connected to {e.dst} but SNI is {e.sni!r} "
                        "(common for CDN, verify context)."
                    ),
                    score_delta=10,
                    evidence={"src": e.src, "dst": e.dst, "sni": e.sni},
                    mitre="T1573",
                )
            )

        if dns_names and sni_norm not in dns_names:
            findings.append(
                Finding(
                    category="tls",
                    severity="low",
                    title="SNI not seen in DNS (this capture)",
                    detail=f"SNI {e.sni!r} was not queried in observed DNS traffic.",
                    score_delta=0,
                    evidence={"sni": e.sni, "dst": e.dst},
                )
            )

    by_src: dict[str, set[str]] = defaultdict(set)
    for e in events:
        if e.sni:
            by_src[e.src].add(e.sni.lower())
    for src, snis in by_src.items():
        if len(snis) >= 8:
            findings.append(
                Finding(
                    category="tls",
                    severity="medium",
                    title="Many distinct SNI values from one host",
                    detail=f"{src} used {len(snis)} different SNI hostnames in this capture.",
                    score_delta=12,
                    evidence={"src": src, "sni_count": len(snis), "sample": sorted(snis)[:20]},
                    mitre="T1573",
                )
            )

    return findings


def _http_summary(events: list) -> Finding | None:
    if not events:
        return None
    hosts = Counter(e.host or e.dst for e in events)
    methods = Counter(e.method for e in events)
    return Finding(
        category="http",
        severity="low",
        title="HTTP traffic summary",
        detail=f"{len(events)} HTTP requests observed (cleartext).",
        score_delta=0,
        evidence={"top_hosts": hosts.most_common(10), "methods": dict(methods)},
    )


def run_detectors(
    parsed: ParsedPcap,
) -> tuple[list[Finding], list[tuple[str, int, int]], dict[str, Any], list]:
    duration = max(parsed.last_ts - parsed.first_ts, 0.001)
    findings: list[Finding] = []

    http_f = _http_summary(parsed.http_events)
    if http_f:
        findings.append(http_f)

    findings.extend(_detect_dns_flood(parsed, duration))
    findings.extend(_detect_port_scan(parsed))
    findings.extend(_detect_unusual_ports(parsed.connections))
    findings.extend(_detect_beaconing(parsed.flow_timestamps))
    findings.extend(_detect_credentials(parsed.credential_hits))
    findings.extend(_detect_tls_sni(parsed.tls_sni_events, parsed.dns_queries))

    top_ips = _top_ips(parsed.ip_stats)

    tcp_list = sorted(
        parsed.connections.values(),
        key=lambda c: c.packets,
        reverse=True,
    )[:30]

    query_count = sum(1 for q in parsed.dns_queries if not q.is_response)
    meta: dict[str, Any] = {
        "duration_seconds": round(duration, 3),
        "tcp_connection_count": len(parsed.connections),
        "dns_query_count": query_count,
        "dns_response_count": sum(1 for q in parsed.dns_queries if q.is_response),
        "dns_nxdomain_count": parsed.dns_nxdomain_count,
        "http_request_count": len(parsed.http_events),
        "syn_count": len(parsed.syn_events),
        "tls_client_hello_count": len(parsed.tls_sni_events),
        "top_dns_domains": Counter(
            q.qname.lower() for q in parsed.dns_queries if not q.is_response
        ).most_common(10),
    }
    return _attach_advice(findings), top_ips, meta, tcp_list
