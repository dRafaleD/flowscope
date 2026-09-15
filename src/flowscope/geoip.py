from __future__ import annotations

import ipaddress
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from flowscope.models import AnalysisReport, Finding
from flowscope.scoring import aggregate_score


@dataclass
class IpGeo:
    ip: str
    country_code: str | None = None
    country_name: str | None = None
    is_private: bool = False
    is_loopback: bool = False
    network_label: str | None = None  # e.g. TEST-NET, RFC1918


def _documentation_net_label(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str | None:
    if not isinstance(ip, ipaddress.IPv4Address):
        return None
    if ip in ipaddress.ip_network("192.0.2.0/24"):
        return "TEST-NET-1 (documentation)"
    if ip in ipaddress.ip_network("198.51.100.0/24"):
        return "TEST-NET-2 (documentation)"
    if ip in ipaddress.ip_network("203.0.113.0/24"):
        return "TEST-NET-3 (documentation)"
    return None


def _classify_special(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str | None:
    doc = _documentation_net_label(ip)
    if doc:
        return doc
    if ip.is_private:
        return "RFC1918 / private"
    if ip.is_loopback:
        return "loopback"
    if ip.is_link_local:
        return "link-local"
    if ip.is_multicast:
        return "multicast"
    if ip.is_reserved:
        return "reserved"
    return None


def classify_ip(ip_str: str) -> IpGeo:
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return IpGeo(ip=ip_str, network_label="invalid")
    label = _classify_special(ip)
    doc = _documentation_net_label(ip) if isinstance(ip, ipaddress.IPv4Address) else None
    return IpGeo(
        ip=ip_str,
        is_private=ip.is_private and not doc,
        is_loopback=ip.is_loopback,
        network_label=label,
    )


class GeoIpResolver:
    """Optional MaxMind Country/City MMDB lookup."""

    def __init__(self, mmdb_path: str | Path) -> None:
        path = Path(mmdb_path)
        if not path.is_file():
            raise FileNotFoundError(f"GeoIP database not found: {path}")
        try:
            import maxminddb  # type: ignore[import-untyped]
        except ImportError as exc:
            raise ImportError(
                "GeoIP requires maxminddb. Install with: pip install maxminddb"
            ) from exc
        self._reader = maxminddb.open_database(str(path))

    def close(self) -> None:
        self._reader.close()

    def lookup(self, ip_str: str) -> IpGeo:
        base = classify_ip(ip_str)
        if base.network_label and "TEST-NET" in base.network_label:
            return base
        if base.is_private or base.is_loopback:
            return base
        record = self._reader.get(ip_str)
        if not record:
            return base
        country = record.get("country") or {}
        code = country.get("iso_code")
        name = country.get("names", {}).get("en")
        base.country_code = code
        base.country_name = name
        return base


def collect_report_ips(report: AnalysisReport) -> set[str]:
    ips: set[str] = set()
    for ip, _pkts, _byts in report.top_ips:
        ips.add(ip)
    for e in report.tls_sni_events:
        ips.add(e.src)
        ips.add(e.dst)
    for c in report.tcp_connections:
        ips.add(c.src)
        ips.add(c.dst)
    return ips


def build_geo_map(ips: set[str], resolver: GeoIpResolver | None) -> dict[str, IpGeo]:
    out: dict[str, IpGeo] = {}
    for ip in ips:
        if resolver is not None:
            out[ip] = resolver.lookup(ip)
        else:
            out[ip] = classify_ip(ip)
    return out


def geo_map_to_meta(geo: dict[str, IpGeo]) -> dict[str, dict[str, Any]]:
    return {ip: asdict(info) for ip, info in geo.items()}


def geo_findings(report: AnalysisReport, geo: dict[str, IpGeo]) -> list[Finding]:
    from collections import Counter

    findings: list[Finding] = []
    country_hits: Counter[str] = Counter()

    for ip, info in geo.items():
        if info.country_code:
            country_hits[info.country_code] += 1

    if country_hits:
        findings.append(
            Finding(
                category="geoip",
                severity="low",
                title="GeoIP country summary",
                detail=f"Observed public IPs map to {len(country_hits)} country code(s).",
                score_delta=0,
                evidence={
                    "countries": country_hits.most_common(20),
                    "note": "Requires MaxMind GeoLite2/GeoIP2 MMDB when using --geoip",
                },
            )
        )

    for e in report.tls_sni_events:
        dst_geo = geo.get(e.dst)
        if not dst_geo or not dst_geo.country_code:
            continue
        src_geo = geo.get(e.src)
        if src_geo and (src_geo.is_private or src_geo.network_label):
            findings.append(
                Finding(
                    category="geoip",
                    severity="low",
                    title="TLS to foreign country",
                    detail=(
                        f"{e.src} -> {e.dst} ({e.sni or 'no SNI'}) "
                        f"destination country: {dst_geo.country_name or dst_geo.country_code}"
                    ),
                    score_delta=5,
                    evidence={
                        "src": e.src,
                        "dst": e.dst,
                        "sni": e.sni,
                        "country_code": dst_geo.country_code,
                        "country_name": dst_geo.country_name,
                    },
                    mitre="T1573",
                    advice="Confirm a business reason for this destination country.",
                )
            )

    doc_nets = {
        info.ip
        for info in geo.values()
        if info.network_label and "TEST-NET" in (info.network_label or "")
    }
    if doc_nets:
        findings.append(
            Finding(
                category="geoip",
                severity="low",
                title="Documentation / lab address space",
                detail=f"IPs in RFC5737 TEST-NET ranges: {', '.join(sorted(doc_nets)[:10])}",
                score_delta=0,
                evidence={"ips": sorted(doc_nets)},
            )
        )

    return findings


def enrich_with_geo(report: AnalysisReport, mmdb_path: str | Path | None) -> AnalysisReport:
    resolver: GeoIpResolver | None = None
    if mmdb_path:
        resolver = GeoIpResolver(mmdb_path)
    try:
        ips = collect_report_ips(report)
        geo = build_geo_map(ips, resolver)
        report.meta["geoip"] = geo_map_to_meta(geo)
        report.meta["geoip_enabled"] = bool(mmdb_path)
        report.findings.extend(geo_findings(report, geo))
        report.risk_score = aggregate_score(report.findings)
    finally:
        if resolver is not None:
            resolver.close()
    return report
