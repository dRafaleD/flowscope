from __future__ import annotations

import socket
from dataclasses import dataclass

import dpkt

from flowscope.frames import CaptureError, DLT_EN10MB, decode_l3
from flowscope.models import DnsQuery, HttpEvent, TcpConnection, TlsSniEvent
from flowscope.tls_sni import (
    _MAX_FLOW_BUFFER,
    _TLS_PORTS,
    extract_tls_client_hello,
    extract_tls_server_hello,
    should_buffer_tls,
)

_HTTP_PREFIXES = (b"GET ", b"POST ", b"HEAD ", b"PUT ", b"DELETE ", b"PATCH ", b"OPTIONS ")
_PCAP_MAGICS = {
    b"\xd4\xc3\xb2\xa1",
    b"\xa1\xb2\xc3\xd4",
    b"\x4d\x3c\xb2\xa1",
    b"\xa1\xb2\x3c\x4d",
}
_PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"

_DNS_TYPES = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    33: "SRV",
    255: "ANY",
}


@dataclass
class ParsedPcap:
    packet_count: int
    first_ts: float
    last_ts: float
    dns_queries: list[DnsQuery]
    http_events: list[HttpEvent]
    connections: dict[tuple[str, int, str, int], TcpConnection]
    ip_stats: dict[str, tuple[int, int]]  # packets, bytes
    syn_events: list[tuple[float, str, str, int]]  # ts, src, dst, dport
    flow_timestamps: dict[tuple[str, str, int], list[float]]  # src, dst, dport -> ts list
    credential_hits: list[dict]
    tls_sni_events: list[TlsSniEvent]
    dns_nxdomain_count: int = 0


def _looks_like_http_request(payload: bytes) -> bool:
    return any(payload.startswith(prefix) for prefix in _HTTP_PREFIXES)


def _http_header(headers, name: str) -> str:
    """Read a header from dpkt (string or bytes keys, string or bytes values)."""
    if not headers:
        return ""
    raw = None
    for key in (name, name.lower(), name.encode("ascii"), name.lower().encode("ascii")):
        if key in headers:
            raw = headers[key]
            break
    if raw is None:
        want = name.lower()
        for key, value in headers.items():
            label = key.decode("ascii", errors="replace") if isinstance(key, bytes) else str(key)
            if label.lower() == want:
                raw = value
                break
    if raw is None:
        return ""
    if isinstance(raw, (list, tuple)):
        raw = raw[0] if raw else ""
    if isinstance(raw, bytes):
        return raw.decode(errors="replace").strip()
    return str(raw).strip()


def _ip(addr: bytes) -> str:
    return socket.inet_ntop(socket.AF_INET, addr)


def _ip6(addr: bytes) -> str:
    return socket.inet_ntop(socket.AF_INET6, addr)


def _iter_packets(path: str):
    try:
        handle = open(path, "rb")
    except OSError as exc:
        raise CaptureError(f"cannot open capture: {path}") from exc
    try:
        magic = handle.read(4)
        handle.seek(0)
        if magic in _PCAP_MAGICS:
            reader = dpkt.pcap.Reader(handle)
        elif magic == _PCAPNG_MAGIC:
            reader = dpkt.pcapng.Reader(handle)
        else:
            try:
                reader = dpkt.pcap.Reader(handle)
            except (ValueError, dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError) as exc:
                handle.seek(0)
                try:
                    reader = dpkt.pcapng.Reader(handle)
                except Exception as exc2:
                    raise CaptureError("unsupported capture (not pcap or pcapng)") from exc2
        try:
            dlt = int(reader.datalink())
        except Exception:
            dlt = DLT_EN10MB
        for ts, buf in reader:
            yield dlt, ts, buf
    except CaptureError:
        raise
    except (ValueError, dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError, OSError) as exc:
        raise CaptureError("unsupported or corrupt capture") from exc
    finally:
        handle.close()


def _parse_dns(ts: float, src: str, dst: str, data: bytes) -> list[DnsQuery]:
    out: list[DnsQuery] = []
    try:
        dns = dpkt.dns.DNS(data)
    except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError, ValueError):
        return out
    is_response = dns.qr != dpkt.dns.DNS_Q
    rcode = int(dns.rcode) if is_response else None
    questions = dns.qd or []
    for q in questions:
        name = q.name.decode(errors="replace") if isinstance(q.name, bytes) else str(q.name)
        qtype = _DNS_TYPES.get(q.type, str(q.type))
        out.append(
            DnsQuery(
                ts=ts,
                src=src,
                dst=dst,
                qname=name.rstrip("."),
                qtype=qtype,
                rcode=rcode,
                is_response=is_response,
            )
        )
    return out


def _parse_http(ts: float, src: str, dst: str, tcp: dpkt.tcp.TCP) -> HttpEvent | None:
    payload = bytes(tcp.data or b"")
    if tcp.dport != 80 and tcp.sport != 80 and not _looks_like_http_request(payload):
        return None
    try:
        req = dpkt.http.Request(tcp.data)
    except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError, ValueError):
        return None
    host = _http_header(req.headers, "host")
    uri = req.uri.decode(errors="replace") if isinstance(req.uri, bytes) else str(req.uri)
    method = req.method.decode(errors="replace") if isinstance(req.method, bytes) else str(req.method)
    return HttpEvent(
        ts=ts,
        src=src,
        dst=dst,
        method=method,
        uri=uri,
        host=host,
        has_body=bool(req.body),
    )


def _redact_ftp_line(line: str) -> str:
    upper = line.upper()
    if upper.startswith("PASS "):
        return "PASS [redacted]"
    if upper.startswith("USER "):
        parts = line.split(" ", 1)
        user = parts[1][:32] if len(parts) > 1 else ""
        return f"USER {user}"
    return line[:120]


def _credential_scan(ts: float, src: str, dst: str, sport: int, dport: int, payload: bytes) -> list[dict]:
    hits: list[dict] = []
    if not payload:
        return hits
    text = payload.decode("latin-1", errors="ignore")
    upper = text[:512].upper()

    if dport == 21 or sport == 21:
        for line in text.split("\r\n")[:5]:
            if line.upper().startswith("USER ") or line.upper().startswith("PASS "):
                hits.append(
                    {
                        "ts": ts,
                        "proto": "FTP",
                        "src": src,
                        "dst": dst,
                        "snippet": _redact_ftp_line(line),
                    }
                )

    if dport == 23 or sport == 23:
        if len(text.strip()) > 0:
            hits.append(
                {
                    "ts": ts,
                    "proto": "TELNET",
                    "src": src,
                    "dst": dst,
                    "snippet": "[telnet payload redacted]",
                }
            )

    if b"authorization: basic " in payload.lower():
        hits.append(
            {
                "ts": ts,
                "proto": "HTTP-Basic",
                "src": src,
                "dst": dst,
                "snippet": "Authorization: Basic [redacted]",
            }
        )

    if " PASSWORD=" in upper or " PASSWD=" in upper or " PWD=" in upper:
        hits.append(
            {
                "ts": ts,
                "proto": "HTTP-Form",
                "src": src,
                "dst": dst,
                "snippet": "Possible password field in cleartext HTTP body",
            }
        )

    return hits


def load_pcap(path: str) -> ParsedPcap:
    dns_queries: list[DnsQuery] = []
    http_events: list[HttpEvent] = []
    connections: dict[tuple[str, int, str, int], TcpConnection] = {}
    ip_stats: dict[str, tuple[int, int]] = {}
    syn_events: list[tuple[float, str, str, int]] = []
    flow_timestamps: dict[tuple[str, str, int], list[float]] = {}
    credential_hits: list[dict] = []
    tls_by_flow: dict[tuple[str, int, str, int], TlsSniEvent] = {}
    tls_client_buffers: dict[tuple[str, int, str, int], bytes] = {}
    tls_server_buffers: dict[tuple[str, int, str, int], bytes] = {}
    tls_client_seen: set[tuple[str, int, str, int]] = set()
    tls_server_seen: set[tuple[str, int, str, int]] = set()
    dns_nxdomain_count = 0

    packet_count = 0
    first_ts: float | None = None
    last_ts: float | None = None

    for dlt, ts, buf in _iter_packets(path):
        packet_count += 1
        if first_ts is None or ts < first_ts:
            first_ts = ts
        if last_ts is None or ts > last_ts:
            last_ts = ts

        ip = decode_l3(buf, dlt)
        if ip is None:
            continue
        if isinstance(ip, dpkt.ip6.IP6):
            src_ip = _ip6(ip.src)
            dst_ip = _ip6(ip.dst)
        elif isinstance(ip, dpkt.ip.IP):
            src_ip = _ip(ip.src)
            dst_ip = _ip(ip.dst)
        else:
            continue

        plen = len(buf)
        for endpoint in (src_ip, dst_ip):
            pkts, byts = ip_stats.get(endpoint, (0, 0))
            ip_stats[endpoint] = (pkts + 1, byts + plen)

        if isinstance(ip.data, dpkt.udp.UDP):
            udp = ip.data
            if udp.dport == 53 or udp.sport == 53:
                parsed_dns = _parse_dns(ts, src_ip, dst_ip, udp.data)
                dns_queries.extend(parsed_dns)
                dns_nxdomain_count += sum(1 for q in parsed_dns if q.rcode == 3)

        if isinstance(ip.data, dpkt.tcp.TCP):
            tcp = ip.data
            payload = bytes(tcp.data or b"")
            key = (src_ip, tcp.sport, dst_ip, tcp.dport)
            conn = connections.get(key)
            if conn is None:
                conn = TcpConnection(
                    src=src_ip,
                    sport=tcp.sport,
                    dst=dst_ip,
                    dport=tcp.dport,
                    first_ts=ts,
                    last_ts=ts,
                )
                connections[key] = conn
            conn.packets += 1
            conn.bytes += len(tcp.data)
            conn.last_ts = ts

            is_syn = bool(tcp.flags & dpkt.tcp.TH_SYN) and not (tcp.flags & dpkt.tcp.TH_ACK)
            if is_syn:
                conn.syn_count += 1
                syn_events.append((ts, src_ip, dst_ip, tcp.dport))

            flow_key = (src_ip, dst_ip, tcp.dport)
            flow_timestamps.setdefault(flow_key, []).append(ts)

            evt = _parse_http(ts, src_ip, dst_ip, tcp)
            if evt:
                http_events.append(evt)

            credential_hits.extend(
                _credential_scan(ts, src_ip, dst_ip, tcp.sport, tcp.dport, tcp.data)
            )

            flow_tls = (src_ip, tcp.sport, dst_ip, tcp.dport)
            if should_buffer_tls(payload, tcp.dport in _TLS_PORTS, flow_tls in tls_client_buffers):
                if flow_tls not in tls_client_seen:
                    tls_buf = tls_client_buffers.get(flow_tls, b"") + payload
                    if len(tls_buf) > _MAX_FLOW_BUFFER:
                        tls_buf = tls_buf[-_MAX_FLOW_BUFFER:]
                    parsed_hello = extract_tls_client_hello(tls_buf)
                    if parsed_hello is not None:
                        tls_client_seen.add(flow_tls)
                        tls_client_buffers.pop(flow_tls, None)
                        tls_by_flow[flow_tls] = TlsSniEvent(
                            ts=ts,
                            src=src_ip,
                            dst=dst_ip,
                            dport=tcp.dport,
                            sni=parsed_hello.get("sni"),
                            tls_version=parsed_hello["tls_version"],
                            cipher_suites=int(parsed_hello.get("cipher_suites", 0)),
                            ja3_hash=parsed_hello.get("ja3_hash"),
                            ja3_string=parsed_hello.get("ja3_string"),
                            ja4=parsed_hello.get("ja4"),
                        )
                    else:
                        tls_client_buffers[flow_tls] = tls_buf

            srv_flow = (dst_ip, tcp.dport, src_ip, tcp.sport)
            if should_buffer_tls(payload, tcp.sport in _TLS_PORTS, srv_flow in tls_server_buffers):
                if srv_flow in tls_by_flow and srv_flow not in tls_server_seen:
                    tls_buf = tls_server_buffers.get(srv_flow, b"") + payload
                    if len(tls_buf) > _MAX_FLOW_BUFFER:
                        tls_buf = tls_buf[-_MAX_FLOW_BUFFER:]
                    parsed_srv = extract_tls_server_hello(tls_buf)
                    if parsed_srv is not None:
                        tls_server_seen.add(srv_flow)
                        tls_server_buffers.pop(srv_flow, None)
                        ev = tls_by_flow[srv_flow]
                        ev.ja3s_hash = parsed_srv.get("ja3s_hash")
                        ev.ja3s_string = parsed_srv.get("ja3s_string")
                        ev.server_tls_version = parsed_srv.get("tls_version")
                    else:
                        tls_server_buffers[srv_flow] = tls_buf

    return ParsedPcap(
        packet_count=packet_count,
        first_ts=first_ts or 0.0,
        last_ts=last_ts or 0.0,
        dns_queries=dns_queries,
        http_events=http_events,
        connections=connections,
        ip_stats=ip_stats,
        syn_events=syn_events,
        flow_timestamps=flow_timestamps,
        credential_hits=credential_hits,
        tls_sni_events=list(tls_by_flow.values()),
        dns_nxdomain_count=dns_nxdomain_count,
    )
