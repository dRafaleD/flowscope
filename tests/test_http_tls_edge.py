"""HTTP Host parsing and split TLS ClientHello on non-standard ports."""

from __future__ import annotations

import socket
from pathlib import Path

import dpkt

from flowscope.pcap_loader import _http_header, load_pcap
from flowscope.tls_sni import build_tls_client_hello_record, build_tls_server_hello_record, should_buffer_tls


def _eth_tcp(src: str, dst: str, sport: int, dport: int, payload: bytes) -> bytes:
    tcp = dpkt.tcp.TCP(sport=sport, dport=dport, flags=dpkt.tcp.TH_PUSH, data=payload)
    ip = dpkt.ip.IP(
        src=socket.inet_aton(src),
        dst=socket.inet_aton(dst),
        p=dpkt.ip.IP_PROTO_TCP,
        data=tcp,
    )
    ip.len = 20 + len(tcp)
    return bytes(dpkt.ethernet.Ethernet(src=b"\x0a" * 6, dst=b"\x0b" * 6, data=ip))


def _write_pcap(path: Path, frames: list[bytes]) -> None:
    with path.open("wb") as fh:
        writer = dpkt.pcap.Writer(fh)
        for i, frame in enumerate(frames):
            writer.writepkt(frame, ts=1_720_000_000.0 + i * 0.01)


def test_http_header_accepts_str_and_bytes_keys():
    assert _http_header({"host": "wiki.corp.local:8080"}, "host") == "wiki.corp.local:8080"
    assert _http_header({b"host": b"wiki.corp.local"}, "host") == "wiki.corp.local"
    assert _http_header({"Host": "Example.COM"}, "host") == "Example.COM"
    assert _http_header({}, "host") == ""


def test_http_host_on_port_8080(tmp_path: Path):
    req = b"GET /health HTTP/1.1\r\nHost: wiki.corp.local:8080\r\n\r\n"
    pcap = tmp_path / "http8080.pcap"
    _write_pcap(pcap, [_eth_tcp("10.20.30.40", "10.20.30.80", 45000, 8080, req)])
    parsed = load_pcap(str(pcap))
    assert len(parsed.http_events) == 1
    event = parsed.http_events[0]
    assert event.method == "GET"
    assert event.uri == "/health"
    assert event.host == "wiki.corp.local:8080"


def test_should_buffer_tls_continues_after_first_record():
    assert should_buffer_tls(b"\x16\x03\x01\x00\x20", False, False)
    assert should_buffer_tls(b"\x00\x00\x00\x00", False, True)
    assert not should_buffer_tls(b"\x00\x00\x00\x00", False, False)
    assert should_buffer_tls(b"\x00\x00\x00\x00", True, False)


def test_split_clienthello_on_nonstandard_port(tmp_path: Path):
    hello = build_tls_client_hello_record("split-hello.internal")
    mid = max(8, len(hello) // 2)
    server = build_tls_server_hello_record()
    pcap = tmp_path / "split9443.pcap"
    _write_pcap(
        pcap,
        [
            _eth_tcp("10.20.30.40", "10.20.30.80", 46000, 12345, hello[:mid]),
            _eth_tcp("10.20.30.40", "10.20.30.80", 46000, 12345, hello[mid:]),
            _eth_tcp("10.20.30.80", "10.20.30.40", 12345, 46000, server),
        ],
    )
    parsed = load_pcap(str(pcap))
    assert len(parsed.tls_sni_events) == 1
    event = parsed.tls_sni_events[0]
    assert event.sni == "split-hello.internal"
    assert event.dport == 12345
    assert event.ja3_hash
    assert event.ja4
    assert event.ja3s_hash


def test_split_serverhello_on_nonstandard_port(tmp_path: Path):
    hello = build_tls_client_hello_record("split-hello.internal")
    server = build_tls_server_hello_record()
    mid = max(8, len(server) // 2)
    pcap = tmp_path / "split_sh.pcap"
    _write_pcap(
        pcap,
        [
            _eth_tcp("10.20.30.40", "10.20.30.80", 46000, 12345, hello),
            _eth_tcp("10.20.30.80", "10.20.30.40", 12345, 46000, server[:mid]),
            _eth_tcp("10.20.30.80", "10.20.30.40", 12345, 46000, server[mid:]),
        ],
    )
    parsed = load_pcap(str(pcap))
    assert parsed.tls_sni_events[0].ja3s_hash
