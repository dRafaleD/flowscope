#!/usr/bin/env python3
"""Generate a small demo PCAP for Flowscope (educational lab only)."""

from __future__ import annotations

import socket
import time
from pathlib import Path

import dpkt

from flowscope.tls_sni import build_tls_client_hello_record, build_tls_server_hello_record


def _ip4(addr: str) -> bytes:
    return socket.inet_aton(addr)


def main() -> None:
    out = Path(__file__).resolve().parents[1] / "samples" / "lab_demo.pcap"
    out.parent.mkdir(parents=True, exist_ok=True)

    client = _ip4("192.168.1.50")
    server = _ip4("192.168.1.10")
    c2 = _ip4("203.0.113.77")
    dns_srv = _ip4("192.168.1.1")

    with open(out, "wb") as fh:
        writer = dpkt.pcap.Writer(fh)
        t0 = time.time()

        def eth_ip_udp(ts: float, src: bytes, dst: bytes, sport: int, dport: int, payload: bytes) -> None:
            udp = dpkt.udp.UDP(sport=sport, dport=dport, data=payload)
            udp.ulen = 8 + len(payload)
            ip = dpkt.ip.IP(src=src, dst=dst, p=dpkt.ip.IP_PROTO_UDP, data=udp)
            ip.len = 20 + len(udp)
            eth = dpkt.ethernet.Ethernet(src=b"\x00" * 6, dst=b"\x00" * 6, data=ip)
            writer.writepkt(bytes(eth), ts)

        def eth_ip_tcp(
            ts: float, src: bytes, dst: bytes, sport: int, dport: int, flags: int, payload: bytes = b""
        ) -> None:
            tcp = dpkt.tcp.TCP(sport=sport, dport=dport, flags=flags, data=payload)
            ip = dpkt.ip.IP(src=src, dst=dst, p=dpkt.ip.IP_PROTO_TCP, data=tcp)
            ip.len = 20 + len(tcp)
            eth = dpkt.ethernet.Ethernet(src=b"\x00" * 6, dst=b"\x00" * 6, data=ip)
            writer.writepkt(bytes(eth), ts)

        for i in range(60):
            q = dpkt.dns.DNS(
                id=i,
                qr=dpkt.dns.DNS_Q,
                qd=[dpkt.dns.DNS.Q(name=f"query{i}.evil.test", type=1, cls=1)],
            )
            eth_ip_udp(t0 + i * 0.05, client, dns_srv, 53000 + (i % 100), 53, bytes(q))

        http_req = (
            b"GET /login HTTP/1.1\r\nHost: 192.168.1.10\r\n"
            b"Authorization: Basic dXNlcjpzZWNyZXQ=\r\n\r\n"
        )
        eth_ip_tcp(t0 + 2, client, server, 44444, 80, dpkt.tcp.TH_PUSH, http_req)

        for port in range(20, 55):
            eth_ip_tcp(t0 + 3 + port * 0.01, client, server, 40000 + port, port, dpkt.tcp.TH_SYN)

        for n in range(12):
            eth_ip_tcp(t0 + 5 + n * 60.0, client, c2, 50000, 8443, dpkt.tcp.TH_PUSH, b"\x00")

        eth_ip_tcp(t0 + 4, client, server, 45000, 21, dpkt.tcp.TH_PUSH, b"USER labuser\r\nPASS labpass\r\n")

        # TLS to C2 IP with explicit SNI (metadata-only analysis)
        tls_hello = build_tls_client_hello_record("c2.evil.lab")
        eth_ip_tcp(t0 + 6, client, c2, 51000, 443, dpkt.tcp.TH_PUSH, tls_hello)
        tls_srv = build_tls_server_hello_record()
        eth_ip_tcp(t0 + 6.05, c2, client, 443, 51000, dpkt.tcp.TH_PUSH, tls_srv)

    print(f"Wrote {out}")


if __name__ == "__main__":
    main()
