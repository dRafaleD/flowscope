#!/usr/bin/env python3
"""Edge-case lab PCAP: VLAN, IPv6, HTTP/8080, TLS/9443 split hello, NXDOMAIN, horizontal SYN."""

from __future__ import annotations

import socket
from pathlib import Path

import dpkt

from flowscope.tls_sni import build_tls_client_hello_record, build_tls_server_hello_record

T0 = 1_720_000_000.0


def ip4(addr: str) -> bytes:
    return socket.inet_aton(addr)


def ip6(addr: str) -> bytes:
    return socket.inet_pton(socket.AF_INET6, addr)


def main() -> None:
    out = Path(__file__).resolve().parents[1] / "samples" / "edge_cases.pcap"
    out.parent.mkdir(parents=True, exist_ok=True)
    host = ip4("10.20.30.40")
    dns = ip4("10.20.30.1")
    web = ip4("10.20.30.80")
    n = {"c": 0}

    with open(out, "wb") as fh:
        writer = dpkt.pcap.Writer(fh)

        def put(ts: float, eth: dpkt.ethernet.Ethernet) -> None:
            writer.writepkt(bytes(eth), ts)
            n["c"] += 1

        def eth_v4(ip_pkt, vlan: bool = False) -> dpkt.ethernet.Ethernet:
            if vlan:
                tag = dpkt.ethernet.VLANtag8021Q(id=100)
                tag.type = dpkt.ethernet.ETH_TYPE_IP
                return dpkt.ethernet.Ethernet(
                    src=b"\x0a" * 6, dst=b"\x0b" * 6, vlan_tags=[tag], data=ip_pkt
                )
            return dpkt.ethernet.Ethernet(src=b"\x0a" * 6, dst=b"\x0b" * 6, data=ip_pkt)

        def udp4(src, dst, sport, dport, payload, vlan=False):
            udp = dpkt.udp.UDP(sport=sport, dport=dport, data=payload)
            udp.ulen = 8 + len(payload)
            ip = dpkt.ip.IP(src=src, dst=dst, p=dpkt.ip.IP_PROTO_UDP, data=udp)
            ip.len = 20 + len(udp)
            return eth_v4(ip, vlan=vlan)

        def tcp4(src, dst, sport, dport, flags, payload=b"", vlan=False):
            tcp = dpkt.tcp.TCP(sport=sport, dport=dport, flags=flags, data=payload)
            ip = dpkt.ip.IP(src=src, dst=dst, p=dpkt.ip.IP_PROTO_TCP, data=tcp)
            ip.len = 20 + len(tcp)
            return eth_v4(ip, vlan=vlan)

        t = T0

        # VLAN-tagged normal DNS
        q = bytes(dpkt.dns.DNS(id=1, qr=0, qd=[dpkt.dns.DNS.Q(name="wiki.corp.local", type=1)]))
        put(t, udp4(host, dns, 40001, 53, q, vlan=True))
        t += 0.01
        a = bytes(
            dpkt.dns.DNS(
                id=1,
                qr=1,
                rcode=0,
                qd=[dpkt.dns.DNS.Q(name="wiki.corp.local", type=1)],
            )
        )
        put(t, udp4(dns, host, 53, 40001, a, vlan=True))

        # IPv6 DNS query + NXDOMAIN-style still v4 below
        t += 0.2
        q6 = bytes(dpkt.dns.DNS(id=2, qr=0, qd=[dpkt.dns.DNS.Q(name="ipv6only.example", type=28)]))
        udp6 = dpkt.udp.UDP(sport=40002, dport=53, data=q6)
        udp6.ulen = 8 + len(q6)
        ip6p = dpkt.ip6.IP6(src=ip6("fd00::42"), dst=ip6("fd00::1"), nxt=dpkt.ip.IP_PROTO_UDP, data=udp6)
        ip6p.plen = len(udp6)
        put(t, dpkt.ethernet.Ethernet(src=b"\x0a" * 6, dst=b"\x0b" * 6, data=ip6p))

        # 12 NXDOMAIN replies (plus queries) — untagged
        t = T0 + 2
        for i in range(12):
            name = f"no-such-{i}.ghost.invalid"
            qq = bytes(dpkt.dns.DNS(id=50 + i, qr=0, qd=[dpkt.dns.DNS.Q(name=name, type=1)]))
            nx = bytes(
                dpkt.dns.DNS(
                    id=50 + i,
                    qr=1,
                    rcode=3,
                    qd=[dpkt.dns.DNS.Q(name=name, type=1)],
                )
            )
            put(t + i * 0.05, udp4(host, dns, 41000 + i, 53, qq))
            put(t + i * 0.05 + 0.01, udp4(dns, host, 53, 41000 + i, nx))

        # HTTP on 8080 (magic bytes, not port 80)
        t = T0 + 5
        req = b"GET /health HTTP/1.1\r\nHost: wiki.corp.local:8080\r\n\r\n"
        put(t, tcp4(host, web, 45000, 8080, dpkt.tcp.TH_PUSH, req))

        # Telnet
        t += 0.5
        put(t, tcp4(host, web, 45001, 23, dpkt.tcp.TH_PUSH, b"login: admin\r\n"))

        # TLS ClientHello split across two segments on 9443
        t = T0 + 8
        hello = build_tls_client_hello_record("split-hello.internal")
        mid = max(8, len(hello) // 2)
        put(t, tcp4(host, web, 46000, 9443, dpkt.tcp.TH_PUSH, hello[:mid]))
        put(t + 0.01, tcp4(host, web, 46000, 9443, dpkt.tcp.TH_PUSH, hello[mid:]))
        put(t + 0.02, tcp4(web, host, 9443, 46000, dpkt.tcp.TH_PUSH, build_tls_server_hello_record()))

        # Horizontal scan: SYN/22 to 12 hosts
        t = T0 + 12
        for i in range(12):
            dst = ip4(f"10.20.31.{10 + i}")
            put(t + i * 0.02, tcp4(host, dst, 47000 + i, 22, dpkt.tcp.TH_SYN))

        # Quiet HTTPS keepalive padding
        t = T0 + 20
        for i in range(8):
            put(t + i, tcp4(host, web, 48000, 443, dpkt.tcp.TH_ACK, b""))

    print(f"Wrote {out} ({n['c']} packets)")


if __name__ == "__main__":
    main()
