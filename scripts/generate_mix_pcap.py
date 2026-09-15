#!/usr/bin/env python3
"""Lab mix capture: entropy DNS, VLAN HTTP, split TLS/10443, IPv6 TLS, beacon, vertical scan."""

from __future__ import annotations

import hashlib
import socket
from pathlib import Path

import dpkt

from flowscope.tls_sni import build_tls_client_hello_record, build_tls_server_hello_record

T0 = 1_735_689_600.0  # 2025-01-01 00:00:00 UTC


def ip4(addr: str) -> bytes:
    return socket.inet_aton(addr)


def ip6(addr: str) -> bytes:
    return socket.inet_pton(socket.AF_INET6, addr)


def main() -> None:
    out = Path(__file__).resolve().parents[1] / "samples" / "mix_office.pcap"
    out.parent.mkdir(parents=True, exist_ok=True)
    pc = ip4("10.50.1.20")
    dns = ip4("10.50.1.1")
    web = ip4("10.50.1.80")
    n = {"c": 0}

    with open(out, "wb") as fh:
        writer = dpkt.pcap.Writer(fh)

        def put(ts: float, eth: dpkt.ethernet.Ethernet) -> None:
            writer.writepkt(bytes(eth), ts)
            n["c"] += 1

        def wrap(ip_pkt, vlan: bool = False) -> dpkt.ethernet.Ethernet:
            if vlan:
                tag = dpkt.ethernet.VLANtag8021Q(id=40)
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
            return wrap(ip, vlan=vlan)

        def tcp4(src, dst, sport, dport, flags, payload=b"", vlan=False):
            tcp = dpkt.tcp.TCP(sport=sport, dport=dport, flags=flags, data=payload)
            ip = dpkt.ip.IP(src=src, dst=dst, p=dpkt.ip.IP_PROTO_TCP, data=tcp)
            ip.len = 20 + len(tcp)
            return wrap(ip, vlan=vlan)

        t = T0

        # High-entropy DNS names (DGA-like labels)
        for i in range(6):
            label = hashlib.md5(f"dga-{i}".encode()).hexdigest()
            name = f"{label}.tunnel.invalid"
            q = bytes(dpkt.dns.DNS(id=10 + i, qr=0, qd=[dpkt.dns.DNS.Q(name=name, type=1)]))
            put(t + i * 0.04, udp4(pc, dns, 40000 + i, 53, q))

        # VLAN-tagged HTTP with Host header
        t = T0 + 2
        req = b"GET /status HTTP/1.1\r\nHost: portal.corp.local\r\nUser-Agent: lab\r\n\r\n"
        put(t, tcp4(pc, web, 41000, 80, dpkt.tcp.TH_PUSH, req, vlan=True))

        # HTTP/8080 Host + form password (space before password= so detector matches)
        t += 0.3
        post = (
            b"POST /login HTTP/1.1\r\nHost: app.corp.local:8080\r\n"
            b"Content-Type: application/x-www-form-urlencoded\r\n"
            b"Content-Length: 27\r\n\r\n"
            b"user=lab password=secret123"
        )
        put(t, tcp4(pc, web, 41001, 8080, dpkt.tcp.TH_PUSH, post))

        # HTTP Basic
        t += 0.2
        basic = (
            b"GET /admin HTTP/1.1\r\nHost: app.corp.local\r\n"
            b"Authorization: Basic bGFiOnBhc3M=\r\n\r\n"
        )
        put(t, tcp4(pc, web, 41002, 80, dpkt.tcp.TH_PUSH, basic))

        # FTP
        t += 0.4
        put(t, tcp4(pc, web, 41003, 21, dpkt.tcp.TH_PUSH, b"USER backup\r\nPASS labpass\r\n"))

        # Eight TLS sessions, distinct SNI, distinct TEST-NET destinations (same JA3)
        t = T0 + 6
        snis = [
            "cdn.updates.example",
            "api.mailer.example",
            "push.notify.example",
            "sync.backup.example",
            "telemetry.metrics.example",
            "edge.static.example",
            "login.sso.example",
            "graph.office.example",
        ]
        for i, sni in enumerate(snis):
            dst = ip4(f"198.51.100.{20 + i}")
            sport = 42000 + i
            ts = t + i * 0.2
            put(ts, tcp4(pc, dst, sport, 443, dpkt.tcp.TH_PUSH, build_tls_client_hello_record(sni)))
            put(ts + 0.02, tcp4(dst, pc, 443, sport, dpkt.tcp.TH_PUSH, build_tls_server_hello_record()))

        # TLS ClientHello without SNI
        t = T0 + 10
        nosni = ip4("198.51.100.40")
        put(t, tcp4(pc, nosni, 43000, 443, dpkt.tcp.TH_PUSH, build_tls_client_hello_record(None)))
        put(t + 0.02, tcp4(nosni, pc, 443, 43000, dpkt.tcp.TH_PUSH, build_tls_server_hello_record()))

        # Split ClientHello on 10443 (not in the known TLS port list)
        t = T0 + 12
        split_dst = ip4("198.51.100.50")
        hello = build_tls_client_hello_record("split-on-10443.lab")
        mid = max(8, len(hello) // 2)
        put(t, tcp4(pc, split_dst, 44000, 10443, dpkt.tcp.TH_PUSH, hello[:mid]))
        put(t + 0.01, tcp4(pc, split_dst, 44000, 10443, dpkt.tcp.TH_PUSH, hello[mid:]))
        put(t + 0.02, tcp4(split_dst, pc, 10443, 44000, dpkt.tcp.TH_PUSH, build_tls_server_hello_record()))

        # IPv6 TLS
        t = T0 + 14
        hello6 = build_tls_client_hello_record("ipv6-api.internal")
        tcp6 = dpkt.tcp.TCP(sport=45000, dport=443, flags=dpkt.tcp.TH_PUSH, data=hello6)
        ip6c = dpkt.ip6.IP6(
            src=ip6("fd00::20"),
            dst=ip6("fd00::80"),
            nxt=dpkt.ip.IP_PROTO_TCP,
            data=tcp6,
        )
        ip6c.plen = len(tcp6)
        put(t, dpkt.ethernet.Ethernet(src=b"\x0a" * 6, dst=b"\x0b" * 6, data=ip6c))
        srv6 = build_tls_server_hello_record()
        tcp6s = dpkt.tcp.TCP(sport=443, dport=45000, flags=dpkt.tcp.TH_PUSH, data=srv6)
        ip6s = dpkt.ip6.IP6(
            src=ip6("fd00::80"),
            dst=ip6("fd00::20"),
            nxt=dpkt.ip.IP_PROTO_TCP,
            data=tcp6s,
        )
        ip6s.plen = len(tcp6s)
        put(t + 0.02, dpkt.ethernet.Ethernet(src=b"\x0a" * 6, dst=b"\x0b" * 6, data=ip6s))

        # Vertical scan: 18 ports on intranet web
        t = T0 + 18
        for i, port in enumerate(range(20, 38)):
            put(t + i * 0.03, tcp4(pc, web, 46000 + i, port, dpkt.tcp.TH_SYN))

        # Beacon to TEST-NET C2
        t = T0 + 30
        c2 = ip4("203.0.113.200")
        for i in range(9):
            put(t + i * 40.0, tcp4(pc, c2, 47000, 8443, dpkt.tcp.TH_PUSH, b"\x00keep"))

        # Uncommon destination port (enough packets to score)
        t = T0 + 400
        odd = ip4("10.50.1.90")
        for i in range(4):
            put(t + i * 0.5, tcp4(pc, odd, 48000, 9000, dpkt.tcp.TH_PUSH, b"probe"))

    print(f"Wrote {out} ({n['c']} packets)")


if __name__ == "__main__":
    main()
