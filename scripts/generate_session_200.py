#!/usr/bin/env python3
"""Build a 200-packet lab capture that looks like a workstation session (educational)."""

from __future__ import annotations

import socket
from pathlib import Path

import dpkt

from flowscope.tls_sni import build_tls_client_hello_record, build_tls_server_hello_record

# Fixed start so the capture is reproducible
T0 = 1_704_067_200.0  # 2023-12-31 16:00:00 UTC


def _ip4(addr: str) -> bytes:
    return socket.inet_aton(addr)


def _dns_query(name: str, dns_id: int) -> bytes:
    return bytes(
        dpkt.dns.DNS(
            id=dns_id,
            qr=dpkt.dns.DNS_Q,
            qd=[dpkt.dns.DNS.Q(name=name, type=1, cls=1)],
        )
    )


def _dns_reply(name: str, dns_id: int, answer_ip: str) -> bytes:
    return bytes(
        dpkt.dns.DNS(
            id=dns_id,
            qr=dpkt.dns.DNS_R,
            aa=1,
            qd=[dpkt.dns.DNS.Q(name=name, type=1, cls=1)],
            an=[dpkt.dns.DNS.RR(name=name, type=1, cls=1, ttl=60, rdata=socket.inet_aton(answer_ip))],
        )
    )


def main() -> None:
    out = Path(__file__).resolve().parents[1] / "samples" / "session_200.pcap"
    out.parent.mkdir(parents=True, exist_ok=True)

    pc = _ip4("192.168.10.42")  # workstation
    gw = _ip4("192.168.10.1")  # DNS / gateway
    intranet = _ip4("192.168.10.20")  # internal web/ftp
    cdn = _ip4("151.101.1.69")
    mail = _ip4("52.96.10.8")
    c2 = _ip4("203.0.113.88")

    count = 0
    with open(out, "wb") as fh:
        writer = dpkt.pcap.Writer(fh)

        def udp(ts: float, src: bytes, dst: bytes, sport: int, dport: int, payload: bytes) -> None:
            nonlocal count
            pkt = dpkt.udp.UDP(sport=sport, dport=dport, data=payload)
            pkt.ulen = 8 + len(payload)
            ip = dpkt.ip.IP(src=src, dst=dst, p=dpkt.ip.IP_PROTO_UDP, data=pkt)
            ip.len = 20 + len(pkt)
            eth = dpkt.ethernet.Ethernet(src=b"\xaa" * 6, dst=b"\xbb" * 6, data=ip)
            writer.writepkt(bytes(eth), ts)
            count += 1

        def tcp(
            ts: float,
            src: bytes,
            dst: bytes,
            sport: int,
            dport: int,
            flags: int,
            payload: bytes = b"",
        ) -> None:
            nonlocal count
            pkt = dpkt.tcp.TCP(sport=sport, dport=dport, flags=flags, seq=1, data=payload)
            ip = dpkt.ip.IP(src=src, dst=dst, p=dpkt.ip.IP_PROTO_TCP, data=pkt)
            ip.len = 20 + len(pkt)
            eth = dpkt.ethernet.Ethernet(src=b"\xaa" * 6, dst=b"\xbb" * 6, data=ip)
            writer.writepkt(bytes(eth), ts)
            count += 1

        t = T0

        # --- 08:00 morning: normal DNS + TLS browsing ---
        sites = [
            ("www.office.com", "52.96.10.8"),
            ("login.microsoftonline.com", "20.190.160.14"),
            ("github.com", "140.82.112.3"),
            ("cdn.jsdelivr.net", "151.101.1.69"),
            ("update.microsoft.com", "13.107.4.50"),
            ("ntp.ubuntu.com", "185.125.190.57"),
            ("safebrowsing.googleapis.com", "142.250.187.10"),
            ("outlook.office365.com", "52.96.10.8"),
        ]
        for i, (name, ans) in enumerate(sites):
            udp(t, pc, gw, 51000 + i, 53, _dns_query(name, 100 + i))
            t += 0.02
            udp(t, gw, pc, 53, 51000 + i, _dns_reply(name, 100 + i, ans))
            t += 0.15
            hello = build_tls_client_hello_record(name)
            sport = 52000 + i
            dst = _ip4(ans)
            tcp(t, pc, dst, sport, 443, dpkt.tcp.TH_SYN)
            t += 0.01
            tcp(t, dst, pc, 443, sport, dpkt.tcp.TH_SYN | dpkt.tcp.TH_ACK)
            t += 0.01
            tcp(t, pc, dst, sport, 443, dpkt.tcp.TH_ACK)
            t += 0.02
            tcp(t, pc, dst, sport, 443, dpkt.tcp.TH_PUSH | dpkt.tcp.TH_ACK, hello)
            t += 0.03
            tcp(t, dst, pc, 443, sport, dpkt.tcp.TH_PUSH | dpkt.tcp.TH_ACK, build_tls_server_hello_record())
            t += 1.8

        # --- intranet HTTP (cleartext login page) ---
        t = T0 + 90
        udp(t, pc, gw, 51100, 53, _dns_query("intranet.corp.local", 200))
        t += 0.02
        udp(t, gw, pc, 53, 51100, _dns_reply("intranet.corp.local", 200, "192.168.10.20"))
        t += 0.2
        http_get = (
            b"GET /timesheet HTTP/1.1\r\nHost: intranet.corp.local\r\n"
            b"User-Agent: Mozilla/5.0\r\n\r\n"
        )
        tcp(t, pc, intranet, 53001, 80, dpkt.tcp.TH_PUSH | dpkt.tcp.TH_ACK, http_get)
        t += 2.0
        http_auth = (
            b"GET /admin HTTP/1.1\r\nHost: intranet.corp.local\r\n"
            b"Authorization: Basic bGFiOnBhc3M=\r\n\r\n"
        )
        tcp(t, pc, intranet, 53002, 80, dpkt.tcp.TH_PUSH | dpkt.tcp.TH_ACK, http_auth)

        # --- FTP to file server (plaintext) ---
        t = T0 + 140
        tcp(t, pc, intranet, 54000, 21, dpkt.tcp.TH_PUSH, b"USER backup\r\nPASS [lab]\r\n")

        # --- lunch: extra DNS (looks noisy) ---
        t = T0 + 300
        for i in range(55):
            name = f"cdn-edge-{i:02d}.updates.example.net"
            udp(t + i * 0.08, pc, gw, 55000 + i, 53, _dns_query(name, 300 + i))

        # --- afternoon: vertical scan against intranet (lab) ---
        t = T0 + 420
        for port in range(21, 41):
            tcp(t + (port - 21) * 0.05, pc, intranet, 56000 + port, port, dpkt.tcp.TH_SYN)

        # --- periodic beacon to documentation TEST-NET ---
        t = T0 + 480
        for n in range(10):
            tcp(t + n * 45.0, pc, c2, 57000, 8443, dpkt.tcp.TH_PUSH, b"\x00keep")

        # --- TLS to C2 IP with unmatched SNI ---
        t = T0 + 500
        tcp(t, pc, c2, 58000, 443, dpkt.tcp.TH_PUSH, build_tls_client_hello_record("mailer-update.evil.lab"))
        t += 0.04
        tcp(t, c2, pc, 443, 58000, dpkt.tcp.TH_PUSH, build_tls_server_hello_record())

        # --- pad to 200 with quiet HTTPS keepalives ---
        t = T0 + 600
        n = 0
        while count < 200:
            tcp(t + n * 0.3, pc, cdn, 59000 + (n % 50), 443, dpkt.tcp.TH_ACK, b"")
            n += 1
            if n > 80:
                break

    print(f"Wrote {out} ({count} packets)")


if __name__ == "__main__":
    main()
