import socket

import dpkt

from flowscope.frames import DLT_EN10MB, DLT_LINUX_SLL, DLT_RAW_LINUX, decode_l3
from flowscope.ja3 import ja3_from_client_hello_body
from flowscope.tls_parse import is_grease16


def _ipv4_udp() -> dpkt.ip.IP:
    udp = dpkt.udp.UDP(sport=12345, dport=53, data=b"\x00")
    udp.ulen = 8 + len(udp.data)
    ip = dpkt.ip.IP(
        src=socket.inet_aton("10.0.0.1"),
        dst=socket.inet_aton("10.0.0.2"),
        p=dpkt.ip.IP_PROTO_UDP,
        data=udp,
    )
    ip.len = 20 + len(udp)
    return ip


def test_decode_vlan_ethernet():
    ip = _ipv4_udp()
    tag = dpkt.ethernet.VLANtag8021Q(id=32)
    tag.type = dpkt.ethernet.ETH_TYPE_IP
    eth = dpkt.ethernet.Ethernet(
        src=b"\x00" * 6,
        dst=b"\x11" * 6,
        vlan_tags=[tag],
        data=ip,
    )
    parsed = decode_l3(bytes(eth), DLT_EN10MB)
    assert parsed is not None
    assert socket.inet_ntoa(parsed.src) == "10.0.0.1"
    assert socket.inet_ntoa(parsed.dst) == "10.0.0.2"


def test_decode_linux_sll():
    ip = _ipv4_udp()
    cooked = dpkt.sll.SLL(ethtype=dpkt.ethernet.ETH_TYPE_IP, data=ip)
    parsed = decode_l3(bytes(cooked), DLT_LINUX_SLL)
    assert parsed is not None
    assert socket.inet_ntoa(parsed.src) == "10.0.0.1"


def test_decode_raw_ip():
    ip = _ipv4_udp()
    parsed = decode_l3(bytes(ip), DLT_RAW_LINUX)
    assert parsed is not None
    assert socket.inet_ntoa(parsed.dst) == "10.0.0.2"


def test_ja3_strips_grease():
    assert is_grease16(0x0A0A)
    # version + random + session(0) + ciphers 0x0a0a and 0xc02f + comp + no ext
    body = (
        b"\x03\x03"
        + b"\x00" * 32
        + b"\x00"
        + b"\x00\x04\x0a\x0a\xc0\x2f"
        + b"\x01\x00"
    )
    ja3 = ja3_from_client_hello_body(body)
    assert ja3 is not None
    assert "2570" not in ja3.string  # 0x0a0a decimal
    assert "49199" in ja3.string
