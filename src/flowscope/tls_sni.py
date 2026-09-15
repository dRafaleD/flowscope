from __future__ import annotations

import struct
from typing import Any

import dpkt
import dpkt.ssl as ssl

from flowscope.ja3 import ja3_from_client_hello_body, ja3s_from_server_hello_body
from flowscope.ja4 import ja4_client_from_client_hello_body

EXT_SERVER_NAME = 0
_TLS_CONTENT_HANDSHAKE = 0x16
_TLS_HANDSHAKE_CLIENT_HELLO = 1
_TLS_HANDSHAKE_SERVER_HELLO = 2
_TLS_PORTS = frozenset({443, 8443, 9443, 4443, 465, 636, 993, 995})
_MAX_FLOW_BUFFER = 16_384


def looks_like_tls_handshake(payload: bytes) -> bool:
    return len(payload) >= 3 and payload[0] == _TLS_CONTENT_HANDSHAKE and payload[1] == 0x03


def should_buffer_tls(payload: bytes, on_known_port: bool, already_buffering: bool) -> bool:
    """Keep reassembling after the first TLS record, including non-standard ports."""
    if not payload:
        return False
    return on_known_port or already_buffering or looks_like_tls_handshake(payload)


def tls_version_label(version: int) -> str:
    major = (version >> 8) & 0xFF
    minor = version & 0xFF
    if version == 0x0304:
        return "TLS 1.3"
    if version == 0x0303:
        return "TLS 1.2"
    if version == 0x0302:
        return "TLS 1.1"
    if version == 0x0301:
        return "TLS 1.0"
    return f"SSL/TLS {major}.{minor}"


def parse_sni_from_extension_data(ext_data: bytes) -> str | None:
    """RFC 6066 server_name extension (type 0)."""
    if len(ext_data) < 5:
        return None
    list_len = struct.unpack("!H", ext_data[0:2])[0]
    pos = 2
    end = min(2 + list_len, len(ext_data))
    names: list[str] = []
    while pos + 3 <= end:
        name_type = ext_data[pos]
        name_len = struct.unpack("!H", ext_data[pos + 1 : pos + 3])[0]
        pos += 3
        if pos + name_len > end:
            break
        raw = ext_data[pos : pos + name_len]
        pos += name_len
        if name_type == 0:
            names.append(raw.decode("ascii", errors="replace"))
    return names[0] if names else None


def _sni_from_client_hello(hello: ssl.TLSClientHello) -> str | None:
    for ext_type, ext_data in getattr(hello, "extensions", []) or []:
        if ext_type == EXT_SERVER_NAME:
            return parse_sni_from_extension_data(ext_data)
    return None


def _handshake_body_from_payload(payload: bytes, handshake_type: int) -> bytes | None:
    if len(payload) < 5 or payload[0] != _TLS_CONTENT_HANDSHAKE:
        return None
    try:
        records, _consumed = ssl.tls_multi_factory(payload)
    except ssl.SSL3Exception:
        return None

    for record in records:
        if record.type != 22:
            continue
        raw = record.data
        if not raw:
            continue
        try:
            handshake = ssl.TLSHandshake(raw)
        except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError, ssl.SSL3Exception, ValueError):
            continue
        if handshake.type != handshake_type:
            continue
        return raw[4 : 4 + handshake.length]
    return None


def extract_tls_client_hello(payload: bytes) -> dict[str, Any] | None:
    """Parse first ClientHello; returns metadata including JA3 and JA4."""
    body = _handshake_body_from_payload(payload, _TLS_HANDSHAKE_CLIENT_HELLO)
    if body is None:
        return None
    try:
        hello = ssl.TLSClientHello(body)
    except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError, ValueError):
        return None

    sni = _sni_from_client_hello(hello)
    ja3 = ja3_from_client_hello_body(body)
    ja4 = ja4_client_from_client_hello_body(body)
    return {
        "sni": sni,
        "tls_version": tls_version_label(hello.version),
        "cipher_suites": len(getattr(hello, "ciphersuites", []) or []),
        "ja3_string": ja3.string if ja3 else None,
        "ja3_hash": ja3.hash if ja3 else None,
        "ja4": ja4,
    }


def extract_tls_server_hello(payload: bytes) -> dict[str, Any] | None:
    """Parse first ServerHello; returns JA3S metadata."""
    body = _handshake_body_from_payload(payload, _TLS_HANDSHAKE_SERVER_HELLO)
    if body is None:
        return None
    try:
        hello = ssl.TLSServerHello(body)
    except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError, ValueError):
        return None

    ja3s = ja3s_from_server_hello_body(body)
    cipher_name = getattr(hello, "ciphersuite", None)
    return {
        "tls_version": tls_version_label(hello.version),
        "cipher": str(cipher_name) if cipher_name else None,
        "ja3s_string": ja3s.string if ja3s else None,
        "ja3s_hash": ja3s.hash if ja3s else None,
    }


def build_tls_client_hello_record(hostname: str | None = None, record_version: bytes = b"\x03\x01") -> bytes:
    """Build a minimal TLS ClientHello; omit SNI when hostname is empty."""
    if hostname:
        host = hostname.encode("ascii")
        sni_list = struct.pack("!H", 3 + len(host)) + b"\x00" + struct.pack("!H", len(host)) + host
        sni_ext = struct.pack("!HH", EXT_SERVER_NAME, len(sni_list)) + sni_list
        extensions = struct.pack("!H", len(sni_ext)) + sni_ext
    else:
        extensions = b"\x00\x00"

    body = (
        b"\x03\x03"
        + b"\x00" * 32
        + b"\x00"
        + b"\x00\x02\xc0\x2f"
        + b"\x01\x00"
        + extensions
    )
    handshake = b"\x01" + struct.pack("!I", len(body))[1:] + body
    return (
        bytes([_TLS_CONTENT_HANDSHAKE])
        + record_version
        + struct.pack("!H", len(handshake))
        + handshake
    )


def build_tls_server_hello_record(cipher: int = 0xC02F, record_version: bytes = b"\x03\x03") -> bytes:
    """Minimal TLS ServerHello for lab PCAP generation."""
    body = b"\x03\x03" + b"\x00" * 32 + b"\x00" + struct.pack("!H", cipher) + b"\x00"
    handshake = b"\x02" + struct.pack("!I", len(body))[1:] + body
    return (
        bytes([_TLS_CONTENT_HANDSHAKE])
        + record_version
        + struct.pack("!H", len(handshake))
        + handshake
    )
