from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass

from flowscope.tls_parse import (
    EXT_EC_POINT_FORMATS,
    EXT_SUPPORTED_GROUPS,
    is_grease16,
    parse_server_hello_body,
)


@dataclass(frozen=True)
class Ja3Fingerprint:
    """TLS ClientHello JA3 (Salesforce spec) — metadata only."""

    string: str
    hash: str


def _parse_supported_groups(ext_data: bytes) -> list[int]:
    if len(ext_data) < 2:
        return []
    list_len = struct.unpack("!H", ext_data[0:2])[0]
    pos = 2
    end = min(2 + list_len, len(ext_data))
    groups: list[int] = []
    while pos + 2 <= end:
        groups.append(struct.unpack("!H", ext_data[pos : pos + 2])[0])
        pos += 2
    return groups


def _parse_ec_point_formats(ext_data: bytes) -> list[int]:
    if len(ext_data) < 1:
        return []
    list_len = ext_data[0]
    pos = 1
    end = min(1 + list_len, len(ext_data))
    return list(ext_data[pos:end])


def ja3_from_client_hello_body(body: bytes) -> Ja3Fingerprint | None:
    """
    Compute JA3 from the ClientHello handshake body (version through extensions).
    Does not include the handshake type/length header.
    """
    if len(body) < 2 + 32 + 1:
        return None

    pos = 0
    version = struct.unpack("!H", body[pos : pos + 2])[0]
    pos += 2 + 32

    sid_len = body[pos]
    pos += 1
    if pos + sid_len > len(body):
        return None
    pos += sid_len

    if pos + 2 > len(body):
        return None
    cs_len = struct.unpack("!H", body[pos : pos + 2])[0]
    pos += 2
    if pos + cs_len > len(body) or cs_len % 2 != 0:
        return None

    cipher_codes: list[int] = []
    for i in range(0, cs_len, 2):
        cipher_codes.append(struct.unpack("!H", body[pos + i : pos + i + 2])[0])
    pos += cs_len

    if pos >= len(body):
        return _finalize(version, cipher_codes, [], [], [])

    comp_len = body[pos]
    pos += 1 + comp_len
    if pos + 2 > len(body):
        return _finalize(version, cipher_codes, [], [], [])

    ext_block_len = struct.unpack("!H", body[pos : pos + 2])[0]
    pos += 2
    end = pos + ext_block_len

    ext_types: list[int] = []
    curves: list[int] = []
    ec_points: list[int] = []

    while pos + 4 <= end and pos + 4 <= len(body):
        ext_type = struct.unpack("!H", body[pos : pos + 2])[0]
        ext_len = struct.unpack("!H", body[pos + 2 : pos + 4])[0]
        pos += 4
        if pos + ext_len > len(body):
            break
        ext_data = body[pos : pos + ext_len]
        pos += ext_len
        ext_types.append(ext_type)
        if ext_type == EXT_SUPPORTED_GROUPS:
            curves = _parse_supported_groups(ext_data)
        elif ext_type == EXT_EC_POINT_FORMATS:
            ec_points = _parse_ec_point_formats(ext_data)

    return _finalize(version, cipher_codes, ext_types, curves, ec_points)


def _field(values: list[int]) -> str:
    return "-".join(str(v) for v in values)


def _finalize(
    version: int,
    ciphers: list[int],
    extensions: list[int],
    curves: list[int],
    ec_points: list[int],
) -> Ja3Fingerprint:
    ciphers = [c for c in ciphers if not is_grease16(c)]
    extensions = [e for e in extensions if not is_grease16(e)]
    curves = [c for c in curves if not is_grease16(c)]
    ja3_string = ",".join(
        [
            str(version),
            _field(ciphers),
            _field(extensions),
            _field(curves),
            _field(ec_points),
        ]
    )
    ja3_hash = hashlib.md5(ja3_string.encode("ascii"), usedforsecurity=False).hexdigest()
    return Ja3Fingerprint(string=ja3_string, hash=ja3_hash)


def ja3s_from_server_hello_body(body: bytes) -> Ja3Fingerprint | None:
    """JA3S — ServerHello version, cipher, extension types (Salesforce spec)."""
    parsed = parse_server_hello_body(body)
    if parsed is None:
        return None
    ext_types = [t for t, _ in parsed.extensions]
    ja3s_string = ",".join([str(parsed.version), str(parsed.cipher), _field(ext_types)])
    ja3s_hash = hashlib.md5(ja3s_string.encode("ascii"), usedforsecurity=False).hexdigest()
    return Ja3Fingerprint(string=ja3s_string, hash=ja3s_hash)
