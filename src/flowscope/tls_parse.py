from __future__ import annotations

import struct
from dataclasses import dataclass, field

EXT_SERVER_NAME = 0
EXT_SUPPORTED_GROUPS = 10
EXT_EC_POINT_FORMATS = 11
EXT_ALPN = 16
EXT_SIGNATURE_ALGORITHMS = 13
EXT_SUPPORTED_VERSIONS = 43


def is_grease16(value: int) -> bool:
    return (value & 0x0F0F) == 0x0A0A


@dataclass
class ClientHelloParsed:
    version: int
    cipher_codes: list[int] = field(default_factory=list)
    extensions: list[tuple[int, bytes]] = field(default_factory=list)


@dataclass
class ServerHelloParsed:
    version: int
    cipher: int
    extensions: list[tuple[int, bytes]] = field(default_factory=list)


def _parse_extensions_block(body: bytes, pos: int) -> tuple[list[tuple[int, bytes]], int]:
    extensions: list[tuple[int, bytes]] = []
    if pos + 2 > len(body):
        return extensions, pos
    ext_block_len = struct.unpack("!H", body[pos : pos + 2])[0]
    pos += 2
    end = pos + ext_block_len
    while pos + 4 <= end and pos + 4 <= len(body):
        ext_type = struct.unpack("!H", body[pos : pos + 2])[0]
        ext_len = struct.unpack("!H", body[pos + 2 : pos + 4])[0]
        pos += 4
        if pos + ext_len > len(body):
            break
        ext_data = body[pos : pos + ext_len]
        pos += ext_len
        extensions.append((ext_type, ext_data))
    return extensions, pos


def parse_client_hello_body(body: bytes) -> ClientHelloParsed | None:
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
    ciphers: list[int] = []
    for i in range(0, cs_len, 2):
        ciphers.append(struct.unpack("!H", body[pos + i : pos + i + 2])[0])
    pos += cs_len
    if pos >= len(body):
        return ClientHelloParsed(version=version, cipher_codes=ciphers)
    comp_len = body[pos]
    pos += 1 + comp_len
    extensions, _ = _parse_extensions_block(body, pos)
    return ClientHelloParsed(version=version, cipher_codes=ciphers, extensions=extensions)


def parse_server_hello_body(body: bytes) -> ServerHelloParsed | None:
    if len(body) < 2 + 32 + 1 + 2 + 1:
        return None
    pos = 0
    version = struct.unpack("!H", body[pos : pos + 2])[0]
    pos += 2 + 32
    sid_len = body[pos]
    pos += 1
    if pos + sid_len + 3 > len(body):
        return None
    pos += sid_len
    cipher = struct.unpack("!H", body[pos : pos + 2])[0]
    pos += 2
    comp_len = body[pos]
    pos += 1 + comp_len
    extensions, _ = _parse_extensions_block(body, pos)
    return ServerHelloParsed(version=version, cipher=cipher, extensions=extensions)


def sni_from_extensions(extensions: list[tuple[int, bytes]]) -> str | None:
    for ext_type, ext_data in extensions:
        if ext_type != EXT_SERVER_NAME:
            continue
        if len(ext_data) < 5:
            continue
        list_len = struct.unpack("!H", ext_data[0:2])[0]
        p = 2
        end = min(2 + list_len, len(ext_data))
        while p + 3 <= end:
            name_type = ext_data[p]
            name_len = struct.unpack("!H", ext_data[p + 1 : p + 3])[0]
            p += 3
            if p + name_len > end:
                break
            name = ext_data[p : p + name_len]
            p += name_len
            if name_type == 0:
                return name.decode("ascii", errors="replace")
    return None


def alpn_first_value(extensions: list[tuple[int, bytes]]) -> bytes | None:
    for ext_type, ext_data in extensions:
        if ext_type != EXT_ALPN or len(ext_data) < 2:
            continue
        list_len = struct.unpack("!H", ext_data[0:2])[0]
        p = 2
        if p >= len(ext_data):
            return None
        proto_len = ext_data[p]
        p += 1
        if p + proto_len > len(ext_data):
            return None
        return ext_data[p : p + proto_len]
    return None


def signature_algorithms(extensions: list[tuple[int, bytes]]) -> list[int]:
    for ext_type, ext_data in extensions:
        if ext_type != EXT_SIGNATURE_ALGORITHMS or len(ext_data) < 2:
            continue
        list_len = struct.unpack("!H", ext_data[0:2])[0]
        p = 2
        end = min(2 + list_len, len(ext_data))
        sigs: list[int] = []
        while p + 2 <= end:
            sigs.append(struct.unpack("!H", ext_data[p : p + 2])[0])
            p += 2
        return sigs
    return []


def tls_version_for_ja4(parsed: ClientHelloParsed) -> str:
    for ext_type, ext_data in parsed.extensions:
        if ext_type != EXT_SUPPORTED_VERSIONS or len(ext_data) < 1:
            continue
        list_len = ext_data[0]
        p = 1
        end = min(1 + list_len, len(ext_data))
        versions: list[int] = []
        while p + 2 <= end:
            versions.append(struct.unpack("!H", ext_data[p : p + 2])[0])
            p += 2
        versions = [v for v in versions if not is_grease16(v)]
        if versions:
            return _ja4_version_label(max(versions))
    return _ja4_version_label(parsed.version)


def _ja4_version_label(version: int) -> str:
    mapping = {
        0x0304: "13",
        0x0303: "12",
        0x0302: "11",
        0x0301: "10",
        0x0300: "s3",
        0x0002: "s2",
        0xFEFF: "d1",
        0xFEFD: "d2",
        0xFEFC: "d3",
    }
    return mapping.get(version, "00")
