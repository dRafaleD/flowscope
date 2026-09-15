from __future__ import annotations

import hashlib
import re

from flowscope.tls_parse import (
    EXT_ALPN,
    EXT_SERVER_NAME,
    alpn_first_value,
    is_grease16,
    parse_client_hello_body,
    signature_algorithms,
    sni_from_extensions,
    tls_version_for_ja4,
)


def _ja4_alpn_suffix(proto: bytes | None) -> str:
    if not proto:
        return "00"
    alnum = re.findall(rb"[0-9A-Za-z]", proto)
    if not alnum:
        hx = proto.hex()
        if len(hx) >= 2:
            return hx[0] + hx[-1]
        return hx or "00"
    if len(alnum) == 1:
        ch = alnum[0].decode("ascii")
        return ch + ch
    return alnum[0].decode("ascii") + alnum[-1].decode("ascii")


def _count_two_digit(count: int) -> str:
    return f"{min(count, 99):02d}"


def _trunc_sha12(payload: str) -> str:
    if not payload:
        return "000000000000"
    return hashlib.sha256(payload.encode("ascii")).hexdigest()[:12]


def ja4_client_from_client_hello_body(body: bytes) -> str | None:
    """FoxIO JA4 client fingerprint (TCP TLS)."""
    parsed = parse_client_hello_body(body)
    if parsed is None:
        return None

    ciphers = [c for c in parsed.cipher_codes if not is_grease16(c)]
    ext_types = [t for t, _ in parsed.extensions if not is_grease16(t)]

    sni = sni_from_extensions(parsed.extensions)
    sni_flag = "d" if sni else "i"
    version = tls_version_for_ja4(parsed)
    alpn = _ja4_alpn_suffix(alpn_first_value(parsed.extensions))

    part_a = f"t{version}{sni_flag}{_count_two_digit(len(ciphers))}{_count_two_digit(len(ext_types))}{alpn}"

    cipher_hex = ",".join(f"{c:04x}" for c in sorted(ciphers))
    part_b = _trunc_sha12(cipher_hex)

    ext_for_c = sorted(
        f"{t:04x}" for t in ext_types if t not in (EXT_SERVER_NAME, EXT_ALPN)
    )

    sigs = signature_algorithms(parsed.extensions)
    sig_part = ",".join(f"{s:04x}" for s in sigs)
    if ext_for_c and sig_part:
        ext_payload = ",".join(ext_for_c) + "_" + sig_part
    elif ext_for_c:
        ext_payload = ",".join(ext_for_c)
    elif sig_part:
        ext_payload = sig_part
    else:
        ext_payload = ""

    part_c = _trunc_sha12(ext_payload)

    return f"{part_a}_{part_b}_{part_c}"
