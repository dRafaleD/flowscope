from __future__ import annotations

import dpkt
import dpkt.sll as sll

DLT_EN10MB = 1
DLT_RAW_LINUX = 12
DLT_RAW_OPENBSD = 14
DLT_RAW_ALT = 101
DLT_LINUX_SLL = 113
_RAW_DLTS = frozenset({DLT_RAW_LINUX, DLT_RAW_OPENBSD, DLT_RAW_ALT})


class CaptureError(Exception):
    """Unreadable or unsupported capture file."""


def _as_ip(pkt) -> dpkt.ip.IP | dpkt.ip6.IP6 | None:
    if isinstance(pkt, (dpkt.ip.IP, dpkt.ip6.IP6)):
        return pkt
    data = getattr(pkt, "data", None)
    if isinstance(data, (dpkt.ip.IP, dpkt.ip6.IP6)):
        return data
    return None


def _parse_raw_ip(buf: bytes):
    if not buf:
        return None
    version = buf[0] >> 4
    try:
        if version == 4:
            return dpkt.ip.IP(buf)
        if version == 6:
            return dpkt.ip6.IP6(buf)
    except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError, ValueError):
        return None
    return None


def decode_l3(buf: bytes, dlt: int):
    """Return IPv4/IPv6 packet from a link-layer buffer, or None."""
    try:
        if dlt == DLT_EN10MB:
            eth = dpkt.ethernet.Ethernet(buf)
            return _as_ip(eth)
        if dlt == DLT_LINUX_SLL:
            cooked = sll.SLL(buf)
            return _as_ip(cooked)
        if dlt in _RAW_DLTS:
            return _parse_raw_ip(buf)
    except (dpkt.dpkt.NeedData, dpkt.dpkt.UnpackError, ValueError):
        return None
    return None
