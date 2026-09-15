"""Reference labels for JA3 hashes (extend from JA3er / abuse.ch / internal CTI)."""

JA3_LABELS: dict[str, str] = {
    "61cfdf1a447a978ff66f0880924eded7": "Flowscope lab ClientHello (minimal SNI)",
    "174e7e4992a63f6d419626d97363adb8": "Flowscope lab ServerHello (TLS_ECDHE_RSA_AES_128_GCM)",
    "cd08e31494f9531f560d64c695473da9": "Google Chrome (common desktop, verify on your PCAP)",
    "b32309a26951912be7dba376398abc3b": "Firefox (common desktop, verify on your PCAP)",
}


def label_for_ja3(ja3_hash: str) -> str | None:
    return JA3_LABELS.get(ja3_hash.lower())
