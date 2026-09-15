from flowscope.ja3 import ja3_from_client_hello_body
from flowscope.tls_sni import build_tls_client_hello_record, extract_tls_client_hello


def test_ja3_lab_client_hello_stable():
    record = build_tls_client_hello_record("c2.evil.lab")
    parsed = extract_tls_client_hello(record)
    assert parsed is not None
    assert parsed["ja3_hash"] is not None
    assert parsed["ja3_string"] == "771,49199,0,,"

    body = record[5:]  # skip TLS record header
    # handshake inside record: type 1 + len 3 + body
    hello_body = body[4:]
    ja3 = ja3_from_client_hello_body(hello_body)
    assert ja3 is not None
    assert ja3.hash == parsed["ja3_hash"]
