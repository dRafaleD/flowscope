from flowscope.ja3 import ja3s_from_server_hello_body
from flowscope.tls_sni import (
    build_tls_client_hello_record,
    build_tls_server_hello_record,
    extract_tls_client_hello,
    extract_tls_server_hello,
)


def test_ja4_and_ja3s_lab_handshakes():
    client_rec = build_tls_client_hello_record("c2.evil.lab")
    client = extract_tls_client_hello(client_rec)
    assert client is not None
    assert client["ja4"] is not None
    assert client["ja4"] == "t12d010100_f06271c2b022_000000000000"

    server_rec = build_tls_server_hello_record()
    server = extract_tls_server_hello(server_rec)
    assert server is not None
    assert server["ja3s_string"] == "771,49199,"
    assert server["ja3s_hash"] is not None

    body = server_rec[5 + 4 :]  # record hdr + handshake hdr
    ja3s = ja3s_from_server_hello_body(body)
    assert ja3s is not None
    assert ja3s.hash == server["ja3s_hash"]
