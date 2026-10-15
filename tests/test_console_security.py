from flowscope.models import AnalysisReport, TlsSniEvent, Finding
from flowscope.report import print_console, report_to_dict
from flowscope.report import literal
from flowscope.tls_sni import build_tls_client_hello_record, extract_tls_client_hello


def test_packet_markup_is_literal_in_table_and_findings(capsys):
    value = "[/unmatched][link=https://example.test]name[/link]"
    metadata = extract_tls_client_hello(build_tls_client_hello_record(value))
    assert metadata["sni"] == value
    report = AnalysisReport("capture[/unmatched].pcap", 1, 0.1)
    report.tls_sni_events.append(TlsSniEvent(0, "10.0.0.1", "10.0.0.2", 443, value, "TLS 1.2", 1))
    report.findings.append(Finding("tls", "low", "SNI", value, 1))
    print_console(report)
    assert value in capsys.readouterr().out
    assert report_to_dict(report)["tls_sni_events"][0]["sni"] == value


def test_terminal_controls_are_visible_instead_of_interpreted():
    text = literal("normal\x1b]8;;https://example.test\x07\r\n\u202e")
    assert "\x1b" not in text.plain
    assert "\r" not in text.plain
    assert "\u202e" not in text.plain
    assert "normal" in text.plain
