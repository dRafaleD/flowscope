from pathlib import Path

from flowscope.engine import analyze_pcap
from flowscope.geoip import classify_ip
from flowscope.report_html import write_html


def test_classify_test_net():
    info = classify_ip("203.0.113.77")
    assert "TEST-NET" in (info.network_label or "")


def test_html_report_writes(tmp_path: Path):
    sample = Path(__file__).resolve().parents[1] / "samples" / "lab_demo.pcap"
    if not sample.is_file():
        return
    report = analyze_pcap(str(sample))
    out = tmp_path / "report.html"
    write_html(report, str(out))
    text = out.read_text(encoding="utf-8")
    assert "Flowscope report" in text
    assert "Scored findings" in text
    assert "attack.mitre.org/techniques/" in text
    assert "Advice" in text
    assert "203.0.113.77" in text or "TEST-NET" in text
