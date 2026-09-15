"""CLI and stability checks: happy path, filters, corrupt/empty files."""

from __future__ import annotations

import json
from pathlib import Path

from flowscope.cli import main
from flowscope.engine import analyze_pcap
from flowscope.frames import CaptureError
from flowscope.pcap_loader import load_pcap
from flowscope.report import meets_severity

SAMPLE = Path(__file__).resolve().parents[1] / "samples" / "lab_demo.pcap"


def test_cli_happy_path_json_html(tmp_path: Path, capsys):
    assert SAMPLE.is_file(), "Run: python scripts/generate_sample_pcap.py"
    json_out = tmp_path / "out.json"
    html_out = tmp_path / "out.html"
    code = main(
        [
            str(SAMPLE),
            "-o",
            str(json_out),
            "--html",
            str(html_out),
            "-q",
        ]
    )
    assert code == 0
    data = json.loads(json_out.read_text(encoding="utf-8"))
    assert data["packet_count"] > 0
    assert data["risk_score"] <= 100
    assert data["meta"]["scored_finding_count"] >= 1
    html = html_out.read_text(encoding="utf-8")
    assert "Flowscope report" in html
    assert "attack.mitre.org" in html


def test_cli_min_severity_high_still_exports_full_json(tmp_path: Path):
    json_out = tmp_path / "full.json"
    html_out = tmp_path / "high.html"
    code = main(
        [
            str(SAMPLE),
            "--min-severity",
            "high",
            "-o",
            str(json_out),
            "--html",
            str(html_out),
            "-q",
        ]
    )
    assert code == 0
    data = json.loads(json_out.read_text(encoding="utf-8"))
    findings = data["findings"]
    scored = [f for f in findings if f["score_delta"] > 0]
    medium = [f for f in scored if f["severity"] == "medium"]
    assert medium, "JSON must keep medium findings even when HTML is filtered"
    html = html_out.read_text(encoding="utf-8")
    assert "Beacon-like periodic traffic" not in html
    assert "Plaintext credential risk" in html or "High DNS query rate" in html


def test_cli_missing_file():
    assert main(["C:/definitely/missing/flowscope.pcap"]) == 1


def test_cli_corrupt_file(tmp_path: Path):
    junk = tmp_path / "junk.bin"
    junk.write_bytes(b"not a pcap")
    assert main([str(junk)]) == 1


def test_cli_empty_file(tmp_path: Path):
    empty = tmp_path / "empty.pcap"
    empty.write_bytes(b"")
    assert main([str(empty)]) == 1


def test_load_pcap_corrupt_raises(tmp_path: Path):
    junk = tmp_path / "junk.bin"
    junk.write_bytes(b"XXXX")
    try:
        load_pcap(str(junk))
    except CaptureError:
        return
    raise AssertionError("expected CaptureError")


def test_analyze_twice_stable():
    a = analyze_pcap(str(SAMPLE))
    b = analyze_pcap(str(SAMPLE))
    assert a.packet_count == b.packet_count
    assert a.risk_score == b.risk_score
    assert a.meta["scored_finding_count"] == b.meta["scored_finding_count"]
    assert {f.title for f in a.findings} == {f.title for f in b.findings}


def test_meets_severity_filter():
    report = analyze_pcap(str(SAMPLE))
    high = [f for f in report.findings if f.score_delta > 0 and meets_severity(f, "high")]
    assert high
    assert all(f.severity in ("high", "critical") for f in high)
