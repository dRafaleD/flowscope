from pathlib import Path

from flowscope.engine import analyze_pcap
from flowscope.scoring import aggregate_score, scored_finding_count


SAMPLE = Path(__file__).resolve().parents[1] / "samples" / "lab_demo.pcap"


def _ensure_sample() -> Path:
    if not SAMPLE.is_file():
        raise FileNotFoundError("Run: python scripts/generate_sample_pcap.py")
    return SAMPLE


def test_lab_demo_detectors():
    report = analyze_pcap(str(_ensure_sample()))
    titles = {f.title for f in report.findings}

    assert "High DNS query rate" in titles
    assert "Possible vertical port scan" in titles
    assert "Beacon-like periodic traffic" in titles
    assert any("Plaintext credential risk" in t for t in titles)
    assert "SNI hostname to IP destination" in titles
    assert "Documentation / lab address space" in titles

    scored = [f for f in report.findings if f.score_delta > 0]
    assert any(f.mitre == "T1071.004" for f in scored)
    assert any(f.mitre == "T1046" for f in scored)
    assert any(f.mitre == "T1071" for f in scored)
    assert any(f.mitre == "T1040" for f in scored)
    assert any(f.mitre == "T1573" for f in scored)

    creds = [f for f in scored if f.category == "credentials"]
    assert len(creds) == 2  # FTP and HTTP-Basic, not USER+PASS duplicates
    assert all(f.advice for f in scored)

    tls = [e for e in report.tls_sni_events if e.sni == "c2.evil.lab"]
    assert tls
    assert tls[0].ja3_hash
    assert tls[0].ja4
    assert tls[0].ja3s_hash

    geo = report.meta.get("geoip") or {}
    assert "TEST-NET" in (geo.get("203.0.113.77") or {}).get("network_label", "")

    assert report.risk_score <= 100
    assert report.risk_score == aggregate_score(report.findings)
    assert report.meta["scored_finding_count"] == scored_finding_count(report.findings)
    assert report.risk_score < 100  # category caps keep lab capture below ceiling

    syn_total = sum(c.syn_count for c in report.tcp_connections)
    assert syn_total > 0
