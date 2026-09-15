from pathlib import Path

import dpkt

from flowscope.pcap_loader import load_pcap


def test_pcapng_fallback(tmp_path: Path):
    sample = Path(__file__).resolve().parents[1] / "samples" / "lab_demo.pcap"
    assert sample.is_file(), "Run: python scripts/generate_sample_pcap.py"

    ng_path = tmp_path / "lab_demo.pcapng"
    with open(sample, "rb") as src, open(ng_path, "wb") as dst:
        classic = dpkt.pcap.Reader(src)
        writer = dpkt.pcapng.Writer(dst, snaplen=65535, linktype=classic.datalink())
        for ts, buf in classic:
            writer.writepkt(buf, ts)

    parsed_ng = load_pcap(str(ng_path))
    parsed_pcap = load_pcap(str(sample))
    assert parsed_ng.packet_count == parsed_pcap.packet_count
    assert parsed_ng.packet_count > 0
    assert len(parsed_ng.dns_queries) == len(parsed_pcap.dns_queries)
