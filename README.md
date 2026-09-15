# Flowscope

[![CI](https://github.com/dRafaleD/flowscope/actions/workflows/ci.yml/badge.svg)](https://github.com/dRafaleD/flowscope/actions)

Flowscope is an offline **PCAP / PCAPNG** analyzer for network security learning. It reads a capture you already have, reconstructs DNS, HTTP, TCP, and TLS metadata, and writes a terminal report plus optional JSON and HTML.

It does not decrypt TLS, does not scan live networks, and does not execute payloads. Heuristics are explainable and threshold-based; they are not malware verdicts.

> Analyze captures you own or are authorized to inspect.

## What it reports

| Area | Behavior |
|------|----------|
| DNS | Queries and responses, burst rate, NXDOMAIN ratio, high-entropy names |
| HTTP | Cleartext requests (port 80 or HTTP magic bytes), Host header |
| TCP | Top flows, SYN counts, uncommon destination ports |
| Scan heuristics | Vertical (many ports, one host) and horizontal (one port, many hosts) |
| Beaconing | Low-variance inter-arrival times on a flow |
| Credentials | FTP, Telnet, HTTP Basic, and form hints — secrets redacted |
| TLS fingerprints | SNI, JA3, JA3S, JA4 (no decryption; GREASE stripped) |
| GeoIP | RFC1918 / TEST-NET labels; optional MaxMind country MMDB |
| Risk score | Per-category caps, then a global cap at 100, with MITRE ATT&CK IDs |

Link layers: Ethernet (including 802.1Q VLAN), Linux cooked capture (SLL), and raw IP.

## Requirements

- Python 3.10+
- [dpkt](https://github.com/kbandla/dpkt) and [rich](https://github.com/Textualize/rich)

Optional: `maxminddb` plus a MaxMind GeoLite2 `.mmdb` for country labels.

## Install

```console
git clone https://github.com/dRafaleD/flowscope.git
cd flowscope
python -m venv .venv
```

Windows:

```console
.venv\Scripts\activate
pip install -e ".[dev]"
```

Linux / macOS:

```console
source .venv/bin/activate
pip install -e ".[dev]"
```

## Quick start

```console
python scripts/generate_sample_pcap.py
flowscope samples/lab_demo.pcap -o report.json --html report.html
```

The lab capture is synthetic and safe to share. Expected scored findings after generate:

```text
Risk score: 90/100

High DNS query rate                     T1071.004
Possible vertical port scan             T1046
Beacon-like periodic traffic            T1071
Plaintext credential risk (FTP)         T1040
Plaintext credential risk (HTTP-Basic)  T1040
SNI hostname to IP destination          T1573
```

Informational rows (DNS/TLS summaries, TEST-NET labels) do not add to the score.

## Usage

```console
flowscope capture.pcap
flowscope capture.pcapng -o analysis.json
flowscope capture.pcap --html report.html
flowscope capture.pcap --min-severity high --html report.html
flowscope capture.pcap --geoip GeoLite2-Country.mmdb -o report.json --html report.html
flowscope capture.pcap -o report.json --html report.html -q
```

`--min-severity` hides lower scored rows in the CLI and HTML tables. JSON always contains the full finding list.

### GeoIP

Without `--geoip`, Flowscope still labels private, loopback, and RFC 5737 TEST-NET ranges.

1. Download **GeoLite2-Country.mmdb** (or City) from [MaxMind](https://www.maxmind.com/).
2. `pip install -e ".[geoip]"`
3. `flowscope capture.pcap --geoip path/to/GeoLite2-Country.mmdb`

## How scoring works

Only findings with `score_delta > 0` count. Totals are capped per category, then capped globally at 100:

| Category | Cap |
|----------|-----|
| credentials | 30 |
| scan | 20 |
| dns | 15 |
| beacon | 15 |
| tls | 10 |
| http / ports / geoip | 5 |

Thresholds live in `src/flowscope/detectors.py` and are intended to be readable, not hidden.

| Detection | Default threshold | MITRE |
|-----------|-------------------|-------|
| High DNS query rate | ≥50 queries from one source in 10s | T1071.004 |
| High NXDOMAIN rate | ≥40% of responses and ≥10 NXDOMAIN | T1071.004 |
| High-entropy DNS names | ≥5 distinct long, high-entropy qnames | T1071.004 |
| Vertical port scan | ≥15 unique dest ports, SYN, 30s window | T1046 |
| Horizontal scan | SYN to the same port on ≥10 hosts | T1046 |
| Beacon-like traffic | ≥8 timestamps, mean interval ≥5s, CV ≤0.15 | T1071 |
| Plaintext credentials | FTP / Telnet / HTTP Basic / form body | T1040 |
| TLS / SNI anomalies | Missing SNI, SNI-to-IP, JA3 fan-out, many SNIs | T1573 |

TLS ClientHello reassembly follows a flow even when the handshake is split across segments or uses a non-standard port (magic bytes `0x16 0x03`, plus a small well-known port list).

## Architecture

```text
pcap / pcapng  →  frames (L2)  →  pcap_loader  →  detectors  →  scoring
                                                      │
                                                 geoip enrich
                                                      │
                                           CLI  /  JSON  /  HTML
```

```text
src/flowscope/
  frames.py         Ethernet / VLAN / SLL / raw IP
  pcap_loader.py    pcap + pcapng, HTTP/TLS magic, flow reassembly
  detectors.py      heuristics, MITRE IDs, advice
  scoring.py        category-capped risk score
  engine.py         orchestration
  report.py         Rich CLI + JSON
  report_html.py    HTML dashboard
  geoip.py          private / TEST-NET / optional MMDB
  tls_sni.py        ClientHello / ServerHello metadata
  ja3.py / ja4.py   JA3, JA3S, JA4 (GREASE stripped)
scripts/            lab PCAP generators
samples/lab_demo.pcap
tests/
```

Extra generators (`generate_session_200.py`, `generate_edge_pcap.py`, `generate_mix_pcap.py`) build larger or edge-case lab captures. Those PCAPs are not committed; regenerate them locally.

## Testing

```console
python scripts/generate_sample_pcap.py
python -m pytest tests/ -q
```

CI runs the same path on every push ([`.github/workflows/ci.yml`](.github/workflows/ci.yml)).

## Scope and limitations

- Offline files only. There is no packet capture, port scan, or exploit module.
- TLS is metadata-only. SNI and fingerprints come from the handshake; application data is not decrypted.
- Heuristics can false-positive (for example SNI-to-IP on CDNs). Read the evidence fields before treating a row as malicious.
- Credential findings redact secrets; they are not a substitute for rotating anything that appeared in a real capture.
- Windows consoles that are not UTF-8 may garble a few punctuation characters in the terminal UI. JSON and HTML reports are UTF-8.

## License

MIT — see [LICENSE](LICENSE).

## Responsible use

Use Flowscope only on traffic you are allowed to inspect. It is a learning and triage aid, not a complete investigation or a courtroom artifact. Correlate findings with the original capture in Wireshark (or equivalent) before you act.
