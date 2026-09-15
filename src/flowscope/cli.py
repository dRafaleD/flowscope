from __future__ import annotations

import argparse
import sys
from pathlib import Path

from flowscope.engine import analyze_pcap
from flowscope.frames import CaptureError
from flowscope.report import SEVERITY_RANK, print_console, write_json
from flowscope.report_html import write_html


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Offline PCAP analyzer for network security learning (DNS, HTTP, scans, beaconing).",
    )
    parser.add_argument("pcap", type=Path, help="Path to .pcap or .pcapng file")
    parser.add_argument("-o", "--json", type=Path, help="Write JSON report to file")
    parser.add_argument("--html", type=Path, help="Write HTML report to file")
    parser.add_argument(
        "--geoip",
        type=Path,
        help="MaxMind GeoLite2/GeoIP2 .mmdb for country enrichment (pip install maxminddb)",
    )
    parser.add_argument(
        "--min-severity",
        choices=tuple(SEVERITY_RANK),
        default="low",
        help="Hide scored findings below this severity in CLI and HTML (JSON stays complete)",
    )
    parser.add_argument("-q", "--quiet", action="store_true", help="Skip terminal UI when exporting to file")
    args = parser.parse_args(argv)

    if not args.pcap.is_file():
        print(f"File not found: {args.pcap}", file=sys.stderr)
        return 1
    if args.geoip and not args.geoip.is_file():
        print(f"GeoIP database not found: {args.geoip}", file=sys.stderr)
        return 1

    try:
        report = analyze_pcap(str(args.pcap), geoip_mmdb=args.geoip)
    except CaptureError as exc:
        print(str(exc) or "unsupported capture", file=sys.stderr)
        return 1
    except Exception as exc:
        print(f"unsupported or corrupt capture: {exc}", file=sys.stderr)
        return 1

    if report.packet_count == 0:
        print("no packets in capture", file=sys.stderr)
        return 1

    if args.json:
        write_json(report, str(args.json))
    if args.html:
        write_html(report, str(args.html), min_severity=args.min_severity)
    if not (args.quiet and (args.json or args.html)):
        print_console(report, min_severity=args.min_severity)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
