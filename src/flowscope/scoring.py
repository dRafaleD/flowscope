from __future__ import annotations

from collections import defaultdict

from flowscope.models import Finding

_SCORE_CAP = 100
_CATEGORY_CAPS = {
    "credentials": 30,
    "scan": 20,
    "dns": 15,
    "beacon": 15,
    "tls": 10,
    "http": 5,
    "ports": 5,
    "geoip": 5,
}


def aggregate_score(findings: list[Finding]) -> int:
    """Sum positive score_delta per category, apply per-category caps, then global cap."""
    by_cat: dict[str, int] = defaultdict(int)
    for finding in findings:
        if finding.score_delta > 0:
            by_cat[finding.category] += finding.score_delta
    total = 0
    for category, value in by_cat.items():
        total += min(value, _CATEGORY_CAPS.get(category, 20))
    return min(total, _SCORE_CAP)


def scored_finding_count(findings: list[Finding]) -> int:
    return sum(1 for f in findings if f.score_delta > 0)
