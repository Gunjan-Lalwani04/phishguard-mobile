"""Aggregates a list of Findings into a single risk score and level.

Thresholds are tuned lower than a typical multi-signal email scan because a
bare URL or QR scan usually has only one analyzer (links) contributing at
all, so a single strong finding (e.g. a confirmed typosquat domain) needs to
stand on its own rather than requiring corroborating signals to register as
high risk.
"""

from __future__ import annotations

from core.models import Finding

MAX_SCORE = 100

_RISK_THRESHOLDS = [
    (15, "CRITICAL"),
    (9, "HIGH"),
    (5, "MEDIUM"),
    (0, "LOW"),
]


def risk_level_for_score(score: int) -> str:
    for threshold, label in _RISK_THRESHOLDS:
        if score >= threshold:
            return label
    return "LOW"


def score_findings(findings: list[Finding]) -> int:
    raw = sum(int(f.severity) for f in findings)
    return min(raw, MAX_SCORE)
