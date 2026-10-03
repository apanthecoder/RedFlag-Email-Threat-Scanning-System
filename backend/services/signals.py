"""Builds the signal dicts that a score is made of.

Every point in the final score comes from one of these. evidence is saved
as JSON in scans.signals, so it has to be JSON-serialisable. Don't pass
raw bytes or a whole parser dict.
"""

from __future__ import annotations

from typing import Any


def make_signal(
    category: str,
    signal: str,
    points: int,
    explanation: str,
    evidence: dict[str, Any] | None = None,
    severity: str = "MEDIUM",
) -> dict:
    return {
        "category": category,
        "signal": signal,
        "points": points,
        "severity": severity,
        "explanation": explanation,
        "evidence": evidence or {},
    }
