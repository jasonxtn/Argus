"""
Structured Severity Scoring System
Replaces the crude regex-based keyword matching with a proper scoring framework.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List, Optional


@dataclass
class SeverityScore:
    """Detailed severity assessment for a finding or module output."""
    impact: int             # /25 — How damaging is this if exploited
    exploitability: int     # /25 — How easy to exploit
    confidence: int         # /25 — How certain are we about this finding
    relevance: int          # /25 — How relevant to the assessment goals
    label: str = ""         # critical, high, medium, low, info

    @property
    def total(self) -> int:
        return self.impact + self.exploitability + self.confidence + self.relevance

    @property
    def normalized_label(self) -> str:
        if self.label:
            return self.label
        t = self.total
        if t >= 80:
            return "critical"
        if t >= 60:
            return "high"
        if t >= 40:
            return "medium"
        if t >= 20:
            return "low"
        return "info"


# Pattern-based severity detection with scoring
_SEVERITY_RULES = [
    # (pattern, impact, exploitability, confidence, label)
    (re.compile(r"\b(?:critical|severe)\b", re.I), 25, 20, 20, "critical"),
    (re.compile(r"\b(?:exploit|compromise|rce|injection)\b", re.I), 25, 25, 15, "critical"),
    (re.compile(r"\b(?:vulnerable|vulnerability|cve-\d{4})\b", re.I), 20, 15, 20, "high"),
    (re.compile(r"\bexpired\b", re.I), 15, 10, 25, "high"),
    (re.compile(r"\b(?:high\s*risk|alert)\b", re.I), 18, 12, 18, "high"),
    (re.compile(r"\b(?:warning|warn|risk|exposed|misconfigur)", re.I), 12, 10, 18, "medium"),
    (re.compile(r"\b(?:weak|deprecated|outdated|insecure)\b", re.I), 10, 10, 20, "medium"),
    (re.compile(r"\b(?:missing|absent|not\s+found|disabled)\b", re.I), 8, 5, 20, "low"),
    (re.compile(r"\b(?:ok|secure|valid|passed|enabled)\b", re.I), 0, 0, 25, "info"),
]


def score_text(text: str) -> SeverityScore:
    """Score a block of text for severity based on content analysis."""
    best = SeverityScore(impact=0, exploitability=0, confidence=15, relevance=10, label="info")

    for pattern, impact, exploit, conf, label in _SEVERITY_RULES:
        if pattern.search(text):
            candidate = SeverityScore(
                impact=impact,
                exploitability=exploit,
                confidence=conf,
                relevance=15,
                label=label,
            )
            if candidate.total > best.total:
                best = candidate

    return best


def score_output(full_output: str) -> SeverityScore:
    """
    Score entire module output. Uses the highest severity found
    across all lines, with confidence boosted by consistency.
    """
    if not full_output.strip():
        return SeverityScore(impact=0, exploitability=0, confidence=0, relevance=0, label="info")

    line_scores: List[SeverityScore] = []
    for line in full_output.splitlines():
        line = line.strip()
        if line:
            line_scores.append(score_text(line))

    if not line_scores:
        return SeverityScore(impact=0, exploitability=0, confidence=0, relevance=0, label="info")

    # Take the highest severity finding
    best = max(line_scores, key=lambda s: s.total)

    # Boost confidence if multiple lines agree on severity
    same_severity = sum(1 for s in line_scores if s.normalized_label == best.normalized_label)
    if same_severity > 1:
        confidence_boost = min(5, same_severity - 1)
        best = SeverityScore(
            impact=best.impact,
            exploitability=best.exploitability,
            confidence=min(25, best.confidence + confidence_boost),
            relevance=best.relevance,
            label=best.label,
        )

    return best


def severity_to_legacy(score: SeverityScore) -> str:
    """Map structured severity back to legacy labels for backward compatibility."""
    label = score.normalized_label
    mapping = {
        "critical": "ALERT",
        "high": "ALERT",
        "medium": "WARN",
        "low": "OK",
        "info": "INFO",
    }
    return mapping.get(label, "INFO")
