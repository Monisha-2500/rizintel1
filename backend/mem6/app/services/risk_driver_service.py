"""
Deterministic top_risk_drivers extraction.

PROPOSED IMPLEMENTATION DECISION (documented per Section 22 instructions):
The PS4 contract requires M6 to identify "the most significant risk drivers"
from M5's score_breakdown, but does not specify the exact derivation
algorithm. This module implements it as pure, deterministic code -- NOT
via the LLM -- so the drivers can never diverge from M5's own numbers.

Algorithm:
1. If risk_assessment.score_breakdown is present: map each contribution
   key to a fixed label, sort by contribution value descending, keep
   only positive contributions, return the top `max_drivers`.
2. If score_breakdown is absent: fall back to a simple boolean/threshold
   check on the raw threat_intelligence / asset_context / scanner_consensus
   fields (still zero invention -- every label maps 1:1 to a field M5
   actually sent).
"""

from __future__ import annotations

from app.models.input_models import RiskAssessedFinding

_BREAKDOWN_LABEL_MAP = {
    "cvss_contribution": "HIGH_CVSS",
    "epss_contribution": "HIGH_EPSS",
    "kev_contribution": "KEV_LISTED",
    "exploit_contribution": "EXPLOIT_AVAILABLE",
    "asset_criticality_contribution": "CRITICAL_ASSET",
    "exposure_contribution": "INTERNET_FACING",
    "scanner_confidence_contribution": "HIGH_SCANNER_CONSENSUS",
}


def _from_score_breakdown(finding: RiskAssessedFinding, max_drivers: int) -> list[str]:
    breakdown = finding.risk_assessment.score_breakdown
    ti = finding.threat_intelligence
    ac = finding.asset_context
    sc = finding.scanner_consensus

    pairs: list[tuple[str, float]] = []
    for field_name, label in _BREAKDOWN_LABEL_MAP.items():
        value = getattr(breakdown, field_name, None)
        if value is None or value <= 0:
            continue

        # Filter out labels when underlying values do not warrant the driver label
        if label == "HIGH_CVSS":
            if ti and ti.cvss_score is not None and ti.cvss_score < 7.0:
                continue
            elif not ti and value < 18.0:
                continue

        if label == "HIGH_EPSS":
            if ti and ti.epss_score is not None and ti.epss_score < 0.70:
                continue
            elif not ti and value < 14.0:
                continue

        if label == "KEV_LISTED" and ti and not ti.kev_listed:
            continue

        if label == "EXPLOIT_AVAILABLE" and ti and not ti.exploit_available:
            continue

        if label == "CRITICAL_ASSET" and ac and ac.criticality and ac.criticality.upper() not in ("CRITICAL", "HIGH"):
            continue

        if label == "INTERNET_FACING" and ac and not ac.internet_facing:
            continue

        pairs.append((label, value))

    pairs.sort(key=lambda p: p[1], reverse=True)
    return [label for label, _ in pairs[:max_drivers]]


def _from_raw_fields_fallback(finding: RiskAssessedFinding, max_drivers: int) -> list[str]:
    """Used only when M5 didn't supply score_breakdown at all."""
    labels: list[str] = []
    ti = finding.threat_intelligence
    ac = finding.asset_context
    sc = finding.scanner_consensus

    if ti:
        if ti.cvss_score is not None and ti.cvss_score >= 7.0:
            labels.append("HIGH_CVSS")
        if ti.epss_score is not None and ti.epss_score >= 0.7:
            labels.append("HIGH_EPSS")
        if ti.kev_listed:
            labels.append("KEV_LISTED")
        if ti.exploit_available:
            labels.append("EXPLOIT_AVAILABLE")

    if ac and ac.criticality and ac.criticality.upper() in ("CRITICAL", "HIGH"):
        labels.append("CRITICAL_ASSET")
    if ac and ac.internet_facing:
        labels.append("INTERNET_FACING")

    if sc and sc.score is not None and sc.score >= 0.8:
        labels.append("HIGH_SCANNER_CONSENSUS")

    return labels[:max_drivers]


def extract_top_risk_drivers(finding: RiskAssessedFinding, max_drivers: int = 4) -> list[str]:
    if finding.risk_assessment.score_breakdown is not None:
        drivers = _from_score_breakdown(finding, max_drivers)
        if drivers:
            return drivers
    return _from_raw_fields_fallback(finding, max_drivers)
