"""
M3 — Confidence / Noise scoring engine.

Consumes a DeduplicatedFinding (Section 4) and produces the finding_confidence
and noise_assessment blocks required by Section 5. Deliberately does NOT
touch deduplication, threat intel, risk scoring, explanations, SLA, or
dashboard logic — those stay with M2/M4/M5/M6/M7/M8 respectively.

Design brief this follows (from the team):
  "Don't base confidence only on scanner count because M2 already
   calculates scanner consensus. Use multiple signals: scanner consensus +
   M2 match confidence + evidence strength + cross-scanner consistency +
   data completeness."

So scanner count only enters indirectly, via M2's own
scanner_consensus.score — it is one of five roughly-equal-weighted signals,
not the whole story.
"""

from __future__ import annotations

from dataclasses import dataclass

from schemas import (
    ConfidenceEnrichedFinding,
    ConfidenceSignals,
    DeduplicatedFinding,
    FindingConfidence,
    NoiseAssessment,
)

# ---------------------------------------------------------------------------
# Weights (sum to 1.0). This is the one "policy" surface of the module —
# tune here, not scattered through the logic below.
# ---------------------------------------------------------------------------

WEIGHTS = {
    "scanner_consensus": 0.25,
    "match_confidence": 0.25,
    "evidence_strength": 0.20,
    "cross_scanner_consistency": 0.15,
    "data_completeness": 0.15,
}
assert abs(sum(WEIGHTS.values()) - 1.0) < 1e-9

CLASSIFICATION_THRESHOLDS = [
    (0.90, "CONFIRMED"),
    (0.75, "HIGH_CONFIDENCE"),
    (0.50, "NEEDS_REVIEW"),
    (0.0, "LIKELY_NOISE"),
]


def _clamp01(x: float) -> float:
    return max(0.0, min(1.0, x))


# ---------------------------------------------------------------------------
# Signal 1 — Scanner consensus (passthrough of M2's own number)
# ---------------------------------------------------------------------------

def _scanner_consensus_signal(finding: DeduplicatedFinding) -> tuple[float, list[str]]:
    score = _clamp01(finding.scanner_consensus.score)
    codes = []
    if finding.scanner_consensus.detected_by_count <= 1:
        codes.append("SINGLE_SCANNER_DETECTION")
    elif score >= 0.99:
        codes.append("FULL_SCANNER_CONSENSUS")
    return score, codes


# ---------------------------------------------------------------------------
# Signal 2 — M2's own match confidence (passthrough, with graceful fallback
# for malformed/partial data where match_score is missing)
# ---------------------------------------------------------------------------

def _match_confidence_signal(finding: DeduplicatedFinding) -> tuple[float, list[str]]:
    ms = finding.deduplication.match_score
    if ms is None:
        return 0.5, ["MISSING_MATCH_SCORE"]
    score = _clamp01(ms)
    codes = ["HIGH_M2_MATCH_CONFIDENCE"] if score >= 0.85 else []
    if score < 0.5:
        codes.append("LOW_M2_MATCH_CONFIDENCE")
    return score, codes


# ---------------------------------------------------------------------------
# Signal 3 — Evidence strength: independent of M2's scoring, checks whether
# the merged finding is actually backed by real evidence text, not just an
# assertion. A finding with 3 merged scanners but zero evidence text is
# weaker than M2's match_score alone would suggest.
# ---------------------------------------------------------------------------

def _evidence_strength_signal(finding: DeduplicatedFinding) -> tuple[float, list[str]]:
    sources = finding.source_findings
    if not sources:
        return 0.3, ["NO_SOURCE_FINDINGS_LISTED"]

    with_evidence = [s for s in sources if s.evidence and s.evidence.strip()]
    ratio = len(with_evidence) / len(sources)

    codes = []
    if ratio == 0:
        codes.append("NO_EVIDENCE_TEXT_PRESENT")
    elif ratio < 0.5:
        codes.append("PARTIAL_EVIDENCE_COVERAGE")
    elif ratio == 1.0 and len(sources) > 1:
        codes.append("FULL_EVIDENCE_COVERAGE")

    return _clamp01(ratio), codes


# ---------------------------------------------------------------------------
# Signal 4 — Cross-scanner consistency: do M2's own match_features agree
# with each other? A finding where cve_match=1.0 but endpoint_similarity=0.2
# is internally inconsistent — M2 merged it, but the underlying signals
# disagree about how confident that merge should be. A single-source
# finding (duplicate_count == 1) has nothing to cross-validate against, so
# it gets a fixed neutral value rather than a spuriously high or low one.
# ---------------------------------------------------------------------------

def _cross_scanner_consistency_signal(finding: DeduplicatedFinding) -> tuple[float, list[str]]:
    if finding.deduplication.duplicate_count <= 1:
        return 0.5, ["SINGLE_SOURCE_NO_CROSS_VALIDATION"]

    mf = finding.deduplication.match_features
    if mf is None:
        return 0.5, ["MISSING_MATCH_FEATURES"]

    values = [v for v in [mf.cve_match, mf.host_match, mf.endpoint_similarity,
                           mf.parameter_match, mf.vulnerability_similarity] if v is not None]
    if len(values) < 2:
        return 0.5, ["INSUFFICIENT_MATCH_FEATURES"]

    spread = max(values) - min(values)
    consistency = _clamp01(1.0 - spread)

    codes = []
    if spread > 0.4:
        codes.append("INCONSISTENT_MATCH_FEATURES")
    elif consistency >= 0.9:
        codes.append("HIGHLY_CONSISTENT_MATCH_FEATURES")
    return consistency, codes


# ---------------------------------------------------------------------------
# Signal 5 — Data completeness: how many of the fields M4/M5 downstream
# will actually want are populated. A missing CVE alone should NOT crater
# this to zero (CVE-less findings — e.g. missing security headers — are
# legitimate and expected), so this is a soft, partial-credit signal.
# ---------------------------------------------------------------------------

_COMPLETENESS_FIELDS_WEIGHT = {
    "cve_id": 0.20,
    "vulnerability_type": 0.20,
    "severity": 0.20,
    "asset.endpoint": 0.20,
    "asset.port": 0.20,
}


def _data_completeness_signal(finding: DeduplicatedFinding) -> tuple[float, list[str]]:
    present = 0.0
    codes = []

    if finding.cve_id:
        present += _COMPLETENESS_FIELDS_WEIGHT["cve_id"]
    else:
        codes.append("MISSING_CVE_ID")

    if finding.vulnerability_type:
        present += _COMPLETENESS_FIELDS_WEIGHT["vulnerability_type"]
    else:
        codes.append("MISSING_VULNERABILITY_TYPE")

    if finding.severity:
        present += _COMPLETENESS_FIELDS_WEIGHT["severity"]
    else:
        codes.append("MISSING_SEVERITY")

    if finding.asset.endpoint:
        present += _COMPLETENESS_FIELDS_WEIGHT["asset.endpoint"]
    if finding.asset.port:
        present += _COMPLETENESS_FIELDS_WEIGHT["asset.port"]

    return _clamp01(present), codes


# ---------------------------------------------------------------------------
# Classification + noise assessment
# ---------------------------------------------------------------------------

def _classify(score: float) -> str:
    for threshold, label in CLASSIFICATION_THRESHOLDS:
        if score >= threshold:
            return label
    return "LIKELY_NOISE"  # unreachable given the 0.0 floor above, kept for safety


def _noise_assessment(finding: DeduplicatedFinding, classification: str,
                       all_codes: list[str]) -> NoiseAssessment:
    if classification != "LIKELY_NOISE":
        return NoiseAssessment(likely_noise=False, reason=None)

    # Build a short human-readable reason from whichever weak signals fired.
    weak_reasons = []
    if "SINGLE_SCANNER_DETECTION" in all_codes:
        weak_reasons.append("only one scanner detected this finding")
    if "NO_EVIDENCE_TEXT_PRESENT" in all_codes:
        weak_reasons.append("no supporting evidence text")
    if "LOW_M2_MATCH_CONFIDENCE" in all_codes:
        weak_reasons.append("low deduplication match confidence")
    if "INCONSISTENT_MATCH_FEATURES" in all_codes:
        weak_reasons.append("inconsistent match signals from M2")
    if not weak_reasons:
        weak_reasons.append("combined confidence signals fell below the noise threshold")

    return NoiseAssessment(likely_noise=True, reason="; ".join(weak_reasons).capitalize())


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def assess_confidence(finding: DeduplicatedFinding) -> ConfidenceEnrichedFinding:
    scanner_consensus, c1 = _scanner_consensus_signal(finding)
    match_confidence, c2 = _match_confidence_signal(finding)
    evidence_strength, c3 = _evidence_strength_signal(finding)
    cross_scanner_consistency, c4 = _cross_scanner_consistency_signal(finding)
    data_completeness, c5 = _data_completeness_signal(finding)

    score = _clamp01(
        WEIGHTS["scanner_consensus"] * scanner_consensus
        + WEIGHTS["match_confidence"] * match_confidence
        + WEIGHTS["evidence_strength"] * evidence_strength
        + WEIGHTS["cross_scanner_consistency"] * cross_scanner_consistency
        + WEIGHTS["data_completeness"] * data_completeness
    )
    score = round(score, 4)

    classification = _classify(score)
    all_codes = c1 + c2 + c3 + c4 + c5
    review_required = classification == "NEEDS_REVIEW"

    finding_confidence = FindingConfidence(
        score=score,
        classification=classification,
        signals=ConfidenceSignals(
            scanner_consensus=round(scanner_consensus, 4),
            match_confidence=round(match_confidence, 4),
            evidence_strength=round(evidence_strength, 4),
            cross_scanner_consistency=round(cross_scanner_consistency, 4),
            data_completeness=round(data_completeness, 4),
        ),
        reason_codes=all_codes,
        review_required=review_required,
    )

    noise_assessment = _noise_assessment(finding, classification, all_codes)

    return ConfidenceEnrichedFinding(
        schema_version=finding.schema_version,
        finding_id=finding.finding_id,
        cve_id=finding.cve_id,
        vulnerability_name=finding.vulnerability_name,
        vulnerability_type=finding.vulnerability_type,
        severity=finding.severity,
        asset=finding.asset,
        scanner_consensus=finding.scanner_consensus,
        finding_confidence=finding_confidence,
        noise_assessment=noise_assessment,
        source_findings=[s.finding_id for s in finding.source_findings],
    )
