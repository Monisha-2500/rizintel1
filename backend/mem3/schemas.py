"""
Schemas for M3 (Confidence / Noise).

These are NOT a new contract — they are a direct Pydantic transcription of
PS4 Interface Contract v1.0, Section 4 (M2 -> M3 input) and Section 5
(M3 -> M4 output). M3 does not invent field names, does not require M2 to
change its output shape, and does not rename any canonical field
(finding_id, cve_id, asset_id, scanner_consensus, etc.).

If M2's actual output ever drifts from Section 4, fix M2's output or bump
schema_version per the contract's own change-control rule (Section 13) —
don't patch this file to silently accept a different shape.
"""

from __future__ import annotations

from typing import Optional
from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Section 4 — DeduplicatedFinding (M2 -> M3). This is M3's INPUT. Read-only
# from M3's perspective — M3 must not mutate or drop any of these fields.
# ---------------------------------------------------------------------------

class Asset(BaseModel):
    asset_id: str
    host: str
    endpoint: Optional[str] = None
    port: Optional[int] = None
    parameter: Optional[str] = None


class MatchFeatures(BaseModel):
    cve_match: Optional[float] = None
    host_match: Optional[float] = None
    endpoint_similarity: Optional[float] = None
    parameter_match: Optional[float] = None
    vulnerability_similarity: Optional[float] = None


class Deduplication(BaseModel):
    duplicate_count: int
    merged_finding_ids: list[str] = Field(default_factory=list)
    match_method: Optional[str] = None          # e.g. "HYBRID", "DETERMINISTIC", "NONE"
    match_score: Optional[float] = None          # 0.0-1.0, per Section 12 dictionary
    match_features: Optional[MatchFeatures] = None


class ScannerConsensus(BaseModel):
    scanner_names: list[str] = Field(default_factory=list)
    detected_by_count: int
    total_scanners: int
    score: float                                 # 0.0-1.0 (detected_by_count / total_scanners)


class SourceFinding(BaseModel):
    finding_id: str
    scanner: str
    evidence: Optional[str] = None


class DeduplicatedFinding(BaseModel):
    """Exact shape of Section 4. This is what M2 hands to M3."""
    schema_version: str = "1.0"
    finding_id: str
    member_source: Optional[str] = None
    cve_id: Optional[str] = None
    vulnerability_name: str
    vulnerability_type: Optional[str] = None
    severity: Optional[str] = None                # LOW/MEDIUM/HIGH/CRITICAL, context only per Section 3
    asset: Asset
    deduplication: Deduplication
    scanner_consensus: ScannerConsensus
    source_findings: list[SourceFinding] = Field(default_factory=list)
    first_seen: Optional[str] = None
    last_seen: Optional[str] = None


# ---------------------------------------------------------------------------
# Section 5 — ConfidenceEnrichedFinding (M3 -> M4). This is M3's OUTPUT.
# Matches the contract's own worked example field-for-field. The one
# addition ("reason_codes") is explicitly allowed under Section 13's rule
# that a module may add fields but must not remove required ones.
# ---------------------------------------------------------------------------

class ConfidenceSignals(BaseModel):
    """
    Per M3's brief: confidence must NOT be scanner-count alone (M2 already
    computes that as scanner_consensus.score). These five signals combine
    M2's own consensus/match outputs with independent evidence checks.
    """
    scanner_consensus: float          # passthrough of M2's scanner_consensus.score
    match_confidence: float           # passthrough of M2's deduplication.match_score
    evidence_strength: float          # derived: how much real evidence backs the merge
    cross_scanner_consistency: float  # derived: do M2's match_features agree with each other
    data_completeness: float          # derived: how many expected fields are actually populated


class FindingConfidence(BaseModel):
    score: float                      # 0.0-1.0, weighted combination of the five signals
    classification: str               # CONFIRMED | HIGH_CONFIDENCE | NEEDS_REVIEW | LIKELY_NOISE
    signals: ConfidenceSignals
    reason_codes: list[str] = Field(default_factory=list)
    review_required: bool


class NoiseAssessment(BaseModel):
    likely_noise: bool
    reason: Optional[str] = None


class ConfidenceEnrichedFinding(BaseModel):
    """Exact shape of Section 5, passed forward to M4."""
    schema_version: str = "1.0"
    finding_id: str
    cve_id: Optional[str] = None
    vulnerability_name: str
    vulnerability_type: Optional[str] = None
    severity: Optional[str] = None
    asset: Asset
    scanner_consensus: ScannerConsensus
    finding_confidence: FindingConfidence
    noise_assessment: NoiseAssessment
    source_findings: list[str] = Field(default_factory=list)   # IDs only, per Section 5's example
