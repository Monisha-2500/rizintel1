"""
Pydantic models for the M5 -> M6 "RiskAssessedFinding" contract.

Source of truth: PS4 - Standardized Module Interface Contract v1.0, Section 8.

RULES FOLLOWED:
- Field names are exactly as specified in the contract. Nothing renamed.
- Scales are exactly as specified (CVSS 0-10, EPSS/confidence/consensus 0-1,
  risk_score 0-100). Nothing silently converted.
- Categorical values are uppercase, matching the contract's convention.

Anywhere the contract only gave a single example value for an enum (rather
than a full value set), that is called out explicitly as a
PROPOSED IMPLEMENTATION DECISION in a comment, and the model favors NOT
rejecting data over guessing at an incomplete enum.
"""

from __future__ import annotations

from typing import List, Optional

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# asset_context
# ---------------------------------------------------------------------------

class AssetContext(BaseModel):
    asset_id: str
    asset_name: Optional[str] = None

    # PROPOSED IMPLEMENTATION DECISION: contract Section 8 example only shows
    # "PRODUCTION". Full value set not specified. Using the standard
    # three-tier convention; update here if the team's contract defines more.
    environment: Optional[str] = None  # e.g. "PRODUCTION" | "STAGING" | "DEVELOPMENT"

    # PROPOSED IMPLEMENTATION DECISION: same as above, only "CRITICAL" shown.
    criticality: Optional[str] = None  # e.g. "CRITICAL" | "HIGH" | "MEDIUM" | "LOW"

    internet_facing: Optional[bool] = None
    data_sensitivity: Optional[str] = None


# ---------------------------------------------------------------------------
# threat_intelligence (optional block per Test 7 - missing optional threat intel)
# ---------------------------------------------------------------------------

class ThreatIntelligence(BaseModel):
    cvss_score: Optional[float] = Field(None, ge=0, le=10)
    cvss_vector: Optional[str] = None
    epss_score: Optional[float] = Field(None, ge=0, le=1)
    epss_percentile: Optional[float] = Field(None, ge=0, le=1)
    kev_listed: Optional[bool] = None
    exploit_available: Optional[bool] = None
    exploit_sources: List[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# scanner_consensus (optional block)
# ---------------------------------------------------------------------------

class ScannerConsensus(BaseModel):
    score: Optional[float] = Field(None, ge=0, le=1)
    scanner_names: List[str] = Field(default_factory=list)
    detected_by_count: Optional[int] = Field(None, ge=0)
    total_scanners: Optional[int] = Field(None, ge=0)


# ---------------------------------------------------------------------------
# finding_confidence
# ---------------------------------------------------------------------------

class FindingConfidence(BaseModel):
    score: Optional[float] = Field(None, ge=0, le=1)
    # PROPOSED IMPLEMENTATION DECISION: contract only shows "CONFIRMED" as an
    # example. Left as an open string (not a restricted enum) since the full
    # value set isn't specified and we should not reject valid upstream data
    # we haven't been told about.
    classification: Optional[str] = None


# ---------------------------------------------------------------------------
# risk_assessment - OWNED ENTIRELY BY M5. M6 treats this as read-only.
# ---------------------------------------------------------------------------

class ScoreBreakdown(BaseModel):
    cvss_contribution: Optional[float] = None
    epss_contribution: Optional[float] = None
    kev_contribution: Optional[float] = None
    exploit_contribution: Optional[float] = None
    asset_criticality_contribution: Optional[float] = None
    exposure_contribution: Optional[float] = None
    scanner_confidence_contribution: Optional[float] = None


class RiskAssessment(BaseModel):
    risk_score: float = Field(..., ge=0, le=100)

    # PROPOSED IMPLEMENTATION DECISION: contract example shows "CRITICAL".
    # Using the standard 5-tier convention consistent with earlier team
    # discussion; update if the frozen contract defines a different set.
    risk_level: str

    score_breakdown: Optional[ScoreBreakdown] = None
    scoring_version: Optional[str] = None


# ---------------------------------------------------------------------------
# metadata
# ---------------------------------------------------------------------------

class InputMetadata(BaseModel):
    generated_by: str = "M5"
    timestamp: str


# ---------------------------------------------------------------------------
# Top-level RiskAssessedFinding
# ---------------------------------------------------------------------------

class RiskAssessedFinding(BaseModel):
    schema_version: str = "1.0"
    finding_id: str

    # Test 2 requires: cve_id = null must still work.
    cve_id: Optional[str] = None

    vulnerability_name: Optional[str] = None
    description: Optional[str] = None

    asset_context: AssetContext

    # Test 7 requires: missing optional threat intelligence must be handled
    # gracefully -> optional block.
    threat_intelligence: Optional[ThreatIntelligence] = None

    scanner_consensus: Optional[ScannerConsensus] = None
    finding_confidence: Optional[FindingConfidence] = None

    # Required: this is the one thing M6 cannot function without.
    risk_assessment: RiskAssessment

    metadata: Optional[InputMetadata] = None
