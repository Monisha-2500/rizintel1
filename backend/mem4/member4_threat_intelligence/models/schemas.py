"""
models/schemas.py
=================
Pydantic models for Member 4 — Threat Intelligence Enrichment Engine.

Defines:
  - Input  : ConfidenceEnrichedFinding   (M3 → M4 contract)
  - Output : ThreatEnrichedFinding        (M4 → M5 contract)

Source of truth: RizIntel Interface Contract v1.0
Do NOT rename fields. Do NOT change score scales.
"""

from __future__ import annotations

from enum import Enum
from typing import List, Optional

from pydantic import BaseModel, Field, field_validator, model_validator


# ---------------------------------------------------------------------------
# Enumerations  (uppercase categorical values per contract)
# ---------------------------------------------------------------------------

class SchemaVersion(str, Enum):
    V1_0 = "1.0"


class SeverityLevel(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class VulnerabilityType(str, Enum):
    REMOTE_CODE_EXECUTION   = "REMOTE_CODE_EXECUTION"
    PRIVILEGE_ESCALATION    = "PRIVILEGE_ESCALATION"
    SQL_INJECTION           = "SQL_INJECTION"
    CROSS_SITE_SCRIPTING    = "CROSS_SITE_SCRIPTING"
    AUTHENTICATION_BYPASS   = "AUTHENTICATION_BYPASS"
    INFORMATION_DISCLOSURE  = "INFORMATION_DISCLOSURE"
    PATH_TRAVERSAL          = "PATH_TRAVERSAL"
    COMMAND_INJECTION       = "COMMAND_INJECTION"
    SSRF                    = "SSRF"
    DESERIALIZATION         = "DESERIALIZATION"
    BUFFER_OVERFLOW         = "BUFFER_OVERFLOW"
    MEMORY_CORRUPTION       = "MEMORY_CORRUPTION"
    DENIAL_OF_SERVICE       = "DENIAL_OF_SERVICE"
    OPEN_REDIRECT           = "OPEN_REDIRECT"
    XXE                     = "XXE"
    INSECURE_DESERIALIZATION = "INSECURE_DESERIALIZATION"
    OTHER                   = "OTHER"


class ConfidenceClassification(str, Enum):
    CONFIRMED       = "CONFIRMED"
    HIGH_CONFIDENCE = "HIGH_CONFIDENCE"
    NEEDS_REVIEW    = "NEEDS_REVIEW"
    LIKELY_NOISE    = "LIKELY_NOISE"
    UNCLASSIFIED    = "UNCLASSIFIED"


# ---------------------------------------------------------------------------
# Sub-models for the M3 → M4 input
# ---------------------------------------------------------------------------

class Asset(BaseModel):
    """Asset information as provided by Member 3."""

    asset_id:  str           = Field(..., description="Canonical asset identifier. Do NOT rename to 'asset'.")
    host:      str           = Field(..., description="Hostname or IP address of the asset.")
    endpoint:  Optional[str] = Field(None, description="URL path or endpoint on the asset.")
    port:      Optional[int] = Field(None, ge=1, le=65535, description="Port number.")
    parameter: Optional[str] = Field(None, description="Vulnerable parameter name.")


class ScannerConsensus(BaseModel):
    """Scanner agreement metadata produced by Member 2 and passed through Member 3."""

    scanner_names:      List[str] = Field(..., min_length=1, description="Names of scanners that detected this finding.")
    detected_by_count:  int       = Field(..., ge=1, description="Number of scanners that detected the finding.")
    total_scanners:     int       = Field(..., ge=1, description="Total number of scanners in the pipeline.")
    score:              float     = Field(..., ge=0.0, le=1.0, description="Consensus score in range [0.0, 1.0].")

    @field_validator("score")
    @classmethod
    def score_precision(cls, v: float) -> float:
        """Round to 4 decimal places to prevent floating-point drift."""
        return round(v, 4)

    @model_validator(mode="after")
    def detected_le_total(self) -> "ScannerConsensus":
        if self.detected_by_count > self.total_scanners:
            raise ValueError(
                f"detected_by_count ({self.detected_by_count}) cannot exceed "
                f"total_scanners ({self.total_scanners})"
            )
        return self


class ConfidenceSignals(BaseModel):
    """Component signals that compose the overall confidence score."""

    scanner_consensus: float = Field(..., ge=0.0, le=1.0)
    evidence_quality:  float = Field(..., ge=0.0, le=1.0)
    cve_mapping:       float = Field(..., ge=0.0, le=1.0)
    repeatability:     float = Field(..., ge=0.0, le=1.0)


class FindingConfidence(BaseModel):
    """Confidence assessment produced by Member 3."""

    score:            float                    = Field(..., ge=0.0, le=1.0, description="Confidence score in range [0.0, 1.0].")
    classification:   ConfidenceClassification = Field(..., description="Categorical confidence classification.")
    signals:          ConfidenceSignals        = Field(..., description="Component signals contributing to the score.")
    review_required:  bool                     = Field(..., description="Whether manual review is required.")

    @field_validator("score")
    @classmethod
    def score_precision(cls, v: float) -> float:
        return round(v, 4)


class NoiseAssessment(BaseModel):
    """Noise / false-positive assessment produced by Member 3."""

    likely_noise: bool           = Field(..., description="True if Member 3 assessed this as likely noise.")
    reason:       Optional[str]  = Field(None, description="Human-readable reason for the noise assessment.")


# ---------------------------------------------------------------------------
# M3 → M4 input model
# ---------------------------------------------------------------------------

class ConfidenceEnrichedFinding(BaseModel):
    """
    Output of Member 3 (Confidence / Noise Assessment).
    Input to Member 4 (Threat Intelligence Enrichment Engine).

    Field names are canonical per the RizIntel Interface Contract v1.0.
    Do NOT rename any field.
    """

    schema_version:    SchemaVersion            = Field(..., description="Schema version, must be '1.0'.")
    finding_id:        str                      = Field(..., description="Canonical finding identifier from Member 2.")
    cve_id:            Optional[str]            = Field(None, description="CVE identifier, or null if unknown.")
    vulnerability_name: str                     = Field(..., description="Human-readable vulnerability name.")
    vulnerability_type: VulnerabilityType       = Field(..., description="Categorical vulnerability classification.")
    severity:          SeverityLevel            = Field(..., description="Severity level of the finding.")
    asset:             Asset                    = Field(..., description="Asset information.")
    scanner_consensus: ScannerConsensus         = Field(..., description="Scanner agreement metadata.")
    finding_confidence: FindingConfidence       = Field(..., description="Confidence assessment from Member 3.")
    noise_assessment:  NoiseAssessment          = Field(..., description="Noise assessment from Member 3.")
    source_findings:   List[str]                = Field(default_factory=list, description="Source finding IDs from upstream scanners.")

    @field_validator("cve_id")
    @classmethod
    def validate_cve_format(cls, v: Optional[str]) -> Optional[str]:
        """Validate CVE format if provided (CVE-YYYY-NNNNN+)."""
        if v is None:
            return None
        import re
        pattern = r"^CVE-\d{4}-\d{4,}$"
        if not re.match(pattern, v):
            raise ValueError(
                f"cve_id '{v}' does not match expected CVE format 'CVE-YYYY-NNNNN'."
            )
        return v

    @field_validator("finding_id")
    @classmethod
    def validate_finding_id(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("finding_id must not be empty.")
        return v


# ---------------------------------------------------------------------------
# Threat intelligence sub-model  (M4 → M5 output)
# ---------------------------------------------------------------------------

class ThreatIntelligence(BaseModel):
    """
    Threat intelligence data retrieved and normalized by Member 4.

    All fields are nullable — Member 4 MUST NOT fabricate values.
    Actual values replace nulls only when successfully retrieved.
    """

    cvss_score:         Optional[float]      = Field(None, ge=0.0, le=10.0, description="CVSS base score in range [0.0, 10.0].")
    cvss_vector:        Optional[str]        = Field(None, description="CVSS vector string.")
    epss_score:         Optional[float]      = Field(None, ge=0.0, le=1.0,  description="EPSS probability score in range [0.0, 1.0].")
    epss_percentile:    Optional[float]      = Field(None, ge=0.0, le=1.0,  description="EPSS percentile in range [0.0, 1.0].")
    kev_listed:         Optional[bool]       = Field(None, description="True if listed in CISA KEV; false if not; null if KEV is unavailable.")
    kev_date_added:     Optional[str]        = Field(None, description="Date the CVE was added to CISA KEV (ISO 8601 date string).")
    exploit_available:  Optional[bool]       = Field(None, description="True if a public exploit is known; null if unknown.")
    exploit_sources:    List[str]            = Field(default_factory=list, description="List of exploit source names.")
    last_updated:       Optional[str]        = Field(None, description="ISO 8601 UTC timestamp of last enrichment update.")

    @field_validator("cvss_score")
    @classmethod
    def cvss_score_precision(cls, v: Optional[float]) -> Optional[float]:
        return round(v, 1) if v is not None else None

    @field_validator("epss_score", "epss_percentile")
    @classmethod
    def epss_precision(cls, v: Optional[float]) -> Optional[float]:
        return round(v, 4) if v is not None else None

    @field_validator("kev_date_added")
    @classmethod
    def validate_kev_date(cls, v: Optional[str]) -> Optional[str]:
        """Validate ISO 8601 date format (YYYY-MM-DD) for kev_date_added."""
        if v is None:
            return None
        import re
        if not re.match(r"^\d{4}-\d{2}-\d{2}$", v):
            raise ValueError(
                f"kev_date_added '{v}' must be an ISO 8601 date string (YYYY-MM-DD)."
            )
        return v

    @field_validator("last_updated")
    @classmethod
    def validate_last_updated(cls, v: Optional[str]) -> Optional[str]:
        """Validate ISO 8601 UTC timestamp format for last_updated."""
        if v is None:
            return None
        import re
        # Accept both 'Z' suffix and '+00:00' offset
        pattern = r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$"
        if not re.match(pattern, v):
            raise ValueError(
                f"last_updated '{v}' must be an ISO 8601 UTC timestamp (e.g. '2026-08-20T00:00:00Z')."
            )
        return v


# ---------------------------------------------------------------------------
# M4 → M5 output model
# ---------------------------------------------------------------------------

class ThreatEnrichedFinding(BaseModel):
    """
    Output of Member 4 (Threat Intelligence Enrichment Engine).
    Input to Member 5 (Context-Aware Risk Engine).

    Field names are canonical per the RizIntel Interface Contract v1.0.
    Do NOT rename any field.
    """

    schema_version:                   SchemaVersion              = Field(..., description="Schema version, must be '1.0'.")
    finding_id:                       str                        = Field(..., description="Canonical finding identifier, preserved from upstream.")
    cve_id:                           Optional[str]              = Field(None, description="CVE identifier, preserved from upstream.")
    asset_id:                         str                        = Field(..., description="Canonical asset identifier. Do NOT rename to 'asset'.")
    vulnerability_name:               str                        = Field(..., description="Human-readable vulnerability name.")
    vulnerability_type:               VulnerabilityType          = Field(..., description="Categorical vulnerability classification.")
    scanner_sources:                  List[str]                  = Field(..., min_length=1, description="Scanner names that detected this finding.")
    scanner_consensus_score:          float                      = Field(..., ge=0.0, le=1.0, description="Scanner consensus score in range [0.0, 1.0].")
    finding_confidence_score:         float                      = Field(..., ge=0.0, le=1.0, description="Confidence score in range [0.0, 1.0].")
    finding_confidence_classification: ConfidenceClassification  = Field(..., description="Categorical confidence classification.")
    threat_intelligence:              ThreatIntelligence         = Field(..., description="Threat intelligence data retrieved by Member 4.")

    @field_validator("finding_id", "asset_id")
    @classmethod
    def validate_not_empty(cls, v: str) -> str:
        if not v or not v.strip():
            raise ValueError("Identifier fields must not be empty.")
        return v

    @field_validator("scanner_consensus_score", "finding_confidence_score")
    @classmethod
    def score_precision(cls, v: float) -> float:
        return round(v, 4)
