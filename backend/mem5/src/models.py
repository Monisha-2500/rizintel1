"""Data models and Pydantic schemas for Module M5 — Risk Scoring Engine.

Strictly adheres to Interface Contract v1.0.
Validates all canonical fields, types, and numerical ranges.
"""

from typing import List, Optional, Any, Dict, Union
from pydantic import BaseModel, Field, StrictBool, field_validator, ConfigDict



# ============================================================================
# Asset Context Model (Canonical Fields)
# ============================================================================

class AssetContext(BaseModel):
    """Asset Context schema following Interface Contract v1.0.

    Represents the business and network context of the target asset.

    For genuinely unresolved assets (asset_id='UNMAPPED'), asset_criticality
    may be 'UNKNOWN' and internet_exposure may be None. In both cases the
    scoring engine contributes 0 points for that factor, preserving full
    score accuracy for known assets.
    """
    model_config = ConfigDict(strict=True, extra="forbid")

    asset_id: str = Field(
        ...,
        description="Unique identifier of the asset (e.g., AST-PROD-PAY-001)"
    )
    asset_name: str = Field(
        ...,
        description="Human-readable name or service name of the asset"
    )
    environment: str = Field(
        ...,
        description="Deployment environment (e.g., PRODUCTION, STAGING, DEVELOPMENT, UNKNOWN)"
    )
    asset_criticality: str = Field(
        ...,
        description="Business criticality tier (CRITICAL, HIGH, MEDIUM, LOW) or UNKNOWN for unresolved assets"
    )
    internet_exposure: Optional[StrictBool] = Field(
        ...,
        description="True/False for known assets; None (null) for unresolved assets with unknown exposure"
    )
    data_sensitivity: str = Field(
        ...,
        description="Classification of data handled (RESTRICTED, CONFIDENTIAL, INTERNAL, PUBLIC, or UNKNOWN)"
    )

    @field_validator("asset_criticality")
    @classmethod
    def validate_asset_criticality(cls, v: str) -> str:
        # UNKNOWN is the explicit representation of genuinely unresolved asset tier.
        # Known tiers are unchanged: LOW=2pts, MEDIUM=5pts, HIGH=8pts, CRITICAL=10pts.
        # UNKNOWN=0pts (no fabricated business tier).
        allowed = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"}
        if v.upper() not in allowed:
            raise ValueError(
                f"Invalid asset_criticality '{v}'. Must be one of {sorted(allowed)}."
            )
        return v.upper()


# ============================================================================
# Threat Intelligence Model (Canonical Fields)
# ============================================================================

class ThreatIntelligence(BaseModel):
    """Threat Intelligence enrichment schema received from M4.
    
    Contains CVSS, EPSS, CISA KEV, and active exploit intelligence.
    """
    model_config = ConfigDict(strict=True, extra="forbid")

    cvss_score: float = Field(
        ...,
        ge=0.0,
        le=10.0,
        description="CVSS base score on scale [0.0 - 10.0]"
    )
    epss_score: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="EPSS probability score on scale [0.0 - 1.0]"
    )
    epss_percentile: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="EPSS percentile ranking on scale [0.0 - 1.0]"
    )
    kev_listed: StrictBool = Field(
        ...,
        description="JSON boolean indicating presence in CISA KEV catalog (true/false)"
    )
    exploit_available: StrictBool = Field(
        ...,
        description="JSON boolean indicating whether known exploit code is publicly available (true/false)"
    )


# ============================================================================
# Input Finding Model (M5 Ingestion Contract v1.0)
# ============================================================================

class M5RiskEngineInput(BaseModel):
    """Canonical Input payload received by M5 from M4 finding enrichment and asset context."""
    model_config = ConfigDict(strict=True, extra="forbid")

    schema_version: str = Field(
        default="1.0",
        description="Schema contract version, strictly '1.0'"
    )
    finding_id: str = Field(
        ...,
        description="Unique identifier of the vulnerability finding"
    )
    cve_id: Optional[str] = Field(
        default=None,
        description="CVE identifier if assigned, or null for non-CVE findings"
    )
    vulnerability_name: str = Field(
        ...,
        description="Descriptive title of the vulnerability"
    )
    vulnerability_type: str = Field(
        ...,
        description="Vulnerability category or CWE classification"
    )
    scanner_sources: List[str] = Field(
        ...,
        min_length=1,
        description="List of security scanners that reported this finding"
    )
    scanner_consensus_score: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Consensus score across scanners on scale [0.0 - 1.0]"
    )
    finding_confidence_score: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Overall confidence in finding validity on scale [0.0 - 1.0]"
    )
    finding_confidence_classification: str = Field(
        ...,
        description="Confidence category (e.g., CONFIRMED, HIGH, MEDIUM, LOW)"
    )
    threat_intelligence: ThreatIntelligence = Field(
        ...,
        description="Threat intelligence parameters enriched by M4"
    )
    asset_context: AssetContext = Field(
        ...,
        description="Asset business and deployment context"
    )

    @field_validator("schema_version")
    @classmethod
    def validate_schema_version(cls, v: str) -> str:
        if v != "1.0":
            raise ValueError(f"Unsupported schema_version '{v}'. Expected '1.0'.")
        return v


# ============================================================================
# Output Assessment Models (M5 -> M6 Interface Contract v1.0)
# ============================================================================

class ScannerConsensus(BaseModel):
    """Consensus summary for output contract."""
    model_config = ConfigDict(strict=True, extra="forbid")

    scanner_sources: List[str] = Field(..., description="List of scanners")
    scanner_consensus_score: float = Field(..., ge=0.0, le=1.0, description="Consensus score [0.0 - 1.0]")


class FindingConfidence(BaseModel):
    """Confidence summary for output contract."""
    model_config = ConfigDict(strict=True, extra="forbid")

    finding_confidence_score: float = Field(..., ge=0.0, le=1.0, description="Confidence score [0.0 - 1.0]")
    finding_confidence_classification: str = Field(..., description="Confidence classification")


class FactorBreakdown(BaseModel):
    """Transparent contribution breakdown for an individual scoring factor."""
    model_config = ConfigDict(strict=True, extra="forbid")

    input: Optional[Union[float, int, str, bool]] = Field(
        ...,
        description=(
            "Original input value of the scoring factor. "
            "None indicates a genuinely unknown value (contributes 0 points)."
        )
    )
    points: int = Field(
        ...,
        ge=0,
        description="Additive point contribution calculated for this factor"
    )


class RuleAdjustment(BaseModel):
    """Individual rule modifier in score explanation breakdown."""
    model_config = ConfigDict(strict=True, extra="forbid")

    rule_name: str = Field(..., description="Canonical rule name")
    description: str = Field(..., description="Explanation of triggered rule")
    adjustment: str = Field(..., description="Score adjustment value or factor")


class ScoreBreakdown(BaseModel):
    """Detailed transparent breakdown of risk score computation components."""
    model_config = ConfigDict(strict=True, extra="forbid")

    cvss: FactorBreakdown = Field(..., description="CVSS technical severity contribution")
    epss: FactorBreakdown = Field(..., description="EPSS exploitation likelihood contribution")
    kev: FactorBreakdown = Field(..., description="CISA KEV catalog listing contribution")
    exploit_available: FactorBreakdown = Field(..., description="Public exploit code availability contribution")
    asset_criticality: FactorBreakdown = Field(..., description="Asset business criticality tier contribution")
    internet_exposure: FactorBreakdown = Field(..., description="Internet accessibility exposure contribution")
    finding_confidence: FactorBreakdown = Field(..., description="Detection confidence and validation contribution")


class RiskAssessment(BaseModel):
    """Core risk evaluation object for M6 triage consumption."""
    model_config = ConfigDict(strict=True, extra="forbid")

    risk_score: float = Field(
        ...,
        ge=0.0,
        le=100.0,
        description="Calculated composite risk score on scale [0.0 - 100.0]"
    )
    risk_level: str = Field(
        ...,
        description="Categorical risk priority (CRITICAL, HIGH, MEDIUM, LOW)"
    )
    score_breakdown: ScoreBreakdown = Field(
        ...,
        description="Transparent breakdown of all scoring components"
    )
    risk_drivers: List[str] = Field(
        default_factory=list,
        description="List of triggered key risk driver identifiers"
    )
    scoring_version: str = Field(
        default="1.0",
        description="Version of scoring policy algorithm used (strictly '1.0')"
    )


class AssessmentMetadata(BaseModel):
    """Execution metadata for traceability and auditing."""
    model_config = ConfigDict(strict=True, extra="forbid")

    engine_name: str = Field(default="M5_Risk_Engine")
    engine_version: str = Field(default="1.0.0")
    assessed_at: str = Field(..., description="ISO 8601 UTC timestamp")
    status: str = Field(default="SUCCESS")
    notes: Optional[str] = Field(default=None, description="Audit notes or execution warnings")


class M5RiskEngineOutput(BaseModel):
    """Canonical Output contract produced by M5 for downstream consumption (M6)."""
    model_config = ConfigDict(strict=True, extra="forbid")

    schema_version: str = Field(
        default="1.0",
        description="Schema contract version"
    )
    scoring_version: str = Field(
        default="1.0",
        description="Algorithm version identifier"
    )
    finding_id: str = Field(..., description="Finding identifier")
    cve_id: Optional[str] = Field(default=None, description="CVE ID or null")
    vulnerability_name: str = Field(..., description="Vulnerability name")
    scanner_consensus: ScannerConsensus = Field(..., description="Scanner consensus data")
    finding_confidence: FindingConfidence = Field(..., description="Confidence data")
    threat_intelligence: ThreatIntelligence = Field(..., description="Threat intelligence data")
    asset_context: AssetContext = Field(..., description="Asset context data")
    risk_assessment: RiskAssessment = Field(..., description="Evaluated risk assessment")
    metadata: AssessmentMetadata = Field(..., description="Assessment metadata")
