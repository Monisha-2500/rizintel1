from pydantic import BaseModel, Field, field_validator, model_validator, ConfigDict
from typing import List, Optional
import re

# ── Constants ────────────────────────────────────────────────────────────────
_VALID_FINDING_ID = re.compile(r"^[A-Za-z0-9_\-]{1,64}$")
_VALID_ACTION = re.compile(r"^[A-Z_]{1,100}$")
_ALLOWED_ACTIONS = {"ACCEPT_PRIORITY", "ESCALATE", "DOWNGRADE", "NEEDS_REVIEW", "FALSE_POSITIVE"}

# Schema v1.0 contract models

class ScannerFinding(BaseModel):
    finding_id: str = Field(..., min_length=1, max_length=64)
    scanner: str = Field(..., min_length=1, max_length=100)

class JourneyStage(BaseModel):
    stage: str = Field(..., min_length=1, max_length=200)
    status: str = Field(..., min_length=1, max_length=50)

class ScannerConsensus(BaseModel):
    score: float = Field(..., ge=0.0, le=100.0)
    scanner_names: List[str]
    detected_by_count: int = Field(..., ge=0)
    total_scanners: int = Field(..., ge=0)

class FindingConfidence(BaseModel):
    score: float = Field(..., ge=0.0, le=100.0)
    classification: str

class ThreatIntelligence(BaseModel):
    cvss_score: Optional[float] = Field(None, ge=0.0, le=10.0)
    epss_score: Optional[float] = Field(None, ge=0.0, le=1.0)
    kev_listed: bool = False
    exploit_available: bool = False

class AssetContext(BaseModel):
    asset_name: str = Field(..., min_length=1, max_length=200)
    environment: str = Field(..., min_length=1, max_length=50)
    criticality: str = Field(..., min_length=1, max_length=50)
    internet_facing: bool
    data_sensitivity: str = Field(..., min_length=1, max_length=50)

class RiskAssessment(BaseModel):
    score_breakdown: dict
    scoring_version: str

class Explanation(BaseModel):
    technical: str
    management: str
    top_risk_drivers: List[str] = []

class Provenance(BaseModel):
    source_findings: List[ScannerFinding] = []
    journey: List[JourneyStage] = []

class ChangedFactor(BaseModel):
    model_config = ConfigDict(populate_by_name=True)

    factor: str
    from_val: Optional[object] = Field(None, alias="from")
    to_val: Optional[object] = Field(None, alias="to")

class RiskDelta(BaseModel):
    previous_score: int
    current_score: int
    delta: int
    changed_factors: List[ChangedFactor] = []

class FindingDetail(BaseModel):
    scanner_consensus: ScannerConsensus
    finding_confidence: FindingConfidence
    threat_intelligence: ThreatIntelligence
    asset_context: AssetContext
    risk_assessment: RiskAssessment
    explanation: Explanation
    provenance: Provenance
    risk_delta: Optional[RiskDelta] = None

class Workflow(BaseModel):
    ticket_id: Optional[str] = None
    status: str
    assigned_to: Optional[str] = None
    sla_hours: Optional[int] = None
    sla_due_at: Optional[str] = None
    sla_status: str
    escalation_level: int = 0

class FindingSchema(BaseModel):
    schema_version: str = "1.0"
    finding_id: str = Field(..., min_length=1, max_length=64)
    cve_id: Optional[str] = None
    asset_id: str
    vulnerability_name: str
    vulnerability_type: str
    risk_score: int = Field(..., ge=0, le=100)
    risk_level: str
    confidence_classification: str
    asset_criticality: str
    internet_exposure: bool
    recommended_action: str
    workflow: Workflow
    discovered_at: str
    updated_at: str
    detail: FindingDetail

    @field_validator("finding_id")
    @classmethod
    def validate_finding_id(cls, v: str) -> str:
        if not _VALID_FINDING_ID.match(v):
            raise ValueError("finding_id must be alphanumeric with hyphens/underscores, max 64 chars")
        return v


# ── Feedback & Audit Trail schema validation ─────────────────────────────────

def _sanitize_rationale(v: Optional[str]) -> str:
    """Strip leading/trailing whitespace and clamp to 2000 chars."""
    if not v:
        return ""
    return str(v).strip()[:2000]

def _validate_action(v: Optional[str], field_name: str) -> str:
    """Ensure action is an allowed uppercase keyword."""
    if not v:
        raise ValueError(f"{field_name} is required and cannot be empty")
    cleaned = str(v).strip().upper()
    if not _VALID_ACTION.match(cleaned):
        raise ValueError(f"{field_name} must contain only uppercase letters and underscores")
    if cleaned not in _ALLOWED_ACTIONS:
        raise ValueError(
            f"'{cleaned}' is not a valid analyst action. "
            f"Allowed: {sorted(_ALLOWED_ACTIONS)}"
        )
    return cleaned


class AuditEventCreate(BaseModel):
    finding_id: Optional[str] = Field(None, max_length=64)
    m5_risk_score: Optional[int] = Field(None, ge=0, le=100)
    analyst_action: Optional[str] = Field(None, max_length=100)
    analyst_decision: Optional[str] = Field(None, max_length=100)  # alias
    rationale: Optional[str] = Field(default="", max_length=2000)
    reason: Optional[str] = Field(default="", max_length=2000)     # alias
    role: Optional[str] = Field(default="security_analyst", max_length=128)
    timestamp: Optional[str] = Field(None, max_length=50)

    @field_validator("finding_id")
    @classmethod
    def validate_finding_id(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        if not _VALID_FINDING_ID.match(v):
            raise ValueError("finding_id must be alphanumeric with hyphens/underscores, max 64 chars")
        return v

    @field_validator("analyst_action", "analyst_decision", mode="before")
    @classmethod
    def validate_action_field(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        cleaned = str(v).strip().upper()
        if cleaned and cleaned not in _ALLOWED_ACTIONS:
            raise ValueError(
                f"'{cleaned}' is not a valid analyst action. Allowed: {sorted(_ALLOWED_ACTIONS)}"
            )
        return cleaned if cleaned else None

    @field_validator("rationale", "reason", mode="before")
    @classmethod
    def sanitize_rationale(cls, v: Optional[str]) -> str:
        return _sanitize_rationale(v)

    @model_validator(mode="after")
    def require_at_least_one_action(self) -> "AuditEventCreate":
        if not self.analyst_action and not self.analyst_decision:
            raise ValueError("Either analyst_action or analyst_decision must be provided")
        return self


class AuditEventResponse(BaseModel):
    id: int
    finding_id: str
    m5_risk_score: int
    analyst_action: str
    rationale: Optional[str] = ""
    role: str = "security_analyst"
    timestamp: str
    previous_hash: str
    event_hash: str


class AuditVerifyResponse(BaseModel):
    valid: bool
    broken_at: Optional[int] = None
    total: int
    message: Optional[str] = None
    latest_hash: Optional[str] = None
    # Note: 'error' field is intentionally omitted from the response model
    # to prevent internal DB error messages from leaking to clients.


class AnalystFeedbackInput(BaseModel):
    finding_id: Optional[str] = Field(None, max_length=64)
    analyst_decision: Optional[str] = Field(None, max_length=100)
    analyst_action: Optional[str] = Field(None, max_length=100)
    reason: Optional[str] = Field(default="", max_length=2000)
    rationale: Optional[str] = Field(default="", max_length=2000)
    role: Optional[str] = Field(default="security_analyst", max_length=128)
    timestamp: Optional[str] = Field(None, max_length=50)

    @field_validator("analyst_decision", "analyst_action", mode="before")
    @classmethod
    def validate_action_field(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        cleaned = str(v).strip().upper()
        if cleaned and cleaned not in _ALLOWED_ACTIONS:
            raise ValueError(
                f"'{cleaned}' is not a valid analyst action. Allowed: {sorted(_ALLOWED_ACTIONS)}"
            )
        return cleaned if cleaned else None

    @field_validator("rationale", "reason", mode="before")
    @classmethod
    def sanitize_rationale(cls, v: Optional[str]) -> str:
        return _sanitize_rationale(v)

    @field_validator("finding_id")
    @classmethod
    def validate_finding_id(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        if not _VALID_FINDING_ID.match(v):
            raise ValueError("finding_id must be alphanumeric with hyphens/underscores, max 64 chars")
        return v


