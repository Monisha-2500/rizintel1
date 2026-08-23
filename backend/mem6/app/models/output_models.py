"""
Pydantic models for the M6 -> M7 "ExplainedFinding" contract.

Source of truth: PS4 - Standardized Module Interface Contract v1.0, Section 9.

No fields are added beyond what Section 9 specifies. risk_score / risk_level
are typed exactly as passthrough values -- nothing in this file computes
them; see app/services/explanation_service.py for the enforcement.
"""

from __future__ import annotations

from typing import List

from pydantic import BaseModel, Field


class Explanation(BaseModel):
    technical: str
    management: str
    top_risk_drivers: List[str] = Field(default_factory=list)


class Remediation(BaseModel):
    recommended_action: str
    priority: str
    references: List[str] = Field(default_factory=list)


class ExplainedFinding(BaseModel):
    schema_version: str = "1.0"
    finding_id: str
    cve_id: str | None = None
    asset_id: str
    vulnerability_name: str | None = None

    # PASSTHROUGH ONLY -- never computed by M6. See explanation_service.py.
    risk_score: float
    risk_level: str

    finding_confidence_classification: str | None = None

    explanation: Explanation
    remediation: Remediation

    generated_at: str
