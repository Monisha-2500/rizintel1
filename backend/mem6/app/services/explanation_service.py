"""
Core M6 orchestration.

CRITICAL ARCHITECTURE RULE (Section 4 of the brief):
risk_score and risk_level are set via _passthrough_score(), which does a
DIRECT COPY from the input finding.risk_assessment. No other code path in
this file is permitted to write to those two output fields. This function
runs before the LLM/fallback branch, and its result is not passed into
either -- so no explanation logic can influence it, even indirectly.

top_risk_drivers and priority are also deterministic (risk_driver_service,
utils/validation.map_risk_level_to_priority) -- not LLM-derived -- so they
can never diverge from M5's own numbers.
"""

from __future__ import annotations

import logging

from app.models.input_models import RiskAssessedFinding
from app.models.output_models import ExplainedFinding, Explanation, Remediation
from app.services.fallback_service import build_fallback_explanation
from app.services.llm_service import LLMService
from app.services.risk_driver_service import extract_top_risk_drivers
from app.utils.validation import build_references, map_risk_level_to_priority, utc_now_iso

logger = logging.getLogger("m6.explanation_service")

_llm_service = LLMService()


def _passthrough_score(finding: RiskAssessedFinding) -> tuple[float, str]:
    """
    STRUCTURAL GUARDRAIL: the only place risk_score / risk_level are read
    for the output. Direct copy, no computation, no LLM involvement.
    """
    return finding.risk_assessment.risk_score, finding.risk_assessment.risk_level


def generate_explained_finding(finding: RiskAssessedFinding) -> ExplainedFinding:
    risk_score, risk_level = _passthrough_score(finding)

    generation_mode = "llm"
    result = _llm_service.generate(finding)

    if result is None:
        generation_mode = "template_fallback"
        result = build_fallback_explanation(finding)

    top_risk_drivers = extract_top_risk_drivers(finding)
    priority = map_risk_level_to_priority(risk_level)
    references = build_references(finding.cve_id)

    asset_id = finding.asset_context.asset_id
    confidence_classification = (
        finding.finding_confidence.classification if finding.finding_confidence else None
    )

    output = ExplainedFinding(
        schema_version=finding.schema_version or "1.0",
        finding_id=finding.finding_id,
        cve_id=finding.cve_id,
        asset_id=asset_id,
        vulnerability_name=finding.vulnerability_name,
        risk_score=risk_score,
        risk_level=risk_level,
        finding_confidence_classification=confidence_classification,
        explanation=Explanation(
            technical=result.technical,
            management=result.management,
            top_risk_drivers=top_risk_drivers,
        ),
        remediation=Remediation(
            recommended_action=result.recommended_action,
            priority=priority,
            references=references,
        ),
        generated_at=utc_now_iso(),
    )

    # Belt-and-suspenders: assert the echoed score never drifted from input.
    assert output.risk_score == finding.risk_assessment.risk_score
    assert output.risk_level == finding.risk_assessment.risk_level

    logger.info(
        "Generated ExplainedFinding for %s via %s path.",
        finding.finding_id,
        generation_mode,
    )

    return output
