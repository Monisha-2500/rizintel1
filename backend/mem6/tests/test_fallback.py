"""
Test 3: LLM unavailable -> rule-based fallback still produces a valid
ExplainedFinding. Since no ANTHROPIC_API_KEY is set in this test
environment by default, the service already exercises the fallback path
end-to-end -- these tests make that explicit and also unit-test the
fallback builder directly.
"""

import json

from app.models.input_models import RiskAssessedFinding
from app.services.explanation_service import generate_explained_finding
from app.services.fallback_service import build_fallback_explanation
from app.services.llm_service import LLMService

with open("sample_data/m5_input.json") as f:
    SAMPLE_INPUT = json.load(f)


def _make_finding() -> RiskAssessedFinding:
    return RiskAssessedFinding(**SAMPLE_INPUT)


def test_llm_service_returns_none_without_api_key(monkeypatch):
    monkeypatch.setattr("app.config.ANTHROPIC_API_KEY", "")
    service = LLMService()
    result = service.generate(_make_finding())
    assert result is None


def test_fallback_builder_never_raises_and_produces_valid_result():
    finding = _make_finding()
    result = build_fallback_explanation(finding)
    assert result.technical
    assert result.management
    assert result.recommended_action
    # must reference the CVE, not fabricate a different one
    assert "CVE-2026-1234" in result.technical


def test_end_to_end_falls_back_cleanly(monkeypatch):
    monkeypatch.setattr("app.config.ANTHROPIC_API_KEY", "")
    finding = _make_finding()
    output = generate_explained_finding(finding)
    assert output.risk_score == 94
    assert output.risk_level == "CRITICAL"
    assert output.explanation.technical
    assert output.remediation.priority == "IMMEDIATE"
