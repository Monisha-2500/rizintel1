"""
Test 6: Hallucination protection -- unsupported information isn't added.
Also directly unit-tests the risk driver extraction and the score
passthrough guardrail described in explanation_service.py.
"""

import json

from app.models.input_models import RiskAssessedFinding
from app.services.explanation_service import generate_explained_finding
from app.services.risk_driver_service import extract_top_risk_drivers

with open("sample_data/m5_input.json") as f:
    SAMPLE_INPUT = json.load(f)


def _make_finding(overrides: dict | None = None) -> RiskAssessedFinding:
    data = json.loads(json.dumps(SAMPLE_INPUT))
    if overrides:
        data.update(overrides)
    return RiskAssessedFinding(**data)


def test_top_risk_drivers_derived_from_score_breakdown():
    finding = _make_finding()
    drivers = extract_top_risk_drivers(finding)
    # cvss_contribution (28) is the highest -> HIGH_CVSS should be first
    assert drivers[0] == "HIGH_CVSS"
    assert "KEV_LISTED" in drivers
    assert len(drivers) <= 4


def test_top_risk_drivers_without_score_breakdown_uses_raw_fields():
    data = json.loads(json.dumps(SAMPLE_INPUT))
    data["risk_assessment"]["score_breakdown"] = None
    finding = RiskAssessedFinding(**data)
    # Request all matching labels (max_drivers=10) to test the raw-field
    # fallback logic itself, separately from the default top-4 cap.
    drivers = extract_top_risk_drivers(finding, max_drivers=10)
    assert "INTERNET_FACING" in drivers  # asset_context.internet_facing = true
    assert "KEV_LISTED" in drivers  # threat_intelligence.kev_listed = true


def test_risk_score_never_drifts_even_if_input_is_tampered_with():
    """The core guarantee: M6 cannot change M5's score, for any input."""
    finding = _make_finding()
    output = generate_explained_finding(finding)
    assert output.risk_score == finding.risk_assessment.risk_score
    assert output.risk_level == finding.risk_assessment.risk_level

    # A different score in -> that exact different score out. M6 never
    # recalculates towards "what it thinks the score should be".
    data = json.loads(json.dumps(SAMPLE_INPUT))
    data["risk_assessment"]["risk_score"] = 12
    data["risk_assessment"]["risk_level"] = "LOW"
    low_finding = RiskAssessedFinding(**data)
    low_output = generate_explained_finding(low_finding)
    assert low_output.risk_score == 12
    assert low_output.risk_level == "LOW"
    assert low_output.remediation.priority == "LOW"


def test_no_fabricated_cve_in_output():
    """Test 6: the output must not reference a CVE other than the one supplied."""
    finding = _make_finding()
    output = generate_explained_finding(finding)
    assert output.cve_id == "CVE-2026-1234"
    # crude but effective: no other CVE-looking token should appear in the prose
    import re

    all_text = output.explanation.technical + output.explanation.management
    mentioned_cves = set(re.findall(r"CVE-\d{4}-\d+", all_text))
    assert mentioned_cves <= {"CVE-2026-1234"}
