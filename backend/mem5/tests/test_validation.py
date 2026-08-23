"""Validation and schema contract test suite for Module M5.

Tests:
1. Valid sample input complies with Interface Contract v1.0.
2. Missing CVE input (cve_id = null) is valid.
3. Standalone asset_context.json parses cleanly.
4. Malformed input raises Pydantic ValidationError for invalid ranges/types.
5. Boolean strictness (rejecting string 'true'/'false'/'Yes'/'No').
6. Numerical range constraints (CVSS [0-10], EPSS [0-1], consensus [0-1]).
"""

import json
from pathlib import Path
import pytest
from pydantic import ValidationError

from src.models import (
    M5RiskEngineInput,
    AssetContext,
    ThreatIntelligence,
    M5RiskEngineOutput
)
from src.risk_engine import RiskEngine


BASE_DIR = Path(__file__).parent.parent
INPUT_DIR = BASE_DIR / "input"
OUTPUT_DIR = BASE_DIR / "output"


def load_json(path: Path) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


class TestM5Validation:
    """Test suite for M5 input models and contract compliance."""

    def test_sample_input_valid(self):
        data = load_json(INPUT_DIR / "sample_input.json")
        model = M5RiskEngineInput.model_validate(data)
        assert model.schema_version == "1.0"
        assert model.finding_id == "FIND-2026-0892"
        assert model.cve_id == "CVE-2021-44228"
        assert model.threat_intelligence.cvss_score == 10.0
        assert model.threat_intelligence.epss_score == 0.975
        assert model.threat_intelligence.kev_listed is True
        assert model.threat_intelligence.exploit_available is True
        assert model.asset_context.internet_exposure is True

    def test_missing_cve_input_valid(self):
        data = load_json(INPUT_DIR / "missing_cve_input.json")
        model = M5RiskEngineInput.model_validate(data)
        assert model.cve_id is None
        assert model.finding_id == "FIND-2026-1044"
        assert model.threat_intelligence.cvss_score == 8.5

    def test_asset_context_valid(self):
        data = load_json(INPUT_DIR / "asset_context.json")
        model = AssetContext.model_validate(data)
        assert model.asset_id == "AST-PROD-PAY-001"
        assert model.environment == "PRODUCTION"
        assert model.asset_criticality == "CRITICAL"
        assert model.internet_exposure is True

    def test_malformed_input_rejected(self):
        data = load_json(INPUT_DIR / "malformed_input.json")
        with pytest.raises(ValidationError) as exc_info:
            M5RiskEngineInput.model_validate(data)
        
        errors = exc_info.value.errors()
        assert len(errors) > 0

    def test_expected_output_conforms_to_schema(self):
        data = load_json(OUTPUT_DIR / "expected_output.json")
        model = M5RiskEngineOutput.model_validate(data)
        assert model.schema_version == "1.0"
        assert model.risk_assessment.risk_score == 100.0
        assert model.risk_assessment.risk_level == "CRITICAL"
        assert len(model.risk_assessment.risk_drivers) == 7

    def test_pipeline_execution_sample(self):
        engine = RiskEngine()
        data = load_json(INPUT_DIR / "sample_input.json")
        output = engine.assess_finding(data)
        assert output.finding_id == "FIND-2026-0892"
        assert output.schema_version == "1.0"
        assert output.scoring_version == "1.0"
        assert output.metadata.status == "SUCCESS"
        assert output.risk_assessment.risk_score == 100.0
        assert output.risk_assessment.risk_level == "CRITICAL"

    @pytest.mark.parametrize("invalid_cvss", [-0.01, 10.01, -10.0, 100.0])
    def test_reject_out_of_bound_cvss(self, invalid_cvss):
        data = load_json(INPUT_DIR / "sample_input.json")
        data["threat_intelligence"]["cvss_score"] = invalid_cvss
        with pytest.raises(ValidationError):
            M5RiskEngineInput.model_validate(data)

    @pytest.mark.parametrize("invalid_epss", [-0.001, 1.001, -1.0, 2.0])
    def test_reject_out_of_bound_epss(self, invalid_epss):
        data = load_json(INPUT_DIR / "sample_input.json")
        data["threat_intelligence"]["epss_score"] = invalid_epss
        with pytest.raises(ValidationError):
            M5RiskEngineInput.model_validate(data)

    @pytest.mark.parametrize("invalid_conf", [-0.01, 1.01, 2.0, -1.0])
    def test_reject_out_of_bound_confidence(self, invalid_conf):
        data = load_json(INPUT_DIR / "sample_input.json")
        data["finding_confidence_score"] = invalid_conf
        with pytest.raises(ValidationError):
            M5RiskEngineInput.model_validate(data)

    @pytest.mark.parametrize(
        "field_name, field_val",
        [
            ("kev_listed", "true"),
            ("kev_listed", "True"),
            ("kev_listed", 1),
            ("exploit_available", "false"),
            ("exploit_available", 0),
        ],
    )
    def test_reject_non_strict_boolean_threat_intel(self, field_name, field_val):
        data = load_json(INPUT_DIR / "sample_input.json")
        data["threat_intelligence"][field_name] = field_val
        with pytest.raises(ValidationError):
            M5RiskEngineInput.model_validate(data)

    @pytest.mark.parametrize("invalid_crit", ["INVALID", "EXTREME", "SUPER_CRITICAL", "123"])
    def test_reject_invalid_asset_criticality(self, invalid_crit):
        data = load_json(INPUT_DIR / "sample_input.json")
        data["asset_context"]["asset_criticality"] = invalid_crit
        with pytest.raises(ValidationError):
            M5RiskEngineInput.model_validate(data)

    def test_reject_unsupported_schema_version(self):
        data = load_json(INPUT_DIR / "sample_input.json")
        data["schema_version"] = "2.0"
        with pytest.raises(ValidationError):
            M5RiskEngineInput.model_validate(data)

    def test_reject_extra_fields(self):
        data = load_json(INPUT_DIR / "sample_input.json")
        data["unauthorized_custom_field"] = "malicious_injection"
        with pytest.raises(ValidationError):
            M5RiskEngineInput.model_validate(data)

    def test_engine_safe_failure_on_invalid_input(self):
        engine = RiskEngine()
        malformed_data = load_json(INPUT_DIR / "malformed_input.json")
        with pytest.raises(ValidationError):
            engine.assess_finding(malformed_data)
