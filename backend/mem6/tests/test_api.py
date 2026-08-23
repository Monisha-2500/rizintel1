"""
Test 1 (happy path), Test 4 (invalid risk score), Test 5 (score preservation),
and Test 8 (malformed/partial input) live here, exercised via the FastAPI
TestClient so they cover the real API surface, not just internal functions.
"""

import json

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)

with open("sample_data/m5_input.json") as f:
    SAMPLE_INPUT = json.load(f)


def test_health():
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


def test_version():
    resp = client.get("/api/v1/version")
    assert resp.status_code == 200
    assert resp.json()["contract_version"] == "PS4-v1.0"


def test_happy_path_valid_input_produces_valid_output():
    """Test 1: Valid RiskAssessedFinding -> valid ExplainedFinding."""
    resp = client.post("/api/v1/explain", json=SAMPLE_INPUT)
    assert resp.status_code == 200
    body = resp.json()

    assert body["schema_version"] == "1.0"
    assert body["finding_id"] == "DEDUP-0001"
    assert body["cve_id"] == "CVE-2026-1234"
    assert body["asset_id"] == "ASSET-WEB-001"
    assert "technical" in body["explanation"]
    assert "management" in body["explanation"]
    assert isinstance(body["explanation"]["top_risk_drivers"], list)
    assert "recommended_action" in body["remediation"]
    assert "priority" in body["remediation"]
    assert "generated_at" in body


def test_invalid_risk_score_rejected():
    """Test 4: risk_score = 150 should be rejected (out of 0-100 range)."""
    bad_input = json.loads(json.dumps(SAMPLE_INPUT))
    bad_input["risk_assessment"]["risk_score"] = 150
    resp = client.post("/api/v1/explain", json=bad_input)
    assert resp.status_code == 422


def test_risk_score_is_preserved_exactly():
    """Test 5: M5 sends risk_score=94 -> M6 must return risk_score=94 exactly."""
    resp = client.post("/api/v1/explain", json=SAMPLE_INPUT)
    assert resp.status_code == 200
    body = resp.json()
    assert body["risk_score"] == SAMPLE_INPUT["risk_assessment"]["risk_score"]
    assert body["risk_level"] == SAMPLE_INPUT["risk_assessment"]["risk_level"]


def test_malformed_partial_input_returns_clear_validation_error():
    """Test 8: malformed/partial input -> clear validation error."""
    partial_input = {"finding_id": "ONLY-THIS-FIELD"}
    resp = client.post("/api/v1/explain", json=partial_input)
    assert resp.status_code == 422
    detail = resp.json()["detail"]
    assert detail  # non-empty, contains field-level errors from Pydantic
