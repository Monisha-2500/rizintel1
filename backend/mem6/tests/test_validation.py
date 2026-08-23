"""
Test 2 (missing CVE) and Test 7 (missing optional threat intelligence).
"""

import json

from fastapi.testclient import TestClient

from app.main import app
from app.models.input_models import RiskAssessedFinding

client = TestClient(app)

with open("sample_data/m5_input.json") as f:
    SAMPLE_INPUT = json.load(f)


def test_missing_cve_still_works():
    """Test 2: cve_id = null -> M6 should still work."""
    modified = json.loads(json.dumps(SAMPLE_INPUT))
    modified["cve_id"] = None
    resp = client.post("/api/v1/explain", json=modified)
    assert resp.status_code == 200
    body = resp.json()
    assert body["cve_id"] is None
    # references should gracefully be empty since there's no CVE to build a link from
    assert body["remediation"]["references"] == []


def test_missing_optional_threat_intelligence_handled_gracefully():
    """Test 7: missing optional threat_intelligence block -> graceful handling."""
    modified = json.loads(json.dumps(SAMPLE_INPUT))
    del modified["threat_intelligence"]
    resp = client.post("/api/v1/explain", json=modified)
    assert resp.status_code == 200
    body = resp.json()
    # Should not crash, should still produce a valid explanation and drivers
    assert body["explanation"]["technical"]
    assert body["explanation"]["management"]
    assert isinstance(body["explanation"]["top_risk_drivers"], list)


def test_missing_scanner_consensus_and_finding_confidence_handled():
    modified = json.loads(json.dumps(SAMPLE_INPUT))
    del modified["scanner_consensus"]
    del modified["finding_confidence"]
    resp = client.post("/api/v1/explain", json=modified)
    assert resp.status_code == 200
    body = resp.json()
    assert body["finding_confidence_classification"] is None


def test_input_model_validates_scale_bounds():
    modified = json.loads(json.dumps(SAMPLE_INPUT))
    modified["threat_intelligence"]["epss_score"] = 1.5  # out of 0-1 range
    try:
        RiskAssessedFinding(**modified)
        assert False, "Expected a validation error for epss_score out of range"
    except Exception:
        pass
