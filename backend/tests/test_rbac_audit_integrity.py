"""
test_rbac_audit_integrity.py
=============================
Focused test suite for RizIntel Issue #7: RBAC & Audit Integrity Across LIVE / MOCK / FALLBACK Data.

Verifies:
1. LIVE ID resolves strictly against LIVE source cache.
2. Missing LIVE ID does NOT silently fall back to MOCK.
3. MOCK ID resolves strictly against MOCK cache when requested.
4. Same finding_id existing in both LIVE and MOCK cannot cross-resolve.
5. Viewer role decision -> 403 Forbidden.
6. Analyst role standard decision -> Allowed (200 OK).
7. Analyst role privileged ESCALATE decision -> 403 Forbidden.
8. Security Lead role ESCALATE decision -> Allowed (200 OK).
9. Audit entry records data_source (LIVE, MOCK, FALLBACK).
10. Audit entry records finding-state fingerprint (SHA-256 snapshot).
11. Pipeline refresh does NOT alter historical audit context (snapshot fingerprint is immutable).
12. Modified audit decision breaks SHA-256 chain verification.
13. Modified data_source in audit ledger breaks verification.
14. Modified finding snapshot fingerprint breaks verification.
15. Review promotion preserves source identity.
16. Unauthorized user cannot promote review finding.
17. FALLBACK decision follows explicit fallback policy (audited as FALLBACK, never LIVE).
"""

import pytest
from fastapi.testclient import TestClient
from main import app
from services.data_service import data_service
from routers.integration import _pipeline_cache
from models import FindingSchema, compute_finding_fingerprint
import database

class AuthTestClient(TestClient):
    def request(self, method: str, url: str, **kwargs):
        headers = dict(kwargs.get("headers") or {})
        if "Authorization" not in headers and "authorization" not in headers:
            role = headers.get("X-User-Role", "ANALYST").strip().upper()
            from users import get_user_by_email
            from auth import create_access_token
            email_map = {
                "VIEWER": "viewer@rizintel.demo",
                "ANALYST": "analyst@rizintel.demo",
                "SECURITY_LEAD": "lead@rizintel.demo",
                "ADMIN": "admin@rizintel.demo",
            }
            user = get_user_by_email(email_map.get(role, "analyst@rizintel.demo"))
            if user:
                headers["Authorization"] = f"Bearer {create_access_token(user)}"
            kwargs["headers"] = headers
        return super().request(method, url, **kwargs)

client = AuthTestClient(app)


@pytest.fixture(autouse=True)
def setup_test_caches():
    """Setup clean test state in _pipeline_cache and mock data."""
    database.init_db()
    mock_base = data_service.get_findings()[0]
    
    # 1. Distinct live finding
    live_1 = mock_base.model_copy(deep=True)
    live_1.finding_id = "DEDUP-LIVE-999"
    live_1.vulnerability_name = "Live Remote Code Execution"
    live_1.risk_score = 98
    live_1.risk_level = "CRITICAL"
    live_1.workflow.status = "OPEN"
    live_1.workflow.sla_status = "ON_TRACK"
    live_1.workflow.ticket_id = "TKT-9999"
    live_1.workflow.assigned_to = "secops"

    # 2. PENDING_REVIEW live finding
    live_review = mock_base.model_copy(deep=True)
    live_review.finding_id = "DEDUP-REVIEW-777"
    live_review.vulnerability_name = "Review Required Live SSRF"
    live_review.risk_score = 65
    live_review.risk_level = "MEDIUM"
    live_review.confidence_classification = "NEEDS_REVIEW"
    live_review.workflow.status = "PENDING_REVIEW"
    live_review.workflow.sla_status = "PENDING_REVIEW"
    live_review.workflow.ticket_id = None
    live_review.workflow.assigned_to = None

    # 3. Colliding finding ID with different fields from mock DEDUP-0001
    live_colliding = mock_base.model_copy(deep=True)
    live_colliding.finding_id = "DEDUP-0001"
    live_colliding.vulnerability_name = "LIVE Version of DEDUP-0001"
    live_colliding.risk_score = 88
    live_colliding.risk_level = "HIGH"

    _pipeline_cache["findings"] = [live_1, live_review, live_colliding]
    yield


# =============================================================================
# 1. Source-Aware Finding Lookup Tests
# =============================================================================

def test_live_id_resolves_strictly_against_live_source():
    """Requesting a LIVE source finding resolves from the live pipeline cache."""
    res = client.get("/api/findings/DEDUP-LIVE-999", headers={"X-Data-Source": "LIVE"})
    assert res.status_code == 200
    data = res.json()
    assert data["finding_id"] == "DEDUP-LIVE-999"
    assert data["vulnerability_name"] == "Live Remote Code Execution"


def test_missing_live_id_does_not_fall_back_to_mock():
    """A missing LIVE finding ID returns 404 and NEVER falls back to MOCK."""
    # DEDUP-0003 exists in mock_findings.json but is NOT in _pipeline_cache
    res = client.get("/api/findings/DEDUP-0003", headers={"X-Data-Source": "LIVE"})
    assert res.status_code == 404
    assert "not found in LIVE data source" in res.json()["detail"]


def test_mock_id_resolves_strictly_against_mock():
    """Requesting MOCK data resolves only from the mock cache."""
    res = client.get("/api/findings/DEDUP-0001", headers={"X-Data-Source": "MOCK"})
    assert res.status_code == 200
    data = res.json()
    assert data["finding_id"] == "DEDUP-0001"
    assert data["vulnerability_name"] == "SQL Injection"  # Mock title, not live title


def test_same_finding_id_in_live_and_mock_cannot_cross_resolve():
    """DEDUP-0001 in LIVE returns live record; in MOCK returns mock record."""
    res_live = client.get("/api/findings/DEDUP-0001", headers={"X-Data-Source": "LIVE"})
    assert res_live.status_code == 200
    assert res_live.json()["vulnerability_name"] == "LIVE Version of DEDUP-0001"

    res_mock = client.get("/api/findings/DEDUP-0001", headers={"X-Data-Source": "MOCK"})
    assert res_mock.status_code == 200
    assert res_mock.json()["vulnerability_name"] == "SQL Injection"


# =============================================================================
# 2. Server-Side RBAC Enforcement Tests
# =============================================================================

def test_viewer_decision_returns_403():
    """Viewer cannot record any analyst decision."""
    payload = {
        "finding_id": "DEDUP-LIVE-999",
        "analyst_action": "ACCEPT_PRIORITY",
        "rationale": "Viewer attempting decision"
    }
    res = client.post(
        "/api/findings/DEDUP-LIVE-999/audit",
        json=payload,
        headers={"X-User-Role": "VIEWER", "X-User-Name": "Auditor Bob", "X-Data-Source": "LIVE"}
    )
    assert res.status_code == 403
    assert "Permission denied: VIEWER" in res.json()["detail"]


def test_analyst_standard_decision_allowed():
    """Security Analyst can perform standard decisions (ACCEPT_PRIORITY, DOWNGRADE, etc)."""
    payload = {
        "finding_id": "DEDUP-LIVE-999",
        "analyst_action": "ACCEPT_PRIORITY",
        "rationale": "Analyst validated finding priority"
    }
    res = client.post(
        "/api/findings/DEDUP-LIVE-999/audit",
        json=payload,
        headers={"X-User-Role": "ANALYST", "X-User-Name": "Alice Analyst", "X-Data-Source": "LIVE"}
    )
    assert res.status_code == 200
    assert res.json()["analyst_action"] == "ACCEPT_PRIORITY"
    assert res.json()["data_source"] == "LIVE"


def test_analyst_privileged_escalation_returns_403():
    """Security Analyst cannot perform privileged ESCALATE action."""
    payload = {
        "finding_id": "DEDUP-LIVE-999",
        "analyst_action": "ESCALATE",
        "rationale": "Analyst attempting critical escalation"
    }
    res = client.post(
        "/api/findings/DEDUP-LIVE-999/audit",
        json=payload,
        headers={"X-User-Role": "ANALYST", "X-User-Name": "Alice Analyst", "X-Data-Source": "LIVE"}
    )
    assert res.status_code == 403
    assert "restricted to SECURITY_LEAD or ADMIN" in res.json()["detail"]


def test_security_lead_escalation_allowed():
    """Security Lead can perform high-impact ESCALATE decisions."""
    payload = {
        "finding_id": "DEDUP-LIVE-999",
        "analyst_action": "ESCALATE",
        "rationale": "Lead escalated to executive SOC response"
    }
    res = client.post(
        "/api/findings/DEDUP-LIVE-999/audit",
        json=payload,
        headers={"X-User-Role": "SECURITY_LEAD", "X-User-Name": "Lead Carol", "X-Data-Source": "LIVE"}
    )
    assert res.status_code == 200
    assert res.json()["analyst_action"] == "ESCALATE"


# =============================================================================
# 3. Audit Context & Finding Snapshot Fingerprint Tests
# =============================================================================

def test_audit_entry_records_data_source_and_fingerprint():
    """Audit records store data_source and deterministic finding state fingerprint."""
    payload = {
        "finding_id": "DEDUP-LIVE-999",
        "analyst_action": "ACCEPT_PRIORITY",
        "rationale": "Fingerprint verification"
    }
    res = client.post(
        "/api/findings/DEDUP-LIVE-999/audit",
        json=payload,
        headers={"X-User-Role": "ANALYST", "X-User-Name": "Alice Analyst", "X-Data-Source": "LIVE"}
    )
    assert res.status_code == 200
    ev = res.json()
    assert ev["data_source"] == "LIVE"
    assert ev["finding_snapshot_hash"] != ""
    assert len(ev["finding_snapshot_hash"]) == 16


def test_pipeline_refresh_does_not_alter_historical_audit_context():
    """When pipeline reruns and changes finding risk_score, historical audit entry remains unchanged."""
    fid = "DEDUP-LIVE-999"
    # Clean previous records for fid to isolate test
    conn = database._get_conn()
    conn.execute("DELETE FROM audit_trail WHERE finding_id = ?", (fid,))
    conn.commit()
    conn.close()

    # 1. Record decision when risk_score is 98
    payload = {
        "finding_id": fid,
        "analyst_action": "ACCEPT_PRIORITY",
        "rationale": "Decision on original state"
    }
    res = client.post(
        f"/api/findings/{fid}/audit",
        json=payload,
        headers={"X-User-Role": "ANALYST", "X-Data-Source": "LIVE"}
    )
    original_event = res.json()
    original_fingerprint = original_event["finding_snapshot_hash"]
    original_m5 = original_event["m5_risk_score"]

    # 2. Simulate pipeline rerun: update finding in _pipeline_cache with new score
    for f in _pipeline_cache["findings"]:
        if f.finding_id == fid:
            f.risk_score = 45
            f.risk_level = "MEDIUM"

    # 3. Verify audit record in SQLite still retains original score and original fingerprint
    audit_trail = client.get(f"/api/findings/{fid}/audit").json()
    matching_event = [e for e in audit_trail if e["id"] == original_event["id"]][0]
    assert matching_event["m5_risk_score"] == original_m5
    assert matching_event["finding_snapshot_hash"] == original_fingerprint

    # 4. Chain verification passes
    verify_res = client.get(f"/api/findings/{fid}/audit/verify").json()
    assert verify_res["valid"] is True


# =============================================================================
# 4. SHA-256 Cryptographic Chain Integrity Tests
# =============================================================================

def test_tampering_with_audit_action_breaks_verification():
    """Tampering with analyst_action in the database invalidates cryptographic chain."""
    fid = "DEDUP-LIVE-999"
    conn = database._get_conn()
    conn.execute("DELETE FROM audit_trail WHERE finding_id = ?", (fid,))
    conn.commit()
    conn.close()

    client.post(
        f"/api/findings/{fid}/audit",
        json={"finding_id": fid, "analyst_action": "ACCEPT_PRIORITY"},
        headers={"X-User-Role": "ANALYST", "X-Data-Source": "LIVE"}
    )

    # Tamper with SQLite record
    conn = database._get_conn()
    conn.execute("UPDATE audit_trail SET analyst_action = 'MALICIOUS_OVERRIDE' WHERE finding_id = ?", (fid,))
    conn.commit()
    conn.close()

    verify_res = client.get(f"/api/findings/{fid}/audit/verify").json()
    assert verify_res["valid"] is False
    assert "Event hash mismatch" in verify_res["message"]


def test_tampering_with_data_source_breaks_verification():
    """Tampering with data_source in the database invalidates cryptographic chain."""
    fid = "DEDUP-LIVE-999"
    conn = database._get_conn()
    conn.execute("DELETE FROM audit_trail WHERE finding_id = ?", (fid,))
    conn.commit()
    conn.close()

    client.post(
        f"/api/findings/{fid}/audit",
        json={"finding_id": fid, "analyst_action": "ACCEPT_PRIORITY"},
        headers={"X-User-Role": "ANALYST", "X-Data-Source": "LIVE"}
    )

    # Tamper data_source
    conn = database._get_conn()
    conn.execute("UPDATE audit_trail SET data_source = 'MOCK' WHERE finding_id = ?", (fid,))
    conn.commit()
    conn.close()

    verify_res = client.get(f"/api/findings/{fid}/audit/verify").json()
    assert verify_res["valid"] is False
    assert "Event hash mismatch" in verify_res["message"]


def test_tampering_with_finding_snapshot_breaks_verification():
    """Tampering with finding_snapshot_hash in the database invalidates cryptographic chain."""
    fid = "DEDUP-LIVE-999"
    conn = database._get_conn()
    conn.execute("DELETE FROM audit_trail WHERE finding_id = ?", (fid,))
    conn.commit()
    conn.close()

    client.post(
        f"/api/findings/{fid}/audit",
        json={"finding_id": fid, "analyst_action": "ACCEPT_PRIORITY"},
        headers={"X-User-Role": "ANALYST", "X-Data-Source": "LIVE"}
    )

    conn = database._get_conn()
    conn.execute("UPDATE audit_trail SET finding_snapshot_hash = 'tampered_hash_00' WHERE finding_id = ?", (fid,))
    conn.commit()
    conn.close()

    verify_res = client.get(f"/api/findings/{fid}/audit/verify").json()
    assert verify_res["valid"] is False
    assert "Event hash mismatch" in verify_res["message"]


# =============================================================================
# 5. Analyst Review Promotion & Fallback Policy Tests
# =============================================================================

def test_authorized_analyst_review_promotion_succeeds():
    """Authorized analyst approving PENDING_REVIEW finding promotes it to OPEN with source safety."""
    fid = "DEDUP-REVIEW-777"
    # Verify initial status
    f_initial = data_service.get_finding_by_id(fid, source="LIVE")
    assert f_initial.workflow.status == "PENDING_REVIEW"

    # Analyst approves
    res = client.post(
        f"/api/findings/{fid}/audit",
        json={"finding_id": fid, "analyst_action": "CONFIRM", "rationale": "Legitimate SSRF confirmed"},
        headers={"X-User-Role": "ANALYST", "X-User-Name": "Alice Analyst", "X-Data-Source": "LIVE"}
    )
    assert res.status_code == 200

    f_promoted = data_service.get_finding_by_id(fid, source="LIVE")
    assert f_promoted.workflow.status == "OPEN"
    assert f_promoted.workflow.ticket_id.startswith("TKT-")


def test_unauthorized_viewer_cannot_promote_review_finding():
    """Viewer cannot approve or promote a review finding."""
    fid = "DEDUP-REVIEW-777"
    res = client.post(
        f"/api/findings/{fid}/audit",
        json={"finding_id": fid, "analyst_action": "CONFIRM"},
        headers={"X-User-Role": "VIEWER", "X-User-Name": "Viewer Bob", "X-Data-Source": "LIVE"}
    )
    assert res.status_code == 403


def test_fallback_decision_policy_records_explicit_fallback_source():
    """When in FALLBACK mode, decisions are recorded with data_source=FALLBACK and never LIVE."""
    fid = "DEDUP-0002"
    conn = database._get_conn()
    conn.execute("DELETE FROM audit_trail WHERE finding_id = ?", (fid,))
    conn.commit()
    conn.close()

    res = client.post(
        f"/api/findings/{fid}/audit",
        json={"finding_id": fid, "analyst_action": "ACCEPT_PRIORITY", "rationale": "Fallback decision"},
        headers={"X-User-Role": "ANALYST", "X-User-Name": "Alice", "X-Data-Source": "FALLBACK"}
    )
    assert res.status_code == 200
    ev = res.json()
    assert ev["data_source"] == "FALLBACK"
    assert ev["data_source"] != "LIVE"

    # Verify chain passes for this fallback audit trail
    verify_res = client.get(f"/api/findings/{fid}/audit/verify").json()
    assert verify_res["valid"] is True
