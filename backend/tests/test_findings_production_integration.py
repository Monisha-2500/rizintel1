"""
backend/tests/test_findings_production_integration.py
=====================================================
Production test suite for RizIntel Findings page and authoritative backend integration.
Verifies:
1. Canonical findings persistence and retrieval from SQLite
2. Direct Finding-by-ID canonical resolution
3. Scan-run scoped findings queries
4. Organization scoped findings queries
5. Multi-tenant isolation enforcement across organizations
6. RBAC access control (VIEWER, ANALYST, SECURITY_LEAD, ADMIN)
7. Cross-page data equality for canonical findings
8. API Pagination headers and slicing
"""

import os
import sys
import json
import pytest
from pathlib import Path
from fastapi.testclient import TestClient

backend_dir = Path(__file__).resolve().parent.parent
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

from main import app
from auth import create_access_token, AuthenticatedUser, UserRole
from users import get_user_by_email
import database as db

client = TestClient(app)

ORG_DEMO = "ORG-RIZZOLVE-DEMO"
ORG_ISOLATED = "ORG-SECRET-99"
REAL_SCAN_RUN = "SR-2C5BAAB5FB91"
REAL_CANONICAL_ID = "DEDUP-B858594F"


@pytest.fixture(autouse=True)
def ensure_db():
    db.init_db()


def _get_auth_headers(email: str = "analyst@rizintel.demo", role: str = "ANALYST") -> dict:
    user = get_user_by_email(email)
    if not user:
        user = AuthenticatedUser(
            user_id="usr-test-analyst",
            username="test_analyst",
            email=email,
            role=UserRole(role),
            display_name="Test Analyst"
        )
    token = create_access_token(user)
    return {"Authorization": f"Bearer {token}"}


def test_01_canonical_findings_retrieval():
    """Verify that /api/findings retrieves canonical persisted findings from SQLite."""
    headers = _get_auth_headers("analyst@rizintel.demo", "ANALYST")
    resp = client.get(f"/api/findings?organization_id={ORG_DEMO}", headers=headers)
    assert resp.status_code == 200
    findings = resp.json()
    assert isinstance(findings, list)
    assert len(findings) >= 1
    # Check schema compliance
    for f in findings:
        assert "finding_id" in f
        assert "risk_score" in f
        assert "risk_level" in f
        assert "confidence_classification" in f
        assert "workflow" in f


def test_02_canonical_finding_by_id():
    """Verify that /api/findings/{id} retrieves the exact canonical finding."""
    headers = _get_auth_headers("analyst@rizintel.demo", "ANALYST")
    resp = client.get(f"/api/findings/{REAL_CANONICAL_ID}?organization_id={ORG_DEMO}", headers=headers)
    assert resp.status_code == 200
    finding = resp.json()
    assert finding["finding_id"] == REAL_CANONICAL_ID
    assert finding["vulnerability_name"] == "SQL Injection"
    assert finding["risk_score"] == 30
    assert finding["confidence_classification"] == "NEEDS_REVIEW"
    assert finding["workflow"]["status"] == "PENDING_REVIEW"


def test_03_scan_run_scoped_findings():
    """Verify that passing scan_run_id returns strictly findings from that scan run."""
    headers = _get_auth_headers("analyst@rizintel.demo", "ANALYST")
    resp = client.get(f"/api/findings?scan_run_id={REAL_SCAN_RUN}&organization_id={ORG_DEMO}", headers=headers)
    assert resp.status_code == 200
    findings = resp.json()
    assert len(findings) == 2
    finding_ids = [f["finding_id"] for f in findings]
    assert REAL_CANONICAL_ID in finding_ids
    assert "DEDUP-371E34D2" in finding_ids


def test_04_cross_page_data_consistency():
    """
    Verify that the canonical finding has identical fields across:
    1. /api/findings
    2. /api/findings/{id}
    3. /api/v1/organizations/{org}/scan-runs/{sr}/results
    """
    headers = _get_auth_headers("lead@rizintel.demo", "SECURITY_LEAD")

    # 1. Findings list
    list_resp = client.get(f"/api/findings?scan_run_id={REAL_SCAN_RUN}&organization_id={ORG_DEMO}", headers=headers)
    assert list_resp.status_code == 200
    list_findings = list_resp.json()
    finding_from_list = next(f for f in list_findings if f["finding_id"] == REAL_CANONICAL_ID)

    # 2. Finding by ID
    single_resp = client.get(f"/api/findings/{REAL_CANONICAL_ID}?organization_id={ORG_DEMO}", headers=headers)
    assert single_resp.status_code == 200
    finding_from_single = single_resp.json()

    # 3. Scan run pipeline results
    sr_resp = client.get(f"/api/v1/organizations/{ORG_DEMO}/scan-runs/{REAL_SCAN_RUN}/results", headers=headers)
    assert sr_resp.status_code == 200
    sr_results = sr_resp.json()
    finding_from_sr = next(f for f in sr_results["findings"] if f["finding_id"] == REAL_CANONICAL_ID)

    # Assert exact equality across all representations
    for key in ["finding_id", "risk_score", "risk_level", "confidence_classification", "asset_id"]:
        assert finding_from_list[key] == finding_from_single[key] == finding_from_sr[key], f"Mismatch for key {key}"

    # Assert workflow SLA consistency
    assert finding_from_list["workflow"]["status"] == finding_from_single["workflow"]["status"] == finding_from_sr["workflow"]["status"]


def test_05_tenant_isolation():
    """Verify that a user from Org A cannot retrieve findings from isolated Org B."""
    # Member in ORG_ISOLATED
    user_isolated = AuthenticatedUser(
        user_id="usr-isolated-001",
        username="iso_user",
        email="iso@isolated.corp",
        role=UserRole.ANALYST,
        display_name="Isolated Analyst",
        display_title="Security Analyst"
    )
    # Ensure user has membership only in ORG_ISOLATED
    db.upsert_membership("mem-iso-01", ORG_ISOLATED, "usr-isolated-001", "ANALYST")

    token_isolated = create_access_token(user_isolated)
    headers_isolated = {"Authorization": f"Bearer {token_isolated}"}

    # Attempt to query ORG_DEMO findings with ORG_ISOLATED user
    resp = client.get(f"/api/findings?organization_id={ORG_DEMO}", headers=headers_isolated)
    assert resp.status_code == 200
    # Must return 0 findings (tenant isolated)
    assert len(resp.json()) == 0

    # Attempt to query canonical finding by ID from ORG_DEMO
    resp_id = client.get(f"/api/findings/{REAL_CANONICAL_ID}?organization_id={ORG_DEMO}", headers=headers_isolated)
    assert resp_id.status_code == 404


def test_06_rbac_access_control():
    """Verify RBAC rules: All roles can read findings, but only authorized roles can mutate/audit."""
    viewer_headers = _get_auth_headers("viewer@rizintel.demo", "VIEWER")
    analyst_headers = _get_auth_headers("analyst@rizintel.demo", "ANALYST")

    # Viewer can read findings
    resp_v = client.get(f"/api/findings?organization_id={ORG_DEMO}", headers=viewer_headers)
    assert resp_v.status_code == 200
    assert len(resp_v.json()) > 0

    # Viewer CANNOT submit audit decisions (403 Forbidden)
    resp_v_audit = client.post(
        f"/api/findings/{REAL_CANONICAL_ID}/audit",
        headers=viewer_headers,
        json={"finding_id": REAL_CANONICAL_ID, "analyst_action": "ACCEPT_PRIORITY", "rationale": "Test"}
    )
    assert resp_v_audit.status_code == 403

    # Analyst can submit standard priority decision
    resp_a_audit = client.post(
        f"/api/findings/{REAL_CANONICAL_ID}/audit",
        headers=analyst_headers,
        json={"finding_id": REAL_CANONICAL_ID, "analyst_action": "ACCEPT_PRIORITY", "rationale": "Verified in staging"}
    )
    assert resp_a_audit.status_code == 200


def test_07_pagination_headers():
    """Verify that pagination query parameters and response headers behave correctly."""
    headers = _get_auth_headers("analyst@rizintel.demo", "ANALYST")
    resp = client.get(f"/api/findings?organization_id={ORG_DEMO}&page=1&page_size=2", headers=headers)
    assert resp.status_code == 200
    assert "X-Total-Count" in resp.headers
    assert resp.headers["X-Page"] == "1"
    assert resp.headers["X-Page-Size"] == "2"
    items = resp.json()
    assert len(items) <= 2
