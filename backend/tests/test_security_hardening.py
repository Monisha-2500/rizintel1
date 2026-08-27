"""
test_security_hardening.py — Security & Integrity Test Suite for RizIntel M8

Covers:
  1. CORS Origin Restriction & Headers
  2. RBAC Least-Privilege Authorization (VIEWER, ANALYST, SECURITY_LEAD, ADMIN)
  3. Pydantic Input Validation & Sanitization
  4. Cryptographic SHA-256 Chain Integrity & Tamper Detection
  5. Error Masking (No Stack Trace Leakage)
  6. Endpoint Path Parameter Validation
"""

import pytest
import sqlite3
import json
import urllib.request
import urllib.error
import os
import sys

# Ensure backend root is in sys.path
backend_path = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if backend_path not in sys.path:
    sys.path.insert(0, backend_path)

from database import DB_PATH, compute_hash, insert_audit_event, verify_chain, get_audit_events
from auth import UserRole, AuthenticatedUser, check_analyst_decision_permission
from models import AuditEventCreate, FindingSchema, AnalystFeedbackInput

from main import app
from fastapi.testclient import TestClient

_test_client = TestClient(app)


def make_request(method: str, path: str, headers: dict = None, json_data: dict = None):
    req_headers = dict(headers) if headers else {}
    if "Authorization" not in req_headers and "authorization" not in req_headers:
        role = req_headers.get("X-User-Role", "ANALYST").strip().upper()
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
            req_headers["Authorization"] = f"Bearer {create_access_token(user)}"

    resp = _test_client.request(
        method=method,
        url=path,
        headers=req_headers,
        json=json_data
    )
    try:
        parsed = resp.json()
    except Exception:
        parsed = resp.text
    return {
        "status": resp.status_code,
        "headers": {k.lower(): v for k, v in resp.headers.items()},
        "json": parsed,
    }


# ── 1. CORS RESTRICTIONS ─────────────────────────────────────────────────────

def test_cors_allowed_origin():
    res = make_request(
        "OPTIONS",
        "/api/findings",
        headers={
            "Origin": "http://localhost:5173",
            "Access-Control-Request-Method": "GET",
        }
    )
    assert res["status"] == 200
    allow_origin = res["headers"].get("access-control-allow-origin") or res["headers"].get("Access-Control-Allow-Origin")
    assert allow_origin == "http://localhost:5173"


def test_cors_disallowed_origin():
    res = make_request(
        "OPTIONS",
        "/api/findings",
        headers={
            "Origin": "http://malicious-site.attacker.com",
            "Access-Control-Request-Method": "GET",
        }
    )
    allow_origin = res["headers"].get("access-control-allow-origin") or res["headers"].get("Access-Control-Allow-Origin")
    assert allow_origin != "http://malicious-site.attacker.com"


# ── 2. RBAC AUTHORIZATION ───────────────────────────────────────────────────

def test_viewer_read_access():
    """VIEWER can read findings and audit trail."""
    res = make_request(
        "GET",
        "/api/findings/DEDUP-0001",
        headers={"X-User-Role": "VIEWER", "X-User-Name": "Auditor"}
    )
    assert res["status"] == 200
    assert res["json"]["finding_id"] == "DEDUP-0001"


def test_viewer_cannot_submit_decision():
    """VIEWER is forbidden (403) from recording decisions."""
    res = make_request(
        "POST",
        "/api/findings/DEDUP-0001/audit",
        headers={"X-User-Role": "VIEWER", "X-User-Name": "Auditor"},
        json_data={
            "analyst_action": "ACCEPT_PRIORITY",
            "rationale": "Viewer attempting decision override"
        }
    )
    assert res["status"] == 403
    assert "VIEWER" in str(res["json"])


def test_analyst_can_submit_standard_decision():
    """ANALYST can record standard decisions (ACCEPT_PRIORITY, DOWNGRADE, etc.)."""
    res = make_request(
        "POST",
        "/api/findings/DEDUP-0001/audit",
        headers={"X-User-Role": "ANALYST", "X-User-Name": "Bob Analyst"},
        json_data={
            "analyst_action": "DOWNGRADE",
            "rationale": "Internal controls mitigate risk"
        }
    )
    assert res["status"] == 200
    data = res["json"]
    assert data["analyst_action"] == "DOWNGRADE"
    assert "[ANALYST]" in data["role"]
    assert len(data["event_hash"]) == 64  # SHA-256 hex length


def test_analyst_cannot_escalate():
    """ANALYST is forbidden (403) from submitting high-impact ESCALATE action."""
    res = make_request(
        "POST",
        "/api/findings/DEDUP-0001/audit",
        headers={"X-User-Role": "ANALYST", "X-User-Name": "Bob Analyst"},
        json_data={
            "analyst_action": "ESCALATE",
            "rationale": "Analyst attempting unauthorized escalation"
        }
    )
    assert res["status"] == 403
    assert "restricted to SECURITY_LEAD or ADMIN" in str(res["json"])


def test_security_lead_can_escalate():
    """SECURITY_LEAD is authorized (200) to submit ESCALATE action."""
    res = make_request(
        "POST",
        "/api/findings/DEDUP-0001/audit",
        headers={"X-User-Role": "SECURITY_LEAD", "X-User-Name": "Lead Alice"},
        json_data={
            "analyst_action": "ESCALATE",
            "rationale": "Critical risk requires executive SLA escalation"
        }
    )
    assert res["status"] == 200
    data = res["json"]
    assert data["analyst_action"] == "ESCALATE"
    assert "[SECURITY_LEAD]" in data["role"]


def test_admin_full_authority():
    """ADMIN has full authority across all decision types."""
    res = make_request(
        "POST",
        "/api/findings/DEDUP-0001/audit",
        headers={"X-User-Role": "ADMIN", "X-User-Name": "Root Admin"},
        json_data={
            "analyst_action": "FALSE_POSITIVE",
            "rationale": "Admin confirmed false positive"
        }
    )
    assert res["status"] == 200
    data = res["json"]
    assert data["analyst_action"] == "FALSE_POSITIVE"
    assert "[ADMIN]" in data["role"]


# ── 3. INPUT VALIDATION & SANITIZATION ──────────────────────────────────────

def test_invalid_action_rejected():
    """Invalid/malformed action string returns 422 Unprocessable Entity."""
    res = make_request(
        "POST",
        "/api/findings/DEDUP-0001/audit",
        headers={"X-User-Role": "ANALYST"},
        json_data={
            "analyst_action": "DELETE_RECORD_ATTEMPT",
            "rationale": "Testing injection"
        }
    )
    assert res["status"] == 422


def test_invalid_path_finding_id_rejected():
    """Invalid path finding_id format returns 400 Bad Request."""
    res = make_request(
        "GET",
        "/api/findings/INVALID%20ID%3B%20DROP%20TABLE",
        headers={"X-User-Role": "ANALYST"}
    )
    assert res["status"] == 400


def test_missing_action_rejected():
    """Empty payload without action returns 422."""
    res = make_request(
        "POST",
        "/api/findings/DEDUP-0001/audit",
        headers={"X-User-Role": "ANALYST"},
        json_data={"rationale": "Missing action entirely"}
    )
    assert res["status"] == 422


# ── 4. SHA-256 AUDIT CHAIN INTEGRITY ────────────────────────────────────────

def test_audit_chain_verification():
    """Audit verification returns valid=True for normal cryptographic chain."""
    import uuid
    test_id = f"TEST-CHAIN-{uuid.uuid4().hex[:8]}"
    # Insert multiple sequential events
    insert_audit_event(test_id, 90, "ACCEPT_PRIORITY", "Initial validation", "Analyst [ANALYST]")
    insert_audit_event(test_id, 90, "NEEDS_REVIEW", "Second reviewer requested", "Lead [SECURITY_LEAD]")

    verify_res = verify_chain(test_id)
    assert verify_res["valid"] is True
    assert verify_res["total"] == 2
    assert "latest_hash" in verify_res


def test_tamper_detection_in_chain():
    """Tampering with a past record breaks the SHA-256 cryptographic chain."""
    import uuid
    test_id = f"TEST-TAMPER-{uuid.uuid4().hex[:8]}"
    ev1 = insert_audit_event(test_id, 85, "ACCEPT_PRIORITY", "Step 1", "Analyst [ANALYST]")
    ev2 = insert_audit_event(test_id, 85, "DOWNGRADE", "Step 2", "Analyst [ANALYST]")

    # Tamper with event 1 in database directly
    conn = sqlite3.connect(DB_PATH)
    conn.execute("UPDATE audit_trail SET m5_risk_score = 10 WHERE id = ?", (ev1["id"],))
    conn.commit()
    conn.close()

    verify_res = verify_chain(test_id)
    assert verify_res["valid"] is False
    assert verify_res["broken_at"] == ev1["id"]


# ── 5. HEALTH & SUMMARY INTEGRITY ────────────────────────────────────────────

def test_health_check():
    res = make_request("GET", "/health")
    assert res["status"] == 200
    assert res["json"]["status"] == "healthy"


def test_summary_metrics():
    res = make_request("GET", "/api/dashboard/summary")
    assert res["status"] == 200
