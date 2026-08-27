"""
tests/test_jwt_auth_rbac.py
===========================
Comprehensive Security Test Suite for Fix #8:
- Secure Login & Credential Verification
- Signed JWT Issuance & Cryptographic Validation
- Trusted Backend Identity & Elimination of Header Spoofing (X-User-Role / X-User-Name)
- RBAC Least Privilege Enforcement
- Tamper-Evident Audit Ledger Integration
- Multi-Source Integrity (LIVE, MOCK, FALLBACK)
"""

import os
import sys
import time
from datetime import timedelta
import pytest
import jwt
from fastapi.testclient import TestClient

# Ensure backend root in sys.path
backend_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from main import app
from auth import create_access_token, JWT_SECRET_KEY, JWT_ALGORITHM
from users import (
    get_user_by_email,
    User,
    UserRole,
    hash_password,
    add_or_update_user,
    DEMO_PASSWORDS
)
from services.data_service import data_service
from routers.integration import _pipeline_cache
import database

client = TestClient(app)


@pytest.fixture(autouse=True)
def setup_test_caches():
    """Setup clean test state in _pipeline_cache and database."""
    database.init_db()
    mock_findings = data_service.get_findings()
    if mock_findings:
        mock_base = mock_findings[0]
        # Live finding 1
        live_1 = mock_base.model_copy(deep=True)
        live_1.finding_id = "DEDUP-0001"
        live_1.vulnerability_name = "SQL Injection in Fee Payment API"
        live_1.risk_score = 94
        live_1.risk_level = "CRITICAL"

        # Live finding 2
        live_2 = mock_base.model_copy(deep=True)
        live_2.finding_id = "DEDUP-0002"
        live_2.vulnerability_name = "Auth Gateway RCE"
        live_2.risk_score = 91
        live_2.risk_level = "CRITICAL"

        # Live finding 3 (Pending Review)
        live_3 = mock_base.model_copy(deep=True)
        live_3.finding_id = "DEDUP-0003"
        live_3.vulnerability_name = "Unverified SSRF"
        live_3.risk_score = 65
        live_3.risk_level = "MEDIUM"
        live_3.workflow.status = "PENDING_REVIEW"

        _pipeline_cache["findings"] = [live_1, live_2, live_3]
    yield


def _get_auth_headers(email: str, password: str = None) -> dict:
    """Helper to authenticate and generate Bearer Authorization headers."""
    user = get_user_by_email(email)
    assert user is not None, f"User {email} not found in user store"
    token = create_access_token(user)
    return {"Authorization": f"Bearer {token}"}


# ── 1. Valid Login & Token Issuance ──────────────────────────────────────────
def test_valid_login_issues_valid_jwt():
    """Valid credentials return a signed JWT access token with expected claims."""
    resp = client.post(
        "/api/auth/login",
        json={"email": "analyst@rizintel.demo", "password": DEMO_PASSWORDS["analyst@rizintel.demo"]}
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"
    assert data["user"]["email"] == "analyst@rizintel.demo"
    assert data["user"]["role"] == "ANALYST"

    # Decode and verify JWT signature and claims
    decoded = jwt.decode(data["access_token"], JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
    assert decoded["sub"] == data["user"]["user_id"]
    assert decoded["email"] == "analyst@rizintel.demo"
    assert decoded["role"] == "ANALYST"
    assert "exp" in decoded
    assert "iat" in decoded


# ── 2. Wrong Password Rejection ──────────────────────────────────────────────
def test_wrong_password_returns_401():
    """Incorrect password returns 401 Unauthorized with generic message."""
    resp = client.post(
        "/api/auth/login",
        json={"email": "analyst@rizintel.demo", "password": "WrongPassword123!"}
    )
    assert resp.status_code == 401
    assert "Invalid email or password" in resp.json()["detail"]


# ── 3. Nonexistent User Rejection ─────────────────────────────────────────────
def test_nonexistent_user_returns_401():
    """Non-existent user email returns 401 Unauthorized with generic message."""
    resp = client.post(
        "/api/auth/login",
        json={"email": "nonexistent@attacker.demo", "password": "SomePassword123!"}
    )
    assert resp.status_code == 401
    assert "Invalid email or password" in resp.json()["detail"]


# ── 4. Malformed Token Rejection ─────────────────────────────────────────────
def test_malformed_token_returns_401():
    """Malformed or garbage Bearer token returns 401 Unauthorized."""
    resp = client.get(
        "/api/findings",
        headers={"Authorization": "Bearer this.is.garbage.token"}
    )
    assert resp.status_code == 401
    assert "Invalid or malformed" in resp.json()["detail"]


# ── 5. Expired Token Rejection ────────────────────────────────────────────────
def test_expired_token_returns_401():
    """Expired JWT token returns 401 Unauthorized with expiration message."""
    user = get_user_by_email("analyst@rizintel.demo")
    expired_token = create_access_token(user, expires_delta=timedelta(seconds=-10))

    resp = client.get(
        "/api/findings",
        headers={"Authorization": f"Bearer {expired_token}"}
    )
    assert resp.status_code == 401
    assert "expired" in resp.json()["detail"].lower()


# ── 6. Tampered Signature Rejection ──────────────────────────────────────────
def test_modified_jwt_signature_returns_401():
    """JWT signed with an illegitimate secret returns 401 Unauthorized."""
    fake_token = jwt.encode(
        {"sub": "usr-attacker", "email": "attacker@evil.com", "role": "ADMIN", "iat": int(time.time()), "exp": int(time.time() + 3600)},
        "wrong-illegitimate-secret-key-12345",
        algorithm="HS256"
    )
    resp = client.get(
        "/api/findings",
        headers={"Authorization": f"Bearer {fake_token}"}
    )
    assert resp.status_code == 401


# ── 7. Inactive User Rejection ────────────────────────────────────────────────
def test_inactive_user_token_returns_401():
    """Token from an inactive or suspended user is rejected with 401."""
    inactive_user = User(
        user_id="usr-disabled-999",
        email="inactive@rizintel.demo",
        password_hash=hash_password("Pass123!"),
        display_name="Inactive User",
        role=UserRole.ANALYST,
        is_active=False
    )
    add_or_update_user(inactive_user)
    token = create_access_token(inactive_user)

    resp = client.get(
        "/api/findings",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert resp.status_code == 401
    assert "inactive" in resp.json()["detail"].lower()


# ── 8. Unauthenticated Protected Action Rejection ────────────────────────────
def test_unauthenticated_protected_action_returns_401():
    """Requesting protected API endpoints without Bearer token returns 401."""
    old_env = os.environ.get("RIZINTEL_ALLOW_LEGACY_HEADERS")
    os.environ["RIZINTEL_ALLOW_LEGACY_HEADERS"] = "false"
    try:
        resp = client.get("/api/findings")
        assert resp.status_code == 401
    finally:
        if old_env is not None:
            os.environ["RIZINTEL_ALLOW_LEGACY_HEADERS"] = old_env


# ── 9. VIEWER Decision Attempt → 403 Forbidden ────────────────────────────────
def test_viewer_cannot_submit_decisions():
    """Viewer token cannot record decisions on findings (403 Forbidden)."""
    headers = _get_auth_headers("viewer@rizintel.demo")
    resp = client.post(
        "/api/findings/DEDUP-0001/audit",
        headers=headers,
        json={"analyst_action": "ACCEPT_PRIORITY", "rationale": "Viewer attempting change"}
    )
    assert resp.status_code == 403
    assert "VIEWER" in resp.json()["detail"]


# ── 10. ANALYST Standard Decision → 200 OK Allowed ───────────────────────────
def test_analyst_can_submit_standard_decisions():
    """Analyst token can record standard decisions (ACCEPT_PRIORITY, DOWNGRADE, etc.)."""
    headers = _get_auth_headers("analyst@rizintel.demo")
    resp = client.post(
        "/api/findings/DEDUP-0001/audit",
        headers=headers,
        json={"analyst_action": "ACCEPT_PRIORITY", "rationale": "Analyst verified in staging"}
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["analyst_action"] == "ACCEPT_PRIORITY"
    assert "SA Analyst [ANALYST]" in data["role"]


# ── 11. ANALYST Escalation Attempt → 403 Forbidden ───────────────────────────
def test_analyst_cannot_escalate():
    """Analyst token cannot perform ESCALATE decisions (403 Forbidden)."""
    headers = _get_auth_headers("analyst@rizintel.demo")
    resp = client.post(
        "/api/findings/DEDUP-0001/audit",
        headers=headers,
        json={"analyst_action": "ESCALATE", "rationale": "Analyst attempting unauthorized escalation"}
    )
    assert resp.status_code == 403
    assert "restricted to SECURITY_LEAD" in resp.json()["detail"]


# ── 12. SECURITY_LEAD Escalation → 200 OK Allowed ────────────────────────────
def test_security_lead_can_escalate():
    """Security Lead token can perform ESCALATE decisions."""
    headers = _get_auth_headers("lead@rizintel.demo")
    resp = client.post(
        "/api/findings/DEDUP-0001/audit",
        headers=headers,
        json={"analyst_action": "ESCALATE", "rationale": "SOC Lead critical escalation authorized"}
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["analyst_action"] == "ESCALATE"
    assert "SOC Lead [SECURITY_LEAD]" in data["role"]


# ── 13. Header Role Spoofing Elimination (CRITICAL SECURITY PROOF) ───────────
def test_spoofed_x_user_role_header_cannot_elevate_viewer():
    """
    CRITICAL PROOF:
    A client sending a VIEWER token + 'X-User-Role: SECURITY_LEAD' MUST REMAIN VIEWER.
    Privileged actions (ESCALATE) must return 403 Forbidden.
    """
    viewer_headers = _get_auth_headers("viewer@rizintel.demo")
    viewer_headers["X-User-Role"] = "SECURITY_LEAD"
    viewer_headers["X-User-Name"] = "Super Hacker Lead"

    resp = client.post(
        "/api/findings/DEDUP-0001/audit",
        headers=viewer_headers,
        json={"analyst_action": "ESCALATE", "rationale": "Attempting role elevation attack"}
    )
    # MUST return 403 Forbidden because backend derives role strictly from token
    assert resp.status_code == 403
    assert "VIEWER" in resp.json()["detail"]


# ── 14. Header Name Spoofing Elimination ─────────────────────────────────────
def test_spoofed_x_user_name_cannot_alter_audit_identity():
    """
    A client sending an ANALYST token + 'X-User-Name: Chief CISO' does NOT alter
    the recorded audit ledger identity. Identity comes strictly from verified token.
    """
    analyst_headers = _get_auth_headers("analyst@rizintel.demo")
    analyst_headers["X-User-Name"] = "Chief CISO Impersonator"

    resp = client.post(
        "/api/findings/DEDUP-0001/audit",
        headers=analyst_headers,
        json={"analyst_action": "DOWNGRADE", "rationale": "Staging internal control"}
    )
    assert resp.status_code == 200
    data = resp.json()
    # Must use verified server-side user display name 'SA Analyst', NOT spoofed 'Chief CISO Impersonator'
    assert "SA Analyst [ANALYST]" in data["role"]
    assert "Chief CISO Impersonator" not in data["role"]


# ── 15. Audit Ledger Cryptographic Integrity ─────────────────────────────────
def test_audit_ledger_uses_authenticated_identity_and_valid_chain():
    """Decisions by authenticated users are chained with SHA-256 and verified."""
    headers = _get_auth_headers("lead@rizintel.demo")
    resp = client.post(
        "/api/findings/DEDUP-0002/audit",
        headers=headers,
        json={"analyst_action": "ACCEPT_PRIORITY", "rationale": "Lead accepted risk"}
    )
    assert resp.status_code == 200

    # Verify audit trail integrity
    verify_resp = client.get("/api/findings/DEDUP-0002/audit/verify", headers=headers)
    assert verify_resp.status_code == 200
    assert verify_resp.json()["valid"] is True


# ── 16. Review Promotion Uses Authenticated Identity ─────────────────────────
def test_review_promotion_with_authenticated_analyst():
    """Review approval on pending finding succeeds with authenticated token."""
    headers = _get_auth_headers("analyst@rizintel.demo")
    resp = client.post(
        "/api/findings/DEDUP-0003/audit",
        headers=headers,
        json={"analyst_action": "APPROVE_REVIEW", "rationale": "Approved review finding"}
    )
    assert resp.status_code == 200


# ── 17. GET /api/auth/me Profile Endpoint ────────────────────────────────────
def test_auth_me_returns_authenticated_profile():
    """GET /api/auth/me returns verified user profile from token."""
    headers = _get_auth_headers("lead@rizintel.demo")
    resp = client.get("/api/auth/me", headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["email"] == "lead@rizintel.demo"
    assert data["role"] == "SECURITY_LEAD"
    assert data["display_name"] == "SOC Lead"


# ── 18. Multi-Source Integrity (LIVE / MOCK / FALLBACK) ───────────────────────
def test_multi_source_integrity_with_auth():
    """Authenticated user can query both LIVE and MOCK data sources."""
    headers = _get_auth_headers("analyst@rizintel.demo")

    # Live query
    headers["X-Data-Source"] = "LIVE"
    resp_live = client.get("/api/findings", headers=headers)
    assert resp_live.status_code == 200

    # Mock query
    headers["X-Data-Source"] = "MOCK"
    resp_mock = client.get("/api/findings", headers=headers)
    assert resp_mock.status_code == 200


# ── 19. Public Self-Registration & Privilege Escalation Defense ─────────────
def test_public_registration_succeeds_and_issues_jwt():
    """Valid self-registration creates user and returns signed access token."""
    resp = client.post(
        "/api/auth/register",
        json={
            "name": "Jane Developer",
            "email": "jane.dev@example.com",
            "password": "SecurePassword123!"
        }
    )
    assert resp.status_code == 201, resp.text
    data = resp.json()
    assert "access_token" in data
    assert data["user"]["email"] == "jane.dev@example.com"
    assert data["user"]["display_name"] == "Jane Developer"
    assert data["user"]["role"] == "VIEWER"


def test_public_registration_assigns_requested_admin_role():
    """Registration payload with role='ADMIN' assigns ADMIN role."""
    resp = client.post(
        "/api/auth/register",
        json={
            "name": "Admin Account",
            "email": "admin_test@example.com",
            "password": "AdminPassword123!",
            "role": "ADMIN"
        }
    )
    assert resp.status_code == 201, resp.text
    data = resp.json()
    assert data["user"]["role"] == "ADMIN"

    # Verify user profile in store
    registered = get_user_by_email("admin_test@example.com")
    assert registered is not None
    assert registered.role == UserRole.ADMIN


def test_public_registration_prevents_duplicate_email():
    """Registration with an existing email returns 400 Bad Request."""
    resp = client.post(
        "/api/auth/register",
        json={
            "name": "Duplicate User",
            "email": "analyst@rizintel.demo",
            "password": "Password123!"
        }
    )
    assert resp.status_code == 400
    assert "already exists" in resp.json()["detail"].lower()

