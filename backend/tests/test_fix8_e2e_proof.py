"""
tests/test_fix8_e2e_proof.py
============================
Live E2E Verification Script for Fix #8 Proof:
1. LOGIN AS VIEWER -> Dashboard query works (200), decision attempt -> 403 Forbidden.
2. LOGIN AS ANALYST -> Finding lookup works (200), standard decision succeeds (200), audit records analyst's authenticated identity, escalation attempt -> 403 Forbidden.
3. LOGIN AS SECURITY LEAD -> Escalation succeeds (200), audit records Security Lead identity.
4. ROLE SPOOFING ATTACK -> Authenticated VIEWER token + X-User-Role: SECURITY_LEAD on escalation endpoint -> strictly 403 Forbidden.
"""

import os
import sys
from fastapi.testclient import TestClient

backend_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from main import app
from services.data_service import data_service
from routers.integration import _pipeline_cache
import database

client = TestClient(app)


def test_e2e_security_proof_flow():
    database.init_db()
    mock_base = data_service.get_findings()[0]
    live_1 = mock_base.model_copy(deep=True)
    live_1.finding_id = "DEDUP-0001"
    live_1.vulnerability_name = "SQL Injection in Fee Payment API"
    live_1.risk_score = 94
    live_1.risk_level = "CRITICAL"
    _pipeline_cache["findings"] = [live_1]

    print("\n" + "=" * 80)
    print("FIX #8 E2E SECURITY PROOF: AUTHENTICATION & TRUSTED IDENTITY DEMONSTRATION")
    print("=" * 80)

    # ── STEP 1: LOGIN AS VIEWER ────────────────────────────────────────────────
    v_login = client.post("/api/auth/login", json={"email": "viewer@rizintel.demo", "password": "Viewer2026!"})
    assert v_login.status_code == 200, f"Viewer login failed: {v_login.text}"
    v_token = v_login.json()["access_token"]
    v_headers = {"Authorization": f"Bearer {v_token}"}
    print("✓ 1. Logged in as VIEWER (Token issued).")

    # Dashboard works
    v_dash = client.get("/api/dashboard/summary", headers=v_headers)
    assert v_dash.status_code == 200
    print("✓ 2. VIEWER dashboard access succeeded (200 OK).")

    # Decision attempt returns 403
    v_dec = client.post(
        "/api/findings/DEDUP-0001/audit",
        headers=v_headers,
        json={"analyst_action": "ACCEPT_PRIORITY", "rationale": "Viewer override"}
    )
    assert v_dec.status_code == 403
    print("✓ 3. VIEWER decision attempt blocked (403 Forbidden).")

    # ── STEP 2: LOGIN AS ANALYST ───────────────────────────────────────────────
    a_login = client.post("/api/auth/login", json={"email": "analyst@rizintel.demo", "password": "Analyst2026!"})
    assert a_login.status_code == 200
    a_token = a_login.json()["access_token"]
    a_headers = {"Authorization": f"Bearer {a_token}"}
    print("\n✓ 4. Logged in as ANALYST (Token issued).")

    # Live finding opens
    a_finding = client.get("/api/findings/DEDUP-0001", headers=a_headers)
    assert a_finding.status_code == 200
    print("✓ 5. ANALYST finding detail lookup succeeded (200 OK).")

    # Standard decision succeeds
    a_dec = client.post(
        "/api/findings/DEDUP-0001/audit",
        headers=a_headers,
        json={"analyst_action": "ACCEPT_PRIORITY", "rationale": "Staging verified"}
    )
    assert a_dec.status_code == 200
    a_audit_data = a_dec.json()
    assert "SA Analyst [ANALYST]" in a_audit_data["role"]
    print(f"✓ 6. ANALYST standard decision succeeded. Audit identity: '{a_audit_data['role']}'.")

    # Escalation attempt returns 403
    a_esc = client.post(
        "/api/findings/DEDUP-0001/audit",
        headers=a_headers,
        json={"analyst_action": "ESCALATE", "rationale": "Analyst escalation"}
    )
    assert a_esc.status_code == 403
    print("✓ 7. ANALYST unauthorized escalation blocked (403 Forbidden).")

    # ── STEP 3: LOGIN AS SECURITY LEAD ─────────────────────────────────────────
    l_login = client.post("/api/auth/login", json={"email": "lead@rizintel.demo", "password": "Lead2026!"})
    assert l_login.status_code == 200
    l_token = l_login.json()["access_token"]
    l_headers = {"Authorization": f"Bearer {l_token}"}
    print("\n✓ 8. Logged in as SECURITY_LEAD (Token issued).")

    # Escalation succeeds
    l_esc = client.post(
        "/api/findings/DEDUP-0001/audit",
        headers=l_headers,
        json={"analyst_action": "ESCALATE", "rationale": "Executive escalation"}
    )
    assert l_esc.status_code == 200
    l_audit_data = l_esc.json()
    assert "SOC Lead [SECURITY_LEAD]" in l_audit_data["role"]
    print(f"✓ 9. SECURITY_LEAD escalation succeeded. Audit identity: '{l_audit_data['role']}'.")

    # ── STEP 4: HEADER SPOOFING ATTACK TEST (CRITICAL PROOF) ───────────────────
    print("\n⚡ 10. Executing Header Spoofing Attack:")
    print("     Sending: Authorization: Bearer <VIEWER_TOKEN>")
    print("            + X-User-Role: SECURITY_LEAD")
    print("            + X-User-Name: Chief_Attacker")
    print("     Target : POST /api/findings/DEDUP-0001/audit (action: ESCALATE)")

    spoof_headers = {
        "Authorization": f"Bearer {v_token}",
        "X-User-Role": "SECURITY_LEAD",
        "X-User-Name": "Chief_Attacker"
    }
    spoof_resp = client.post(
        "/api/findings/DEDUP-0001/audit",
        headers=spoof_headers,
        json={"analyst_action": "ESCALATE", "rationale": "Privilege escalation injection"}
    )
    print(f"     Backend Response Status: HTTP {spoof_resp.status_code}")
    print(f"     Backend Diagnostic Detail: {spoof_resp.json().get('detail')}")
    assert spoof_resp.status_code == 403
    assert "VIEWER" in spoof_resp.json()["detail"]
    print("✓ 11. CRITICAL PROOF: Spoofed X-User-Role cannot elevate VIEWER. Operation rejected with 403 Forbidden!")
    print("=" * 80 + "\n")


if __name__ == "__main__":
    test_e2e_security_proof_flow()
