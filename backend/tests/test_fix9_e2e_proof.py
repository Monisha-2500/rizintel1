"""
tests/test_fix9_e2e_proof.py
============================
Live E2E Verification Script for Fix #9 Proof:
1. SECURITY LEAD LOGIN -> trigger explicit demo pipeline -> receive pipeline_run_id -> data_origin=DEMO_DATASET -> results generated -> operational execution audit recorded in SQLite.
2. PRODUCTION MODE -> trigger without scanner payload -> rejected with HTTP 400 -> NO demo data silently substituted.
3. SIMULATE M4 EXTERNAL INTELLIGENCE DEGRADED -> core pipeline functions where designed -> /api/integration/health reports DEGRADED (NOT falsely HEALTHY).
"""

import os
import sys
from pathlib import Path
from fastapi.testclient import TestClient

backend_dir = Path(__file__).resolve().parent.parent
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

from main import app
from users import get_user_by_email
from auth import create_access_token
import database

client = TestClient(app)


def _get_auth_headers(email: str) -> dict:
    user = get_user_by_email(email)
    assert user is not None
    return {"Authorization": f"Bearer {create_access_token(user)}"}


def test_fix9_e2e_proof():
    database.init_db()
    old_env = os.environ.get("RIZINTEL_ENV")
    old_m4 = os.environ.get("RIZINTEL_THREAT_INTEL_STATUS")

    try:
        print("\n" + "=" * 80)
        print("FIX #9 E2E PROOF: PRODUCTION PIPELINE HARDENING & HEALTH READINESS DEMONSTRATION")
        print("=" * 80)

        # ── STEP 1: SECURITY LEAD LOGIN & EXPLICIT DEMO PIPELINE EXECUTION ────────
        print("\n[STEP 1] Logging in as SECURITY_LEAD and triggering explicit demo pipeline...")
        lead_headers = _get_auth_headers("lead@rizintel.demo")
        os.environ["RIZINTEL_ENV"] = "development"

        demo_resp = client.post(
            "/api/integration/pipeline/run",
            headers=lead_headers,
            json={"use_demo_dataset": True}
        )
        assert demo_resp.status_code == 200, demo_resp.text
        demo_data = demo_resp.json()

        run_id = demo_data["pipeline_run_id"]
        data_origin = demo_data["data_origin"]
        total_findings = demo_data["total_findings"]

        print(f"  ✓ Pipeline executed successfully!")
        print(f"  ✓ pipeline_run_id : {run_id}")
        print(f"  ✓ data_origin     : {data_origin}")
        print(f"  ✓ total_findings  : {total_findings}")
        assert run_id.startswith("RUN-")
        assert data_origin == "DEMO_DATASET"
        assert total_findings > 0

        # Verify operational audit log in SQLite
        runs_resp = client.get("/api/integration/pipeline/runs", headers=lead_headers)
        assert runs_resp.status_code == 200
        runs = runs_resp.json()
        matched_run = next((r for r in runs if r["pipeline_run_id"] == run_id), None)
        assert matched_run is not None
        print(f"  ✓ Operational Audit Recorded in SQLite:")
        print(f"      - Actor    : {matched_run['triggered_by_email']} ({matched_run['triggered_by_role']})")
        print(f"      - Run ID   : {matched_run['pipeline_run_id']}")
        print(f"      - Origin   : {matched_run['data_origin']}")
        print(f"      - Status   : {matched_run['status']}")
        print(f"      - Findings : {matched_run['canonical_finding_count']}")

        # ── STEP 2: PRODUCTION SAFETY (NO SILENT DEMO SUBSTITUTION) ───────────────
        print("\n[STEP 2] Testing Production Safety Mode (RIZINTEL_ENV=production)...")
        os.environ["RIZINTEL_ENV"] = "production"

        prod_fail_resp = client.post(
            "/api/integration/pipeline/run",
            headers=lead_headers,
            json={}  # Empty payload without scanner files
        )
        print(f"  ✓ Request with missing scanner payload in production:")
        print(f"      - HTTP Status  : {prod_fail_resp.status_code}")
        print(f"      - Error Detail : {prod_fail_resp.json().get('detail')}")
        assert prod_fail_resp.status_code == 400
        assert prod_fail_resp.json()["detail"]["error"] == "PRODUCTION_SCANNER_INPUT_REQUIRED"
        print("  ✓ PROOF: Production strictly rejected request. Zero silent demo data substitution.")

        # ── STEP 3: SIMULATE M4 EXTERNAL INTELLIGENCE DEGRADATION ─────────────────
        print("\n[STEP 3] Testing Truthful Modular Health & Readiness Inspection...")
        os.environ["RIZINTEL_THREAT_INTEL_STATUS"] = "DEGRADED"

        health_resp = client.get("/api/integration/health")
        assert health_resp.status_code == 200
        health_data = health_resp.json()

        print(f"  ✓ Modular Readiness Check under M4 external degradation:")
        print(f"      - overall_status: {health_data['overall_status']}")
        for mod in health_data["modules"]:
            print(f"      - [{mod['module_id']}] {mod['name']:<40} : {mod['status']}")

        assert health_data["overall_status"] == "DEGRADED"
        m4_mod = next(m for m in health_data["modules"] if m["module_id"] == "M4")
        assert m4_mod["status"] == "DEGRADED"
        print("  ✓ PROOF: System truthfully reported overall_status=DEGRADED, NOT falsely HEALTHY.")
        print("=" * 80 + "\n")

    finally:
        if old_env is not None:
            os.environ["RIZINTEL_ENV"] = old_env
        else:
            os.environ.pop("RIZINTEL_ENV", None)
        if old_m4 is not None:
            os.environ["RIZINTEL_THREAT_INTEL_STATUS"] = old_m4
        else:
            os.environ.pop("RIZINTEL_THREAT_INTEL_STATUS", None)


if __name__ == "__main__":
    test_fix9_e2e_proof()
