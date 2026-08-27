"""
tests/test_pipeline_production_hardening.py
===========================================
Comprehensive Test Suite for Fix #9:
- Pipeline Execution RBAC Authorization (Viewer/Analyst 403, Security Lead/Admin 200)
- Elimination of Header Spoofing on Pipeline Triggers
- Unique pipeline_run_id and data_origin Tagging
- Production Mode Safety (No Silent Demo Dataset Execution)
- Concurrency Safety & Mutex Protection
- Truthful Health vs Modular Readiness (HEALTHY, DEGRADED, NOT_READY)
- Operational Audit Ledger Persistence in SQLite
- Production Error Sanitization (No Leaked Stack Traces / Paths)
"""

import os
import sys
import threading
import time
from pathlib import Path
import pytest
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
    """Helper to generate valid Bearer token headers for a demo user."""
    user = get_user_by_email(email)
    assert user is not None, f"User {email} not found"
    token = create_access_token(user)
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture(autouse=True)
def setup_test_env():
    """Ensure clean test environment before each test."""
    database.init_db()
    old_env = os.environ.get("RIZINTEL_ENV")
    old_m4 = os.environ.get("RIZINTEL_THREAT_INTEL_STATUS")
    os.environ["RIZINTEL_ENV"] = "development"
    if "RIZINTEL_THREAT_INTEL_STATUS" in os.environ:
        del os.environ["RIZINTEL_THREAT_INTEL_STATUS"]

    # Invalidate health check TTL cache so each test gets a fresh evaluation
    try:
        from routers.integration import _health_cache, _health_cache_lock
        with _health_cache_lock:
            _health_cache["result"] = None
            _health_cache["probes"] = None
            _health_cache["expires_at"] = 0.0
    except Exception:
        pass

    yield
    if old_env is not None:
        os.environ["RIZINTEL_ENV"] = old_env
    else:
        os.environ.pop("RIZINTEL_ENV", None)
    if old_m4 is not None:
        os.environ["RIZINTEL_THREAT_INTEL_STATUS"] = old_m4
    else:
        os.environ.pop("RIZINTEL_THREAT_INTEL_STATUS", None)

    # Restore clean health cache state after test
    try:
        from routers.integration import _health_cache, _health_cache_lock
        with _health_cache_lock:
            _health_cache["result"] = None
            _health_cache["probes"] = None
            _health_cache["expires_at"] = 0.0
    except Exception:
        pass



# ── 1. Unauthenticated Pipeline Run ──────────────────────────────────────────
def test_unauthenticated_pipeline_run_returns_401():
    """Unauthenticated POST /api/integration/pipeline/run returns 401."""
    resp = client.post("/api/integration/pipeline/run", json={})
    assert resp.status_code == 401


# ── 2. VIEWER Role Pipeline Run ──────────────────────────────────────────────
def test_viewer_cannot_run_pipeline():
    """VIEWER token cannot trigger pipeline execution (403 Forbidden)."""
    headers = _get_auth_headers("viewer@rizintel.demo")
    resp = client.post("/api/integration/pipeline/run", headers=headers, json={})
    assert resp.status_code == 403
    assert "VIEWER" in resp.json()["detail"]


# ── 3. ANALYST Role Pipeline Run ─────────────────────────────────────────────
def test_analyst_cannot_run_pipeline():
    """ANALYST token cannot trigger pipeline execution (403 Forbidden)."""
    headers = _get_auth_headers("analyst@rizintel.demo")
    resp = client.post("/api/integration/pipeline/run", headers=headers, json={})
    assert resp.status_code == 403
    assert "ANALYST" in resp.json()["detail"]


# ── 4. SECURITY_LEAD Role Pipeline Run ───────────────────────────────────────
def test_security_lead_can_run_pipeline():
    """SECURITY_LEAD token is authorized (200 OK) to trigger pipeline."""
    headers = _get_auth_headers("lead@rizintel.demo")
    resp = client.post(
        "/api/integration/pipeline/run",
        headers=headers,
        json={"use_demo_dataset": True}
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "SUCCESS"
    assert data["pipeline_run_id"].startswith("RUN-")
    assert data["data_origin"] == "DEMO_DATASET"
    assert data["total_findings"] > 0


# ── 5. ADMIN Role Pipeline Run ───────────────────────────────────────────────
def test_admin_can_run_pipeline():
    """ADMIN token is authorized (200 OK) to trigger pipeline."""
    headers = _get_auth_headers("admin@rizintel.demo")
    resp = client.post(
        "/api/integration/pipeline/run",
        headers=headers,
        json={"use_demo_dataset": True}
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "SUCCESS"
    assert data["pipeline_run_id"].startswith("RUN-")


# ── 6. Header Role Spoofing Elimination ──────────────────────────────────────
def test_spoofed_header_cannot_elevate_viewer_or_analyst():
    """
    Sending an ANALYST or VIEWER token along with 'X-User-Role: SECURITY_LEAD'
    MUST NOT permit pipeline execution. Must strictly return 403 Forbidden.
    """
    analyst_headers = _get_auth_headers("analyst@rizintel.demo")
    analyst_headers["X-User-Role"] = "SECURITY_LEAD"
    analyst_headers["X-User-Name"] = "Chief Admin"

    resp = client.post(
        "/api/integration/pipeline/run",
        headers=analyst_headers,
        json={"use_demo_dataset": True}
    )
    assert resp.status_code == 403
    assert "ANALYST" in resp.json()["detail"]


# ── 7. Production Run Without Scanner Input Rejected ─────────────────────────
def test_production_run_without_scanner_input_rejected():
    """In production mode, missing scanner inputs returns 400 Bad Request."""
    os.environ["RIZINTEL_ENV"] = "production"
    headers = _get_auth_headers("lead@rizintel.demo")

    resp = client.post(
        "/api/integration/pipeline/run",
        headers=headers,
        json={"use_demo_dataset": True}  # Attempting demo in production
    )
    assert resp.status_code == 400
    err_data = resp.json()
    detail = err_data.get("detail", {})
    assert detail.get("error") == "PRODUCTION_SCANNER_INPUT_REQUIRED"
    assert "Production environment requires live scanner inputs" in detail.get("message", "")


# ── 8. Production Cannot Silently Load Demo Dataset ──────────────────────────
def test_production_cannot_silently_load_demo_data():
    """Production mode rejects empty payloads without silently executing bundled samples."""
    os.environ["RIZINTEL_ENV"] = "production"
    headers = _get_auth_headers("lead@rizintel.demo")

    resp = client.post(
        "/api/integration/pipeline/run",
        headers=headers,
        json={}
    )
    assert resp.status_code == 400
    assert resp.json()["detail"]["error"] == "PRODUCTION_SCANNER_INPUT_REQUIRED"


# ── 9. Explicit Live Scanner Run Succeeds in Production ───────────────────────
def test_production_live_scanner_run_succeeds():
    """Production mode with real scanner data succeeds and tags LIVE_SCAN."""
    os.environ["RIZINTEL_ENV"] = "production"
    headers = _get_auth_headers("lead@rizintel.demo")

    webgoat_dir = backend_dir / "mem1" / "webgoat"
    with open(webgoat_dir / "webgoat-ZAP-Report.json") as f:
        zap_data = f.read()

    resp = client.post(
        "/api/integration/pipeline/run",
        headers=headers,
        json={"raw_sources": {"ZAP": zap_data}}
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "SUCCESS"
    assert data["data_origin"] == "LIVE_SCAN"
    assert data["pipeline_run_id"].startswith("RUN-")


# ── 10. Pipeline Run ID Uniqueness ───────────────────────────────────────────
def test_every_run_receives_unique_run_id():
    """Consecutive pipeline executions produce distinct pipeline_run_id values."""
    headers = _get_auth_headers("lead@rizintel.demo")

    resp1 = client.post("/api/integration/pipeline/run", headers=headers, json={"use_demo_dataset": True})
    resp2 = client.post("/api/integration/pipeline/run", headers=headers, json={"use_demo_dataset": True})

    assert resp1.status_code == 200
    assert resp2.status_code == 200
    run1 = resp1.json()["pipeline_run_id"]
    run2 = resp2.json()["pipeline_run_id"]
    assert run1 != run2
    assert run1.startswith("RUN-")
    assert run2.startswith("RUN-")


# ── 11. Data Origin Tagging (LIVE_SCAN vs DEMO_DATASET) ──────────────────────
def test_data_origin_tagging():
    """Pipeline results accurately differentiate LIVE_SCAN from DEMO_DATASET."""
    headers = _get_auth_headers("lead@rizintel.demo")

    # Demo dataset
    resp_demo = client.post("/api/integration/pipeline/run", headers=headers, json={"use_demo_dataset": True})
    assert resp_demo.json()["data_origin"] == "DEMO_DATASET"

    # Live scan
    webgoat_dir = backend_dir / "mem1" / "webgoat"
    with open(webgoat_dir / "webgoat-ZAP-Report.json") as f:
        zap_data = f.read()

    resp_live = client.post("/api/integration/pipeline/run", headers=headers, json={"raw_sources": {"ZAP": zap_data}})
    assert resp_live.json()["data_origin"] == "LIVE_SCAN"


# ── 12. Failed Run Does Not Overwrite Latest Successful Results ───────────────
def test_failed_run_preserves_latest_successful_cache():
    """If a subsequent run fails or is rejected, the existing pipeline cache remains intact."""
    headers = _get_auth_headers("lead@rizintel.demo")

    # 1. Successful run
    resp_ok = client.post("/api/integration/pipeline/run", headers=headers, json={"use_demo_dataset": True})
    assert resp_ok.status_code == 200
    original_run_id = resp_ok.json()["pipeline_run_id"]

    # 2. Trigger invalid/failed run in production
    os.environ["RIZINTEL_ENV"] = "production"
    resp_fail = client.post("/api/integration/pipeline/run", headers=headers, json={})
    assert resp_fail.status_code == 400

    # 3. Retrieve latest findings — should still reflect original successful run
    resp_findings = client.get("/api/integration/pipeline/findings", headers=headers)
    assert resp_findings.status_code == 200
    findings = resp_findings.json()
    # Cache was NOT cleared by the failed run — findings are still present
    assert len(findings) > 0


# ── 13. Concurrent Execution Safety ──────────────────────────────────────────
def test_concurrent_pipeline_executions():
    """Simultaneous pipeline runs execute safely without race conditions or data corruption."""
    headers = _get_auth_headers("lead@rizintel.demo")
    results = []
    errors = []

    def run_worker(idx):
        try:
            resp = client.post(
                "/api/integration/pipeline/run",
                headers=headers,
                json={"use_demo_dataset": True}
            )
            if resp.status_code == 200:
                results.append(resp.json()["pipeline_run_id"])
            else:
                errors.append(f"Worker {idx} failed with {resp.status_code}: {resp.text}")
        except Exception as e:
            errors.append(f"Worker {idx} exception: {e}")

    threads = [threading.Thread(target=run_worker, args=(i,)) for i in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(errors) == 0, f"Concurrent errors: {errors}"
    assert len(results) == 4
    # All 4 run IDs should be unique
    assert len(set(results)) == 4


# ── 14. Basic Health vs Modular Readiness Separation ──────────────────────────
def test_health_vs_readiness_separation():
    """
    GET /health and /api/health return basic process liveness.
    GET /api/integration/health returns modular component readiness.
    """
    resp_basic = client.get("/health")
    assert resp_basic.status_code == 200
    assert resp_basic.json()["status"] == "healthy"

    resp_api_basic = client.get("/api/health")
    assert resp_api_basic.status_code == 200
    assert resp_api_basic.json()["status"] == "healthy"

    resp_readiness = client.get("/api/integration/health")
    assert resp_readiness.status_code == 200
    data = resp_readiness.json()
    assert "overall_status" in data
    assert len(data["modules"]) == 8


# ── 15. Readiness Truthfully Reports DEGRADED ─────────────────────────────────
def test_readiness_reports_degraded_when_threat_intel_degraded():
    """Simulating external threat intel unavailability truthfully sets DEGRADED status."""
    try:
        os.environ["RIZINTEL_THREAT_INTEL_STATUS"] = "DEGRADED"

        resp = client.get("/api/integration/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["overall_status"] == "DEGRADED"

        m4_mod = next((m for m in data["modules"] if m["module_id"] == "M4"), None)
        assert m4_mod is not None
        assert m4_mod["status"] == "DEGRADED"
        assert "offline" in m4_mod["description"].lower() or "fallback" in m4_mod["description"].lower()
    finally:
        os.environ.pop("RIZINTEL_THREAT_INTEL_STATUS", None)


# ── 16. Error Sanitization (No Stack Traces / Paths Leaked) ───────────────────
def test_errors_do_not_expose_stack_traces_or_system_paths():
    """Error responses are structured and do not leak Python tracebacks or local filesystem paths."""
    os.environ["RIZINTEL_ENV"] = "production"
    headers = _get_auth_headers("lead@rizintel.demo")

    resp = client.post("/api/integration/pipeline/run", headers=headers, json={})
    assert resp.status_code == 400
    body_text = resp.text

    assert "Traceback (most recent call last)" not in body_text
    assert "/Users/" not in body_text
    assert "File \"" not in body_text
    assert "line " not in body_text


# ── 17. Operational Audit Ledger Records Pipeline Execution ───────────────────
def test_operational_audit_records_privileged_execution():
    """Pipeline runs are logged to SQLite pipeline_execution_log with actor metadata."""
    headers = _get_auth_headers("lead@rizintel.demo")

    resp = client.post(
        "/api/integration/pipeline/run",
        headers=headers,
        json={"use_demo_dataset": True}
    )
    assert resp.status_code == 200
    run_id = resp.json()["pipeline_run_id"]

    # Check operational audit logs endpoint
    runs_resp = client.get("/api/integration/pipeline/runs", headers=headers)
    assert runs_resp.status_code == 200
    runs_list = runs_resp.json()
    assert len(runs_list) > 0

    latest_run = next((r for r in runs_list if r["pipeline_run_id"] == run_id), None)
    assert latest_run is not None
    assert latest_run["triggered_by_email"] == "lead@rizintel.demo"
    assert latest_run["triggered_by_role"] == "SECURITY_LEAD"
    assert latest_run["status"] == "SUCCESS"
    assert latest_run["data_origin"] == "DEMO_DATASET"
    assert latest_run["canonical_finding_count"] > 0


# ── 18. Viewer/Analyst Cannot Access /pipeline/runs ──────────────────────────
def test_viewer_cannot_access_pipeline_runs():
    """VIEWER and ANALYST tokens must receive 403 on GET /api/integration/pipeline/runs."""
    viewer_headers = _get_auth_headers("viewer@rizintel.demo")
    analyst_headers = _get_auth_headers("analyst@rizintel.demo")

    resp_viewer = client.get("/api/integration/pipeline/runs", headers=viewer_headers)
    assert resp_viewer.status_code == 403, f"Expected 403 for VIEWER, got {resp_viewer.status_code}"

    resp_analyst = client.get("/api/integration/pipeline/runs", headers=analyst_headers)
    assert resp_analyst.status_code == 403, f"Expected 403 for ANALYST, got {resp_analyst.status_code}"


# ── 19. Demo-Users Endpoint Disabled in Production ────────────────────────────
def test_demo_users_disabled_in_production():
    """GET /api/auth/demo-users must return 404 when RIZINTEL_ENV=production."""
    os.environ["RIZINTEL_ENV"] = "production"
    resp = client.get("/api/auth/demo-users")
    assert resp.status_code == 404, f"Expected 404 in production, got {resp.status_code}"


def test_demo_users_available_in_development():
    """GET /api/auth/demo-users must return 200 in development mode."""
    os.environ["RIZINTEL_ENV"] = "development"
    resp = client.get("/api/auth/demo-users")
    assert resp.status_code == 200
    assert len(resp.json()) > 0


# ── 20. Schema v1.0 Integrity: pipeline_run_id/data_origin in envelope only ───
def test_schema_v1_finding_does_not_contain_pipeline_metadata():
    """FindingSchema (Schema v1.0) must NOT contain pipeline_run_id or data_origin.
    These fields belong only in the PipelineRunResponse envelope."""
    headers = _get_auth_headers("lead@rizintel.demo")
    resp = client.post("/api/integration/pipeline/run", headers=headers, json={"use_demo_dataset": True})
    assert resp.status_code == 200
    data = resp.json()

    # Envelope carries the fields
    assert "pipeline_run_id" in data
    assert "data_origin" in data
    assert data["pipeline_run_id"].startswith("RUN-")

    # Individual FindingSchema objects must NOT carry them
    findings = data["findings"]
    assert len(findings) > 0
    first_finding = findings[0]
    assert "pipeline_run_id" not in first_finding, "Schema v1.0 violation: pipeline_run_id leaked into FindingSchema"
    assert "data_origin" not in first_finding, "Schema v1.0 violation: data_origin leaked into FindingSchema"
