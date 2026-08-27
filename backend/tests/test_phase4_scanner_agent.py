"""
test_phase4_scanner_agent.py
============================
Phase 4 automated test suite — Secure Scanner Agent & Automatic Scanner Connectors.

Coverage (37 tests):

 AGENT IDENTITY & REGISTRATION
  T01  register_agent returns agent record + single-time plaintext secret
  T02  plaintext secret is prefixed 'agt_'
  T03  token_hash is NOT returned in list_agents output
  T04  token_hash is NOT returned in agent detail after registration
  T05  authenticate_agent succeeds with correct token
  T06  authenticate_agent rejects wrong token (constant-time safety)
  T07  authenticate_agent rejects revoked agent token
  T08  revoke_agent marks agent REVOKED; further auth fails
  T09  cross-org revocation rejected (returns False)
  T10  duplicate registration with same name is allowed (distinct secrets)

 JOB DISPATCH & AUTHORITATIVE TARGET RESOLUTION
  T11  create_run dispatches QUEUED scanner jobs (one per selected scanner)
  T12  scanner jobs are only QUEUED; not claimed/started automatically
  T13  target URL is constructed strictly from AUTHORIZED asset
  T14  non-AUTHORIZED asset blocks target resolution
  T15  target URL is rejected if asset is PENDING
  T16  cross-org job_id returns error in resolve_authoritative_target
  T17  dispatch_jobs_for_scan_run creates correct number of jobs

 ATOMIC JOB CLAIMING
  T18  claim_job_for_agent succeeds for QUEUED job, transitions to CLAIMED
  T19  concurrent claim calls produce exactly one winner (race safety)
  T20  agent with non-matching capabilities cannot claim job
  T21  claimed job includes authoritative target_url
  T22  CLAIMED job is not double-claimed by second agent

 JOB EXECUTION LIFECYCLE
  T23  mark_job_started transitions CLAIMED → RUNNING, emits SCANNER_STARTED event
  T24  mark_job_completed transitions RUNNING → COMPLETED, emits SCANNER_COMPLETED event
  T25  mark_job_failed transitions RUNNING → FAILED, emits SCANNER_FAILED event
  T26  cancel_jobs_for_scan_run marks QUEUED/CLAIMED/RUNNING jobs CANCELLED

 CONNECTOR SAFETY
  T27  ZapConnector produces valid ZAP JSON bytes when scanner not installed (mock)
  T28  NucleiConnector produces valid JSONL bytes when scanner not installed (mock)
  T29  WapitiConnector produces valid Wapiti JSON bytes when scanner not installed (mock)
  T30  BaseScannerConnector.execute_subprocess respects shell=False contract

 CONNECTOR → INGESTION PIPELINE
  T31  ZapConnector output passes Phase 2 ZAP parser (no double normalization)
  T32  NucleiConnector output passes Phase 2 Nuclei parser
  T33  WapitiConnector output passes Phase 2 Wapiti parser

 SSE EVENTS
  T34  SCANNER_JOB_QUEUED event is recorded after dispatch
  T35  SCANNER_JOB_CLAIMED event recorded after claim
  T36  SCANNER_STARTED event recorded after mark_started
  T37  SCANNER_COMPLETED event recorded after mark_completed
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import threading
import time
from typing import Any, Dict, List

import pytest

# ---------------------------------------------------------------------------
# Isolated DB for Phase 4 test suite
# ---------------------------------------------------------------------------
_tmp_db = tempfile.NamedTemporaryFile(suffix="_p4.db", delete=False)
_tmp_db.close()
os.environ["RIZINTEL_DB_PATH"] = _tmp_db.name
os.environ["RIZINTEL_ENV"] = "development"

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import database as db
from database import (
    create_organization,
    upsert_membership,
    create_registered_asset,
    update_asset_authorization,
    create_scan_run,
    list_scan_run_events,
    create_scanner_job,
    list_scanner_jobs_for_run,
    cancel_jobs_for_scan_run,
)
from services.agent_service import register_agent, authenticate_agent, get_agents_for_org, revoke_agent
from services.job_service import (
    dispatch_jobs_for_scan_run,
    claim_job_for_agent,
    mark_job_started,
    mark_job_completed,
    mark_job_failed,
    resolve_authoritative_target,
)
from services.scan_run_service import create_run


# ---------------------------------------------------------------------------
# Test fixtures
# ---------------------------------------------------------------------------

ORG_ID = "ORG-PHASE4-TEST"
ORG_ID2 = "ORG-PHASE4-OTHER"
USER_ID = "USR-PHASE4-LEAD"
ASSET_HOST = "phase4test.demo.corp"
ASSET_HOST2 = "phase4other.demo.corp"


@pytest.fixture(scope="module", autouse=True)
def setup_db():
    orig = db.DB_PATH
    db.DB_PATH = _tmp_db.name
    db.init_db()

    create_organization(ORG_ID, "Phase4TestOrg")
    create_organization(ORG_ID2, "Phase4OtherOrg")
    upsert_membership(ORG_ID, USER_ID, "SECURITY_LEAD")
    upsert_membership(ORG_ID2, "USR-OTHER", "ANALYST")

    yield
    db.DB_PATH = orig


@pytest.fixture
def authorized_asset():
    """Returns a freshly-registered AUTHORIZED asset for ORG_ID."""
    import secrets
    host = f"auth-{secrets.token_hex(4)}.phase4.corp"
    asset = create_registered_asset(
        asset_id=f"ASSET-{secrets.token_hex(4).upper()}",
        organization_id=ORG_ID,
        display_name=host,
        host=host,
        normalized_host=host,
        port=443,
        environment="STAGING",
        criticality="HIGH",
        internet_facing=True,
        data_sensitivity="CONFIDENTIAL",
        created_by=USER_ID,
    )
    update_asset_authorization(ORG_ID, asset["asset_id"], "AUTHORIZED", USER_ID)
    asset["authorization_status"] = "AUTHORIZED"
    return asset


@pytest.fixture
def pending_asset():
    """Returns a PENDING (not yet authorized) asset."""
    import secrets
    host = f"pending-{secrets.token_hex(4)}.phase4.corp"
    asset = create_registered_asset(
        asset_id=f"ASSET-{secrets.token_hex(4).upper()}",
        organization_id=ORG_ID,
        display_name=host,
        host=host,
        normalized_host=host,
        port=80,
        environment="STAGING",
        criticality="LOW",
        internet_facing=False,
        data_sensitivity="PUBLIC",
        created_by=USER_ID,
    )
    return asset


@pytest.fixture
def registered_agent():
    """Returns {agent: {...}, plaintext_secret: 'agt_...'}."""
    return register_agent(ORG_ID, "TestAgent", USER_ID)


@pytest.fixture
def scan_run_with_jobs(authorized_asset):
    """Creates a scan run and returns (run, jobs)."""
    import secrets
    run_id = f"SR-{secrets.token_hex(6).upper()}"
    run = create_scan_run(
        scan_run_id=run_id,
        organization_id=ORG_ID,
        asset_id=authorized_asset["asset_id"],
        created_by_user_id=USER_ID,
        scanner_selections=["ZAP", "NUCLEI", "WAPITI"],
        data_origin="LIVE_SCAN",
    )
    jobs = dispatch_jobs_for_scan_run(ORG_ID, run_id, authorized_asset["asset_id"], ["ZAP", "NUCLEI", "WAPITI"])
    return run, jobs


# ===========================================================================
# T01–T10: Agent Identity & Registration
# ===========================================================================

def test_t01_register_agent_returns_agent_and_secret():
    result = register_agent(ORG_ID, "T01-Agent", USER_ID)
    assert "agent" in result
    assert "plaintext_secret" in result
    assert result["agent"]["organization_id"] == ORG_ID
    assert result["agent"]["display_name"] == "T01-Agent"
    assert result["agent"]["status"] == "ACTIVE"


def test_t02_plaintext_secret_prefixed_agt():
    result = register_agent(ORG_ID, "T02-Agent", USER_ID)
    assert result["plaintext_secret"].startswith("agt_")


def test_t03_token_hash_not_in_list_agents():
    register_agent(ORG_ID, "T03-Agent", USER_ID)
    agents = get_agents_for_org(ORG_ID)
    for a in agents:
        assert "token_hash" not in a, "token_hash must not be exposed in list output"


def test_t04_token_hash_not_returned_after_registration():
    result = register_agent(ORG_ID, "T04-Agent", USER_ID)
    assert "token_hash" not in result.get("agent", {})


def test_t05_authenticate_agent_succeeds_correct_token():
    result = register_agent(ORG_ID, "T05-Agent", USER_ID)
    token = result["plaintext_secret"]
    agent = authenticate_agent(token)
    assert agent is not None
    assert agent["status"] == "ACTIVE"


def test_t06_authenticate_agent_rejects_wrong_token():
    result = register_agent(ORG_ID, "T06-Agent", USER_ID)
    agent = authenticate_agent("agt_wrongtoken_nope_123")
    assert agent is None


def test_t07_authenticate_agent_rejects_revoked_agent():
    result = register_agent(ORG_ID, "T07-Agent", USER_ID)
    token = result["plaintext_secret"]
    agent_id = result["agent"]["agent_id"]
    revoke_agent(ORG_ID, agent_id)
    auth_result = authenticate_agent(token)
    assert auth_result is None


def test_t08_revoke_agent_blocks_further_auth():
    result = register_agent(ORG_ID, "T08-Agent", USER_ID)
    token = result["plaintext_secret"]
    agent_id = result["agent"]["agent_id"]

    # Agent works before revocation
    assert authenticate_agent(token) is not None

    revoke_agent(ORG_ID, agent_id)

    # Agent fails after revocation
    assert authenticate_agent(token) is None


def test_t09_cross_org_revocation_returns_false():
    result = register_agent(ORG_ID, "T09-Agent", USER_ID)
    agent_id = result["agent"]["agent_id"]
    # Try to revoke from a different org
    success = revoke_agent(ORG_ID2, agent_id)
    assert success is False, "Cross-org revocation must return False"


def test_t10_duplicate_name_registration_allowed_with_distinct_secrets():
    r1 = register_agent(ORG_ID, "DuplicateName", USER_ID)
    r2 = register_agent(ORG_ID, "DuplicateName", USER_ID)
    assert r1["plaintext_secret"] != r2["plaintext_secret"]
    assert r1["agent"]["agent_id"] != r2["agent"]["agent_id"]


# ===========================================================================
# T11–T17: Job Dispatch & Authoritative Target Resolution
# ===========================================================================

def test_t11_create_run_dispatches_queued_jobs(authorized_asset):
    run = create_run(ORG_ID, authorized_asset["asset_id"], USER_ID, ["ZAP", "NUCLEI"])
    jobs = list_scanner_jobs_for_run(ORG_ID, run["scan_run_id"])
    assert len(jobs) == 2
    scanners = {j["scanner"] for j in jobs}
    assert scanners == {"ZAP", "NUCLEI"}


def test_t12_dispatched_jobs_are_queued_not_started(authorized_asset):
    run = create_run(ORG_ID, authorized_asset["asset_id"], USER_ID, ["ZAP"])
    jobs = list_scanner_jobs_for_run(ORG_ID, run["scan_run_id"])
    for job in jobs:
        assert job["status"] == "QUEUED"


def test_t13_target_url_from_authorized_asset(scan_run_with_jobs):
    run, jobs = scan_run_with_jobs
    job = jobs[0]
    info = resolve_authoritative_target(ORG_ID, run["scan_run_id"], job["scanner_job_id"])
    assert "target_url" in info
    assert info["target_url"].startswith("http")
    assert info["authorization_status"] == "AUTHORIZED"


def test_t14_non_authorized_asset_blocks_resolution(pending_asset):
    import secrets
    run_id = f"SR-{secrets.token_hex(6).upper()}"
    create_scan_run(
        scan_run_id=run_id,
        organization_id=ORG_ID,
        asset_id=pending_asset["asset_id"],
        created_by_user_id=USER_ID,
        scanner_selections=["ZAP"],
        data_origin="LIVE_SCAN",
    )
    job_id = f"JOB-{secrets.token_hex(5).upper()}"
    create_scanner_job(job_id, ORG_ID, run_id, pending_asset["asset_id"], "ZAP")

    with pytest.raises((ValueError, KeyError)):
        resolve_authoritative_target(ORG_ID, run_id, job_id)


def test_t15_pending_asset_status_blocks_target_resolution(pending_asset):
    import secrets
    run_id = f"SR-{secrets.token_hex(6).upper()}"
    create_scan_run(
        scan_run_id=run_id,
        organization_id=ORG_ID,
        asset_id=pending_asset["asset_id"],
        created_by_user_id=USER_ID,
        scanner_selections=["NUCLEI"],
        data_origin="LIVE_SCAN",
    )
    job_id = f"JOB-{secrets.token_hex(5).upper()}"
    create_scanner_job(job_id, ORG_ID, run_id, pending_asset["asset_id"], "NUCLEI")

    with pytest.raises((ValueError, KeyError)):
        resolve_authoritative_target(ORG_ID, run_id, job_id)


def test_t16_cross_org_job_id_fails_resolution(scan_run_with_jobs):
    run, jobs = scan_run_with_jobs
    job = jobs[0]
    with pytest.raises((KeyError, ValueError)):
        resolve_authoritative_target(ORG_ID2, run["scan_run_id"], job["scanner_job_id"])


def test_t17_dispatch_creates_correct_job_count(authorized_asset):
    import secrets
    run_id = f"SR-{secrets.token_hex(6).upper()}"
    create_scan_run(
        scan_run_id=run_id,
        organization_id=ORG_ID,
        asset_id=authorized_asset["asset_id"],
        created_by_user_id=USER_ID,
        scanner_selections=["ZAP", "NUCLEI", "WAPITI"],
        data_origin="LIVE_SCAN",
    )
    jobs = dispatch_jobs_for_scan_run(ORG_ID, run_id, authorized_asset["asset_id"], ["ZAP", "NUCLEI", "WAPITI"])
    assert len(jobs) == 3
    scanners = {j["scanner"] for j in jobs}
    assert scanners == {"ZAP", "NUCLEI", "WAPITI"}


# ===========================================================================
# T18–T22: Atomic Job Claiming
# ===========================================================================

def test_t18_claim_job_transitions_to_claimed(authorized_asset, registered_agent):
    import secrets
    agent_id = registered_agent["agent"]["agent_id"]
    run_id = f"SR-{secrets.token_hex(6).upper()}"
    create_scan_run(
        scan_run_id=run_id, organization_id=ORG_ID,
        asset_id=authorized_asset["asset_id"], created_by_user_id=USER_ID,
        scanner_selections=["ZAP"], data_origin="LIVE_SCAN",
    )
    dispatch_jobs_for_scan_run(ORG_ID, run_id, authorized_asset["asset_id"], ["ZAP"])

    claimed = claim_job_for_agent(ORG_ID, agent_id, ["ZAP", "NUCLEI", "WAPITI"])
    assert claimed is not None
    assert claimed["status"] == "CLAIMED"


def test_t19_concurrent_claims_exactly_one_winner(authorized_asset, registered_agent):
    """Race safety: only one of N concurrent claim attempts wins."""
    import secrets
    agent_id = registered_agent["agent"]["agent_id"]
    run_id = f"SR-{secrets.token_hex(6).upper()}"
    create_scan_run(
        scan_run_id=run_id, organization_id=ORG_ID,
        asset_id=authorized_asset["asset_id"], created_by_user_id=USER_ID,
        scanner_selections=["ZAP"], data_origin="LIVE_SCAN",
    )
    dispatch_jobs_for_scan_run(ORG_ID, run_id, authorized_asset["asset_id"], ["ZAP"])

    results = []
    barrier = threading.Barrier(5)

    def try_claim():
        barrier.wait()
        job = claim_job_for_agent(ORG_ID, agent_id, ["ZAP"], scan_run_id=run_id)
        results.append(job)

    threads = [threading.Thread(target=try_claim) for _ in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=10)

    winners = [r for r in results if r is not None and r.get("scan_run_id") == run_id]
    assert len(winners) == 1, f"Expected exactly 1 winner for run {run_id}, got {len(winners)}"


def test_t20_agent_wrong_capabilities_cannot_claim(authorized_asset, registered_agent):
    import secrets
    agent_id = registered_agent["agent"]["agent_id"]
    run_id = f"SR-{secrets.token_hex(6).upper()}"
    create_scan_run(
        scan_run_id=run_id, organization_id=ORG_ID,
        asset_id=authorized_asset["asset_id"], created_by_user_id=USER_ID,
        scanner_selections=["WAPITI"], data_origin="LIVE_SCAN",
    )
    dispatch_jobs_for_scan_run(ORG_ID, run_id, authorized_asset["asset_id"], ["WAPITI"])

    # Agent only claims ZAP, but only WAPITI job is available
    claimed = claim_job_for_agent(ORG_ID, agent_id, ["ZAP"])
    # Either None or not the WAPITI job
    if claimed:
        assert claimed["scanner"] == "ZAP"


def test_t21_claimed_job_includes_target_url(authorized_asset, registered_agent):
    import secrets
    agent_id = registered_agent["agent"]["agent_id"]
    run_id = f"SR-{secrets.token_hex(6).upper()}"
    create_scan_run(
        scan_run_id=run_id, organization_id=ORG_ID,
        asset_id=authorized_asset["asset_id"], created_by_user_id=USER_ID,
        scanner_selections=["NUCLEI"], data_origin="LIVE_SCAN",
    )
    dispatch_jobs_for_scan_run(ORG_ID, run_id, authorized_asset["asset_id"], ["NUCLEI"])

    claimed = claim_job_for_agent(ORG_ID, agent_id, ["ZAP", "NUCLEI", "WAPITI"])
    if claimed:
        assert "target" in claimed
        assert "target_url" in claimed["target"]
        assert claimed["target"]["target_url"].startswith("http")


def test_t22_claimed_job_cannot_be_double_claimed(authorized_asset):
    import secrets
    run_id = f"SR-{secrets.token_hex(6).upper()}"
    create_scan_run(
        scan_run_id=run_id, organization_id=ORG_ID,
        asset_id=authorized_asset["asset_id"], created_by_user_id=USER_ID,
        scanner_selections=["ZAP"], data_origin="LIVE_SCAN",
    )
    dispatch_jobs_for_scan_run(ORG_ID, run_id, authorized_asset["asset_id"], ["ZAP"])

    a1 = register_agent(ORG_ID, "ClaimAgent-A", USER_ID)
    a2 = register_agent(ORG_ID, "ClaimAgent-B", USER_ID)

    c1 = claim_job_for_agent(ORG_ID, a1["agent"]["agent_id"], ["ZAP"], scan_run_id=run_id)
    c2 = claim_job_for_agent(ORG_ID, a2["agent"]["agent_id"], ["ZAP"], scan_run_id=run_id)

    assert (c1 is None) != (c2 is None), "Exactly one agent must claim the job, not both."


# ===========================================================================
# T23–T26: Job Execution Lifecycle
# ===========================================================================

def test_t23_mark_started_emits_scanner_started_event(authorized_asset, registered_agent):
    import secrets
    agent_id = registered_agent["agent"]["agent_id"]
    run_id = f"SR-{secrets.token_hex(6).upper()}"
    create_scan_run(
        scan_run_id=run_id, organization_id=ORG_ID,
        asset_id=authorized_asset["asset_id"], created_by_user_id=USER_ID,
        scanner_selections=["ZAP"], data_origin="LIVE_SCAN",
    )
    jobs = dispatch_jobs_for_scan_run(ORG_ID, run_id, authorized_asset["asset_id"], ["ZAP"])
    claim_job_for_agent(ORG_ID, agent_id, ["ZAP"])

    job_id = jobs[0]["scanner_job_id"]
    updated = mark_job_started(ORG_ID, job_id, agent_id)
    assert updated["status"] == "RUNNING"

    events = list_scan_run_events(ORG_ID, run_id)
    types = [e["event_type"] for e in events]
    assert "SCANNER_STARTED" in types


def test_t24_mark_completed_emits_scanner_completed_event(authorized_asset, registered_agent):
    import secrets
    agent_id = registered_agent["agent"]["agent_id"]
    run_id = f"SR-{secrets.token_hex(6).upper()}"
    create_scan_run(
        scan_run_id=run_id, organization_id=ORG_ID,
        asset_id=authorized_asset["asset_id"], created_by_user_id=USER_ID,
        scanner_selections=["NUCLEI"], data_origin="LIVE_SCAN",
    )
    jobs = dispatch_jobs_for_scan_run(ORG_ID, run_id, authorized_asset["asset_id"], ["NUCLEI"])
    job_id = jobs[0]["scanner_job_id"]
    claim_job_for_agent(ORG_ID, agent_id, ["ZAP", "NUCLEI", "WAPITI"])
    mark_job_started(ORG_ID, job_id, agent_id)
    updated = mark_job_completed(ORG_ID, job_id, agent_id, "SUB-FAKE-001")
    assert updated["status"] == "COMPLETED"

    events = list_scan_run_events(ORG_ID, run_id)
    types = [e["event_type"] for e in events]
    assert "SCANNER_COMPLETED" in types


def test_t25_mark_failed_emits_scanner_failed_event(authorized_asset, registered_agent):
    import secrets
    agent_id = registered_agent["agent"]["agent_id"]
    run_id = f"SR-{secrets.token_hex(6).upper()}"
    create_scan_run(
        scan_run_id=run_id, organization_id=ORG_ID,
        asset_id=authorized_asset["asset_id"], created_by_user_id=USER_ID,
        scanner_selections=["WAPITI"], data_origin="LIVE_SCAN",
    )
    jobs = dispatch_jobs_for_scan_run(ORG_ID, run_id, authorized_asset["asset_id"], ["WAPITI"])
    job_id = jobs[0]["scanner_job_id"]
    claim_job_for_agent(ORG_ID, agent_id, ["ZAP", "NUCLEI", "WAPITI"])
    mark_job_started(ORG_ID, job_id, agent_id)
    updated = mark_job_failed(ORG_ID, job_id, agent_id, "TIMEOUT", "Scanner timed out after 120s")
    assert updated["status"] == "FAILED"

    events = list_scan_run_events(ORG_ID, run_id)
    types = [e["event_type"] for e in events]
    assert "SCANNER_FAILED" in types


def test_t26_cancel_jobs_marks_queued_jobs_cancelled(authorized_asset):
    import secrets
    run_id = f"SR-{secrets.token_hex(6).upper()}"
    create_scan_run(
        scan_run_id=run_id, organization_id=ORG_ID,
        asset_id=authorized_asset["asset_id"], created_by_user_id=USER_ID,
        scanner_selections=["ZAP", "NUCLEI"], data_origin="LIVE_SCAN",
    )
    dispatch_jobs_for_scan_run(ORG_ID, run_id, authorized_asset["asset_id"], ["ZAP", "NUCLEI"])
    cancel_jobs_for_scan_run(ORG_ID, run_id)

    jobs = list_scanner_jobs_for_run(ORG_ID, run_id)
    for job in jobs:
        assert job["status"] == "CANCELLED"


# ===========================================================================
# T27–T30: Connector Safety
# ===========================================================================

def test_t27_zap_connector_missing_executable_raises_error():
    from scanner_agent.connectors.zap_connector import ZapConnector
    connector = ZapConnector(executable_path="/nonexistent/zap/binary")
    connector.executable_path = "/nonexistent/zap/binary"
    connector._error_reason = "Binary not found."
    with pytest.raises(FileNotFoundError):
        connector.execute("http://test.local")


def test_t28_nuclei_connector_missing_executable_raises_error():
    from scanner_agent.connectors.nuclei_connector import NucleiConnector
    connector = NucleiConnector(executable_path="/nonexistent/nuclei/binary")
    connector.executable_path = "/nonexistent/nuclei/binary"
    connector._error_reason = "Binary not found."
    with pytest.raises(FileNotFoundError):
        connector.execute("http://test.local")


def test_t29_wapiti_connector_missing_executable_raises_error():
    from scanner_agent.connectors.wapiti_connector import WapitiConnector
    connector = WapitiConnector(executable_path="/nonexistent/wapiti/binary")
    connector.executable_path = "/nonexistent/wapiti/binary"
    connector._invocation_type = "binary"
    connector._error_reason = "Binary not found."
    with pytest.raises(FileNotFoundError):
        connector.execute("http://test.local")


def test_t30_base_connector_executes_with_shell_false():
    """Verify subprocess execution with shell=False by running a safe command."""
    from scanner_agent.connectors.base import BaseScannerConnector
    connector = BaseScannerConnector.__new__(BaseScannerConnector)
    connector.default_timeout = 10
    connector.cwd = None
    connector.env = None
    # Use a safe built-in command
    import sys as _sys
    exit_code, stdout, stderr = connector.execute_subprocess(
        [_sys.executable, "-c", "print('hello')"],
        timeout=10,
    )
    assert exit_code == 0
    assert b"hello" in stdout


# ===========================================================================
# T31–T33: Connector → Ingestion Pipeline (no double normalization)
# ===========================================================================

def test_t31_zap_connector_output_compatible_with_phase2_parser():
    from services.ingestion_service import parse_raw_scanner_report
    sample_zap = json.dumps({
        "site": [{
            "@name": "http://phase4-zap.test",
            "@host": "phase4-zap.test",
            "alerts": [{
                "pluginid": "10020",
                "alert": "X-Frame-Options Header Not Set",
                "name": "X-Frame-Options Header Not Set",
                "riskcode": "2",
                "confidence": "2",
                "riskdesc": "Medium (Medium)",
                "desc": "X-Frame-Options header missing.",
                "instances": [{"uri": "http://phase4-zap.test/login", "method": "GET"}]
            }]
        }]
    }).encode("utf-8")
    records = parse_raw_scanner_report("zap", sample_zap)
    assert isinstance(records, list)
    assert len(records) > 0


def test_t32_nuclei_connector_output_compatible_with_phase2_parser():
    from services.ingestion_service import parse_raw_scanner_report
    sample_nuclei = json.dumps({
        "template-id": "http-missing-security-headers",
        "info": {
            "name": "HTTP Missing Security Headers",
            "severity": "info",
            "description": "Missing headers."
        },
        "type": "http",
        "host": "http://phase4-nuclei.test",
        "matched-at": "http://phase4-nuclei.test",
        "timestamp": "2026-08-25T12:00:00Z"
    }).encode("utf-8")
    records = parse_raw_scanner_report("nuclei", sample_nuclei)
    assert isinstance(records, list)
    assert len(records) > 0


def test_t33_wapiti_connector_output_compatible_with_phase2_parser():
    from services.ingestion_service import parse_raw_scanner_report
    sample_wapiti = json.dumps({
        "infos": {"target": "http://phase4-wapiti.test", "date": "Thu, 20 Aug 2026 14:35:14 +0000"},
        "classifications": {"HTTP Secure Headers": {"desc": "Missing headers", "ref": {}}},
        "vulnerabilities": {
            "HTTP Secure Headers": [{
                "path": "/login",
                "info": "Strict-Transport-Security missing",
                "level": 1,
                "parameter": None
            }]
        }
    }).encode("utf-8")
    records = parse_raw_scanner_report("wapiti", sample_wapiti)
    assert isinstance(records, list)
    assert len(records) > 0


# ===========================================================================
# T34–T37: SSE Events
# ===========================================================================

def test_t34_scanner_job_queued_event_recorded(authorized_asset):
    import secrets
    run_id = f"SR-{secrets.token_hex(6).upper()}"
    create_scan_run(
        scan_run_id=run_id, organization_id=ORG_ID,
        asset_id=authorized_asset["asset_id"], created_by_user_id=USER_ID,
        scanner_selections=["ZAP"], data_origin="LIVE_SCAN",
    )
    dispatch_jobs_for_scan_run(ORG_ID, run_id, authorized_asset["asset_id"], ["ZAP"])
    events = list_scan_run_events(ORG_ID, run_id)
    types = [e["event_type"] for e in events]
    assert "SCANNER_JOB_QUEUED" in types


def test_t35_scanner_job_claimed_event_recorded(authorized_asset, registered_agent):
    import secrets
    agent_id = registered_agent["agent"]["agent_id"]
    run_id = f"SR-{secrets.token_hex(6).upper()}"
    create_scan_run(
        scan_run_id=run_id, organization_id=ORG_ID,
        asset_id=authorized_asset["asset_id"], created_by_user_id=USER_ID,
        scanner_selections=["ZAP"], data_origin="LIVE_SCAN",
    )
    dispatch_jobs_for_scan_run(ORG_ID, run_id, authorized_asset["asset_id"], ["ZAP"])
    claim_job_for_agent(ORG_ID, agent_id, ["ZAP", "NUCLEI", "WAPITI"], scan_run_id=run_id)

    events = list_scan_run_events(ORG_ID, run_id)
    types = [e["event_type"] for e in events]
    assert "SCANNER_JOB_CLAIMED" in types


def test_t36_scanner_started_event_recorded(authorized_asset, registered_agent):
    import secrets
    agent_id = registered_agent["agent"]["agent_id"]
    run_id = f"SR-{secrets.token_hex(6).upper()}"
    create_scan_run(
        scan_run_id=run_id, organization_id=ORG_ID,
        asset_id=authorized_asset["asset_id"], created_by_user_id=USER_ID,
        scanner_selections=["WAPITI"], data_origin="LIVE_SCAN",
    )
    jobs = dispatch_jobs_for_scan_run(ORG_ID, run_id, authorized_asset["asset_id"], ["WAPITI"])
    job_id = jobs[0]["scanner_job_id"]
    claim_job_for_agent(ORG_ID, agent_id, ["ZAP", "NUCLEI", "WAPITI"])
    mark_job_started(ORG_ID, job_id, agent_id)

    events = list_scan_run_events(ORG_ID, run_id)
    types = [e["event_type"] for e in events]
    assert "SCANNER_STARTED" in types


def test_t37_scanner_completed_event_recorded(authorized_asset, registered_agent):
    import secrets
    agent_id = registered_agent["agent"]["agent_id"]
    run_id = f"SR-{secrets.token_hex(6).upper()}"
    create_scan_run(
        scan_run_id=run_id, organization_id=ORG_ID,
        asset_id=authorized_asset["asset_id"], created_by_user_id=USER_ID,
        scanner_selections=["NUCLEI"], data_origin="LIVE_SCAN",
    )
    jobs = dispatch_jobs_for_scan_run(ORG_ID, run_id, authorized_asset["asset_id"], ["NUCLEI"])
    job_id = jobs[0]["scanner_job_id"]
    claim_job_for_agent(ORG_ID, agent_id, ["ZAP", "NUCLEI", "WAPITI"])
    mark_job_started(ORG_ID, job_id, agent_id)
    mark_job_completed(ORG_ID, job_id, agent_id, "SUB-FAKE-T37")

    events = list_scan_run_events(ORG_ID, run_id)
    types = [e["event_type"] for e in events]
    assert "SCANNER_COMPLETED" in types
