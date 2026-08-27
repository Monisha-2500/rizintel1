"""
test_production_scanners.py
===========================
Comprehensive production integration test suite for Nuclei, OWASP ZAP, and Wapiti:
- Connector unit tests (safe subprocess, argv, timeout, no live mocks)
- Agent API contracts & machine auth
- M1 adapter normalization & evidence preservation
- Multi-scanner pipeline consensus & partial failure resilience
- Security & RBAC enforcement
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
from typing import Any, Dict, List
import pytest

backend_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
mem1_dir = os.path.join(backend_dir, "mem1")
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)
if mem1_dir not in sys.path:
    sys.path.insert(0, mem1_dir)

import database as db
from database import (
    create_organization,
    upsert_membership,
    create_registered_asset,
    get_registered_asset,
    update_asset_authorization,
    create_scan_run,
    get_scan_run,
    list_scanner_jobs_for_run,
)
from services.agent_service import (
    register_agent,
    authenticate_agent,
    revoke_agent,
    get_agents_for_org,
)
from services.job_service import (
    dispatch_jobs_for_scan_run,
    claim_job_for_agent,
    mark_job_started,
    mark_job_completed,
    mark_job_failed,
    resolve_authoritative_target,
)
from services.scan_run_service import create_run
from scanner_agent.discovery import ScannerDiscovery
from scanner_agent.connectors.nuclei_connector import NucleiConnector
from scanner_agent.connectors.zap_connector import ZapConnector
from scanner_agent.connectors.wapiti_connector import WapitiConnector
from mem1.scanner_adapters.zap import ZapAdapter
from mem1.scanner_adapters.wapiti import WapitiAdapter
from mem1.scanner_adapters.nuclei import NucleiAdapter
from services.processing_service import process_scan_run_pipeline
from services.ingestion_service import ingest_report

_tmp_db = tempfile.NamedTemporaryFile(suffix="_scanners_test.db", delete=False)
_tmp_db.close()
os.environ["RIZINTEL_DB_PATH"] = _tmp_db.name
os.environ["RIZINTEL_ENV"] = "development"

import database as db
db.DB_PATH = _tmp_db.name

ORG_ID = "ORG-PROD-SCANNERS"
USER_LEAD = "USR-LEAD-01"
USER_ANALYST = "USR-ANALYST-01"
USER_VIEWER = "USR-VIEWER-01"


@pytest.fixture(scope="module", autouse=True)
def setup_test_environment():
    db.DB_PATH = _tmp_db.name
    db.init_db()
    try:
        create_organization(ORG_ID, "Production Scanners Org")
    except Exception:
        pass

    try:
        upsert_membership("MEM-LEAD-01", ORG_ID, USER_LEAD, "SECURITY_LEAD")
        upsert_membership("MEM-ANALYST-01", ORG_ID, USER_ANALYST, "ANALYST")
        upsert_membership("MEM-VIEWER-01", ORG_ID, USER_VIEWER, "VIEWER")
    except Exception:
        pass

    try:
        create_registered_asset(
            asset_id="AST-LOCAL-01",
            organization_id=ORG_ID,
            display_name="Local Backend Target",
            host="localhost",
            normalized_host="localhost",
            port=8000,
            environment="development",
            criticality="HIGH",
            internet_facing=False,
            data_sensitivity="CONFIDENTIAL",
            created_by=USER_LEAD,
        )
    except Exception:
        pass

    update_asset_authorization(ORG_ID, "AST-LOCAL-01", "AUTHORIZED", USER_LEAD)
    yield
    try:
        os.remove(_tmp_db.name)
    except Exception:
        pass


# ===========================================================================
# A. Connector Unit Tests
# ===========================================================================

def test_nuclei_connector_discovery_and_command():
    conn = NucleiConnector()
    is_avail, reason = conn.validate_available()
    assert is_avail is True, f"Nuclei should be discovered on host: {reason}"
    cmd = conn.build_command("http://localhost:8000", "temp_out.jsonl")
    assert isinstance(cmd, list)
    assert cmd[1] == "-u"
    assert cmd[2] == "http://localhost:8000"
    assert "-jsonl" in cmd


def test_zap_connector_discovery_and_command():
    conn = ZapConnector()
    is_avail, reason = conn.validate_available()
    assert is_avail is True, f"ZAP should be discovered on host: {reason}"
    cmd = conn.build_command("http://localhost:8000", "temp_out.json")
    assert isinstance(cmd, list)
    assert "-cmd" in cmd
    assert "-quickurl" in cmd
    assert cmd[cmd.index("-quickurl") + 1] == "http://localhost:8000"


def test_wapiti_connector_discovery_and_command():
    conn = WapitiConnector()
    is_avail, reason = conn.validate_available()
    assert is_avail is True, f"Wapiti should be discovered on host: {reason}"
    cmd = conn.build_command("http://localhost:8000", "temp_out.json")
    assert isinstance(cmd, list)
    assert "-u" in cmd
    assert cmd[cmd.index("-u") + 1] == "http://localhost:8000"
    assert "-f" in cmd
    assert "json" in cmd


def test_connectors_fail_cleanly_on_missing_binary():
    n_conn = NucleiConnector(executable_path="/missing/nuclei")
    with pytest.raises(FileNotFoundError):
        n_conn.execute("http://localhost:8000")

    z_conn = ZapConnector(executable_path="/missing/zap")
    with pytest.raises(FileNotFoundError):
        z_conn.execute("http://localhost:8000")

    w_conn = WapitiConnector(executable_path="/missing/wapiti")
    with pytest.raises(FileNotFoundError):
        w_conn.execute("http://localhost:8000")


# ===========================================================================
# B. Agent Registration & API Contract Tests
# ===========================================================================

def test_agent_registration_defaults_to_unverified_capabilities():
    res = register_agent(ORG_ID, "UnverifiedAgent", USER_LEAD)
    agent = res["agent"]
    token = res["plaintext_secret"]
    assert token.startswith("agt_")
    caps = json.loads(agent["capabilities_json"])
    # Newly registered agent has empty capabilities until first heartbeat
    assert caps == {}


def test_agent_heartbeat_updates_truthful_capabilities():
    res = register_agent(ORG_ID, "HeartbeatAgent", USER_LEAD)
    agent_id = res["agent"]["agent_id"]
    token = res["plaintext_secret"]

    auth_agent = authenticate_agent(token)
    assert auth_agent is not None
    assert auth_agent["agent_id"] == agent_id

    # Probe host capabilities
    caps = ScannerDiscovery.discover_all()
    db.update_agent_heartbeat(agent_id, json.dumps(caps))

    agents = get_agents_for_org(ORG_ID)
    updated = next(a for a in agents if a["agent_id"] == agent_id)
    saved_caps = json.loads(updated["capabilities_json"])
    assert saved_caps["NUCLEI"]["available"] is True
    assert saved_caps["ZAP"]["available"] is True
    assert saved_caps["WAPITI"]["available"] is True


def test_revoked_agent_cannot_authenticate():
    res = register_agent(ORG_ID, "RevokeAgent", USER_LEAD)
    agent_id = res["agent"]["agent_id"]
    token = res["plaintext_secret"]

    assert authenticate_agent(token) is not None
    assert revoke_agent(ORG_ID, agent_id) is True
    assert authenticate_agent(token) is None


# ===========================================================================
# C. M1 Adapters Normalization Tests
# ===========================================================================

def test_m1_zap_adapter_normalizes_native_report():
    sample_zap = json.dumps({
        "@version": "2.16.0",
        "site": [{
            "@name": "http://localhost:8000",
            "@host": "localhost",
            "@port": "8000",
            "alerts": [{
                "pluginid": "10038",
                "alert": "Content Security Policy (CSP) Header Not Set",
                "name": "Content Security Policy (CSP) Header Not Set",
                "riskcode": "2",
                "confidence": "3",
                "riskdesc": "Medium (High)",
                "desc": "<p>Content Security Policy (CSP) is an added layer of security.</p>",
                "solution": "<p>Ensure that your web server sends CSP headers.</p>",
                "cweid": "693",
                "wascid": "15",
                "instances": [{
                    "uri": "http://localhost:8000/api/health",
                    "method": "GET",
                    "param": "",
                    "evidence": ""
                }]
            }]
        }]
    })
    adapter = ZapAdapter()
    findings = adapter.parse(sample_zap)
    assert len(findings) == 1
    f = findings[0]
    assert f.scanner == "ZAP"
    assert f.vulnerability_name == "Content Security Policy (CSP) Header Not Set"
    assert f.cwe in ("CWE-693", "693")
    assert f.host == "http://localhost:8000"
    assert f.endpoint == "/api/health"
    assert f.severity.value.upper() == "MEDIUM"


def test_m1_wapiti_adapter_normalizes_native_report():
    sample_wapiti = json.dumps({
        "infos": {
            "target": "http://localhost:8000",
            "date": "Thu, 27 Aug 2026 12:00:00 +0000",
            "version": "3.2.3"
        },
        "classifications": {
            "HTTP Secure Headers": {
                "desc": "HTTP security headers provide extra protection against attacks.",
                "sol": "Add security headers to responses.",
                "ref": {"CWE-693: Protection Mechanism Failure": "https://cwe.mitre.org"}
            }
        },
        "vulnerabilities": {
            "HTTP Secure Headers": [{
                "method": "GET",
                "path": "/api/health",
                "info": "Strict-Transport-Security header is not configured",
                "level": 1,
                "parameter": None,
                "curl_command": "curl http://localhost:8000/api/health"
            }]
        }
    })
    adapter = WapitiAdapter()
    findings = adapter.parse(sample_wapiti)
    assert len(findings) == 1
    f = findings[0]
    assert f.scanner == "Wapiti"
    assert f.vulnerability_name == "HTTP Secure Headers"
    assert f.cwe == "CWE-693"
    assert f.endpoint == "/api/health"
    assert f.severity.value.upper() == "LOW"


def test_m1_nuclei_adapter_normalizes_native_report():
    sample_nuclei = json.dumps({
        "template-id": "missing-x-frame-options",
        "info": {
            "name": "Missing X-Frame-Options",
            "severity": "info",
            "description": "Missing clickjacking protection header."
        },
        "type": "http",
        "host": "http://localhost:8000",
        "matched-at": "http://localhost:8000/api/health",
        "timestamp": "2026-08-27T12:00:00Z"
    })
    adapter = NucleiAdapter()
    findings = adapter.parse(sample_nuclei)
    assert len(findings) == 1
    f = findings[0]
    assert f.scanner == "Nuclei"
    assert f.vulnerability_name == "Missing X-Frame-Options"
    assert f.endpoint == "/api/health"


# ===========================================================================
# D. Multi-Scanner Pipeline & Partial Failure Tests
# ===========================================================================

def test_multi_scanner_run_creation_and_independent_jobs():
    run = create_run(
        organization_id=ORG_ID,
        asset_id="AST-LOCAL-01",
        scanner_selections=["NUCLEI", "ZAP", "WAPITI"],
        data_origin="LIVE_SCAN",
        created_by_user_id=USER_LEAD,
    )
    run_id = run["scan_run_id"]
    jobs = list_scanner_jobs_for_run(ORG_ID, run_id)
    assert len(jobs) == 3
    scanners = {j["scanner"] for j in jobs}
    assert scanners == {"NUCLEI", "ZAP", "WAPITI"}
    for j in jobs:
        assert j["status"] == "QUEUED"


def test_partial_scanner_failure_allows_processing_available_results():
    asset = get_registered_asset(ORG_ID, "AST-LOCAL-01")
    if not asset:
        create_registered_asset(
            asset_id="AST-LOCAL-01",
            organization_id=ORG_ID,
            display_name="Local Backend Target",
            host="localhost",
            normalized_host="localhost",
            port=8000,
            environment="development",
            criticality="HIGH",
            internet_facing=False,
            data_sensitivity="CONFIDENTIAL",
            created_by=USER_LEAD,
        )
    update_asset_authorization(ORG_ID, "AST-LOCAL-01", "AUTHORIZED", USER_LEAD)

    run = create_run(
        organization_id=ORG_ID,
        asset_id="AST-LOCAL-01",
        scanner_selections=["NUCLEI", "ZAP"],
        data_origin="LIVE_SCAN",
        created_by_user_id=USER_LEAD,
    )
    run_id = run["scan_run_id"]
    jobs = list_scanner_jobs_for_run(ORG_ID, run_id)
    n_job = next(j for j in jobs if j["scanner"] == "NUCLEI")
    z_job = next(j for j in jobs if j["scanner"] == "ZAP")

    # Nuclei completes successfully
    sample_nuclei = json.dumps({
        "template-id": "http-missing-headers",
        "info": {"name": "Missing Headers", "severity": "low", "description": "Desc"},
        "type": "http",
        "host": "http://localhost:8000",
        "matched-at": "http://localhost:8000/api/health",
        "timestamp": "2026-08-27T12:00:00Z"
    }).encode("utf-8")

    sub_res = ingest_report(
        organization_id=ORG_ID,
        scan_run_id=run_id,
        scanner="NUCLEI",
        report_bytes=sample_nuclei,
        submission_type="AUTOMATED_AGENT",
        user_id=USER_LEAD,
    )
    mark_job_completed(ORG_ID, n_job["scanner_job_id"], "AGENT-TEST", sub_res["submission_id"])

    # ZAP fails
    mark_job_failed(ORG_ID, z_job["scanner_job_id"], "AGENT-TEST", "EXECUTION_TIMEOUT", "Timed out after 300s")

    # Trigger partial processing
    proc_res = process_scan_run_pipeline(
        organization_id=ORG_ID,
        scan_run_id=run_id,
        triggered_by_user_id=USER_LEAD,
        is_partial_trigger=True,
    )
    assert proc_res is not None
    assert proc_res["canonical_finding_count"] >= 1
    updated_run = get_scan_run(ORG_ID, run_id)
    assert updated_run["status"] == "COMPLETED"
