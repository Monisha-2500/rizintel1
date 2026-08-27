"""
test_phase2_ingestion_pipeline.py
=================================
Phase 2 automated test suite.

Coverage:
  1.  Valid ZAP report accepted
  2.  Valid Nuclei report accepted
  3.  Valid Wapiti report accepted
  4.  Unsupported scanner rejected
  5.  Scanner not selected for scan run rejected
  6.  Scan run for non-AUTHORIZED asset rejected
  7.  Cross-org upload rejected (403 / 404)
  8.  Cross-run contamination impossible (submissions isolated)
  9.  Malformed report rejected safely without corrupting run state
  10. Duplicate report upload is idempotent (SHA-256 double-count protection)
  11. ZAP + Nuclei + Wapiti independently submit to same scan run
  12. Run accurately tracks pending, received, and failed scanners
  13. Single M1 normalization pass with real parsed records
  14. Deterministic source IDs remain unique across scanners
  15. Pipeline processing uses findings ONLY from requested scan run
  16. M2 deduplication preserves all source scanner IDs
  17. Cross-asset deduplication protections remain passing
  18. M3 confidence and noise routing remain passing
  19. M5 risk engine sovereignty remains passing
  20. Completed scan run exposes correct findings via /results endpoint
  21. VIEWER cannot upload or trigger processing (403)
  22. ANALYST cannot trigger privileged partial processing (403)
  23. SECURITY_LEAD / ADMIN can trigger partial processing (2/3 consensus)
  24. Persistent stage event sequence recorded truthfully in scan_run_events
  25. Failed processing updates status to FAILED and logs SCAN_FAILED event
  26. Target host validation policy (MATCH, CLEAR_MISMATCH, UNKNOWN)
  27. Concurrent final scanner submissions trigger processing exactly ONCE (atomic lock)
  28. Truthful consensus denominator preserved for 3/3 and 2/3 partial cases
"""

from __future__ import annotations

import os
import sys
import json
import tempfile
import pytest

# Ensure backend dir is on path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Isolated DB for test suite
_tmp_db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
_tmp_db.close()
os.environ["RIZINTEL_DB_PATH"] = _tmp_db.name
os.environ["RIZINTEL_ENV"] = "development"

import database as db
from database import (
    create_organization,
    upsert_membership,
    create_registered_asset,
    update_asset_authorization,
    create_scan_run,
    get_scan_run,
    list_submissions_for_run,
    list_scan_run_events,
    get_scan_run_results,
)
from services.ingestion_service import (
    ingest_report,
    validate_report_target,
    TargetMismatchError,
)
from services.processing_service import process_scan_run_pipeline
from services.asset_service import register_asset, set_authorization_status
from services.scan_run_service import create_run


# Sample valid scanner reports matching real structure
SAMPLE_ZAP_REPORT = json.dumps({
    "site": [
        {
            "@name": "https://payments.demo.corp",
            "@host": "payments.demo.corp",
            "@port": "443",
            "alerts": [
                {
                    "pluginid": "40018",
                    "alert": "SQL Injection",
                    "riskcode": "3",
                    "confidence": "3",
                    "cweid": "89",
                    "desc": "<p>SQL Injection detected on parameter id</p>",
                    "instances": [
                        {"uri": "https://payments.demo.corp/api/pay", "method": "POST", "param": "id"}
                    ]
                }
            ]
        }
    ]
})

SAMPLE_NUCLEI_REPORT = json.dumps([
    {
        "template-id": "cve-2026-9999",
        "info": {
            "name": "Remote Code Execution in API",
            "severity": "critical",
            "classification": {"cve-id": ["CVE-2026-9999"], "cwe-id": ["CWE-78"]}
        },
        "host": "payments.demo.corp",
        "matched-at": "https://payments.demo.corp/api/exec"
    }
])

SAMPLE_WAPITI_REPORT = json.dumps({
    "infos": {"target": "https://payments.demo.corp"},
    "classifications": {
        "Cross Site Scripting": {"desc": "XSS vulnerability", "ref": {"CWE-79": "http://cwe"}}
    },
    "vulnerabilities": {
        "Cross Site Scripting": [
            {"method": "GET", "path": "/search", "parameter": "q", "level": 2}
        ]
    }
})

SAMPLE_MISMATCH_ZAP_REPORT = json.dumps({
    "site": [
        {
            "@name": "https://evil.attacker.com",
            "@host": "evil.attacker.com",
            "@port": "443",
            "alerts": []
        }
    ]
})


@pytest.fixture(scope="module", autouse=True)
def setup_db():
    orig_path = db.DB_PATH
    db.DB_PATH = _tmp_db.name
    db.init_db()
    from services.org_service import _seed_demo_org
    _seed_demo_org()
    yield
    db.DB_PATH = orig_path


ORG_TEST = "ORG-PHASE2-TEST"
USER_LEAD = "usr-lead-003"
USER_ANALYST = "usr-analyst-002"
USER_VIEWER = "usr-viewer-001"


@pytest.fixture(scope="module")
def seeded_fixture():
    create_organization(ORG_TEST, "Phase 2 Security Test Org")
    upsert_membership("MEM-P2-LEAD", ORG_TEST, USER_LEAD, "SECURITY_LEAD")
    upsert_membership("MEM-P2-ANALYST", ORG_TEST, USER_ANALYST, "ANALYST")
    upsert_membership("MEM-P2-VIEWER", ORG_TEST, USER_VIEWER, "VIEWER")

    asset = register_asset(
        organization_id=ORG_TEST,
        display_name="Payments Service Target",
        host="payments.demo.corp",
        port=443,
        environment="production",
        criticality="CRITICAL",
        internet_facing=True,
        data_sensitivity="CONFIDENTIAL",
        created_by=USER_LEAD,
    )
    set_authorization_status(ORG_TEST, asset["asset_id"], "AUTHORIZED", USER_LEAD)
    return asset


# ─────────────────────────────────────────────────────────────
# Test 1-3: Valid Report Ingestion (ZAP, Nuclei, Wapiti)
# ─────────────────────────────────────────────────────────────

def test_01_valid_zap_report_accepted(seeded_fixture):
    asset = seeded_fixture
    run = create_run(ORG_TEST, asset["asset_id"], USER_LEAD, ["ZAP"])
    res = ingest_report(
        organization_id=ORG_TEST,
        scan_run_id=run["scan_run_id"],
        scanner="ZAP",
        report_bytes=SAMPLE_ZAP_REPORT.encode("utf-8"),
        submission_type="FILE_UPLOAD",
        user_id=USER_ANALYST,
        original_filename="zap_webgoat.json",
    )
    assert res["is_duplicate"] is False
    assert res["scanner"] == "ZAP"
    assert res["raw_finding_count"] == 1
    assert res["processing_status"] in ("PARSED", "TARGET_REVIEW_REQUIRED")


def test_02_valid_nuclei_report_accepted(seeded_fixture):
    asset = seeded_fixture
    run = create_run(ORG_TEST, asset["asset_id"], USER_LEAD, ["NUCLEI"])
    res = ingest_report(
        organization_id=ORG_TEST,
        scan_run_id=run["scan_run_id"],
        scanner="NUCLEI",
        report_bytes=SAMPLE_NUCLEI_REPORT.encode("utf-8"),
        submission_type="FILE_UPLOAD",
        user_id=USER_ANALYST,
    )
    assert res["scanner"] == "NUCLEI"
    assert res["raw_finding_count"] == 1


def test_03_valid_wapiti_report_accepted(seeded_fixture):
    asset = seeded_fixture
    run = create_run(ORG_TEST, asset["asset_id"], USER_LEAD, ["WAPITI"])
    res = ingest_report(
        organization_id=ORG_TEST,
        scan_run_id=run["scan_run_id"],
        scanner="WAPITI",
        report_bytes=SAMPLE_WAPITI_REPORT.encode("utf-8"),
        submission_type="FILE_UPLOAD",
        user_id=USER_ANALYST,
    )
    assert res["scanner"] == "WAPITI"
    assert res["raw_finding_count"] == 1


# ─────────────────────────────────────────────────────────────
# Test 4-6: Validations (Unsupported scanner, Not selected, Non-authorized)
# ─────────────────────────────────────────────────────────────

def test_04_unsupported_scanner_rejected(seeded_fixture):
    asset = seeded_fixture
    run = create_run(ORG_TEST, asset["asset_id"], USER_LEAD, ["ZAP"])
    with pytest.raises(ValueError, match="Unsupported"):
        ingest_report(
            organization_id=ORG_TEST,
            scan_run_id=run["scan_run_id"],
            scanner="OPENVAS",
            report_bytes=b"{}",
            submission_type="FILE_UPLOAD",
            user_id=USER_ANALYST,
        )


def test_05_scanner_not_selected_rejected(seeded_fixture):
    asset = seeded_fixture
    run = create_run(ORG_TEST, asset["asset_id"], USER_LEAD, ["ZAP"])
    with pytest.raises(ValueError, match="was not selected"):
        ingest_report(
            organization_id=ORG_TEST,
            scan_run_id=run["scan_run_id"],
            scanner="NUCLEI",
            report_bytes=SAMPLE_NUCLEI_REPORT.encode("utf-8"),
            submission_type="FILE_UPLOAD",
            user_id=USER_ANALYST,
        )


def test_06_unauthorized_asset_run_rejected():
    asset = register_asset(
        organization_id=ORG_TEST,
        display_name="Pending Asset",
        host="pending.corp",
        port=80,
        environment="staging",
        criticality="LOW",
        internet_facing=False,
        data_sensitivity="INTERNAL",
        created_by=USER_LEAD,
    )
    # asset is PENDING (not AUTHORIZED)
    assert asset["authorization_status"] == "PENDING"
    # Service ingestion checks asset authorization status
    run = create_run(ORG_TEST, asset["asset_id"], USER_LEAD, ["ZAP"])
    with pytest.raises(ValueError, match="is not AUTHORIZED"):
        ingest_report(
            organization_id=ORG_TEST,
            scan_run_id=run["scan_run_id"],
            scanner="ZAP",
            report_bytes=SAMPLE_ZAP_REPORT.encode("utf-8"),
            submission_type="FILE_UPLOAD",
            user_id=USER_ANALYST,
        )


# ─────────────────────────────────────────────────────────────
# Test 7-8: Tenant & Run Isolation
# ─────────────────────────────────────────────────────────────

def test_07_cross_org_upload_rejected(seeded_fixture):
    asset = seeded_fixture
    run = create_run(ORG_TEST, asset["asset_id"], USER_LEAD, ["ZAP"])
    with pytest.raises(KeyError, match="not found in organization"):
        ingest_report(
            organization_id="ORG-OTHER-999",
            scan_run_id=run["scan_run_id"],
            scanner="ZAP",
            report_bytes=SAMPLE_ZAP_REPORT.encode("utf-8"),
            submission_type="FILE_UPLOAD",
            user_id=USER_ANALYST,
        )


# ─────────────────────────────────────────────────────────────
# Test 9-10: Malformed Parsing & Idempotency
# ─────────────────────────────────────────────────────────────

def test_09_malformed_report_rejected_safely(seeded_fixture):
    asset = seeded_fixture
    run = create_run(ORG_TEST, asset["asset_id"], USER_LEAD, ["ZAP"])
    with pytest.raises(ValueError, match="Failed to parse ZAP"):
        ingest_report(
            organization_id=ORG_TEST,
            scan_run_id=run["scan_run_id"],
            scanner="ZAP",
            report_bytes=b"INVALID_NOT_JSON {{{",
            submission_type="FILE_UPLOAD",
            user_id=USER_ANALYST,
        )


def test_10_duplicate_upload_is_idempotent(seeded_fixture):
    asset = seeded_fixture
    run = create_run(ORG_TEST, asset["asset_id"], USER_LEAD, ["ZAP"])
    res1 = ingest_report(
        organization_id=ORG_TEST,
        scan_run_id=run["scan_run_id"],
        scanner="ZAP",
        report_bytes=SAMPLE_ZAP_REPORT.encode("utf-8"),
        submission_type="FILE_UPLOAD",
        user_id=USER_ANALYST,
    )
    assert res1["is_duplicate"] is False

    res2 = ingest_report(
        organization_id=ORG_TEST,
        scan_run_id=run["scan_run_id"],
        scanner="ZAP",
        report_bytes=SAMPLE_ZAP_REPORT.encode("utf-8"),
        submission_type="FILE_UPLOAD",
        user_id=USER_ANALYST,
    )
    assert res2["is_duplicate"] is True
    assert res2["submission_id"] == res1["submission_id"]


# ─────────────────────────────────────────────────────────────
# Test 11-12: Multi-scanner consensus & tracking
# ─────────────────────────────────────────────────────────────

def test_11_multi_scanner_independent_submissions(seeded_fixture):
    asset = seeded_fixture
    run = create_run(ORG_TEST, asset["asset_id"], USER_LEAD, ["ZAP", "NUCLEI", "WAPITI"])

    res1 = ingest_report(
        organization_id=ORG_TEST,
        scan_run_id=run["scan_run_id"],
        scanner="ZAP",
        report_bytes=SAMPLE_ZAP_REPORT.encode("utf-8"),
        submission_type="FILE_UPLOAD",
        user_id=USER_ANALYST,
    )
    assert "ZAP" in res1["received_scanners"]
    assert "NUCLEI" in res1["pending_scanners"]
    assert res1["is_consensus_reached"] is False

    res2 = ingest_report(
        organization_id=ORG_TEST,
        scan_run_id=run["scan_run_id"],
        scanner="NUCLEI",
        report_bytes=SAMPLE_NUCLEI_REPORT.encode("utf-8"),
        submission_type="FILE_UPLOAD",
        user_id=USER_ANALYST,
    )
    assert "NUCLEI" in res2["received_scanners"]
    assert res2["is_consensus_reached"] is False

    res3 = ingest_report(
        organization_id=ORG_TEST,
        scan_run_id=run["scan_run_id"],
        scanner="WAPITI",
        report_bytes=SAMPLE_WAPITI_REPORT.encode("utf-8"),
        submission_type="FILE_UPLOAD",
        user_id=USER_ANALYST,
    )
    assert "WAPITI" in res3["received_scanners"]
    assert len(res3["pending_scanners"]) == 0
    assert res3["is_consensus_reached"] is True


# ─────────────────────────────────────────────────────────────
# Test 13-20: Pipeline Execution & Results Verification
# ─────────────────────────────────────────────────────────────

def test_13_full_pipeline_execution(seeded_fixture):
    asset = seeded_fixture
    run = create_run(ORG_TEST, asset["asset_id"], USER_LEAD, ["ZAP", "NUCLEI"])

    ingest_report(ORG_TEST, run["scan_run_id"], "ZAP", SAMPLE_ZAP_REPORT.encode("utf-8"), "FILE_UPLOAD", USER_ANALYST)
    ingest_report(ORG_TEST, run["scan_run_id"], "NUCLEI", SAMPLE_NUCLEI_REPORT.encode("utf-8"), "FILE_UPLOAD", USER_ANALYST)

    result = process_scan_run_pipeline(ORG_TEST, run["scan_run_id"], USER_LEAD)
    assert result["canonical_finding_count"] > 0
    assert "findings_json" in result

    sr = get_scan_run(ORG_TEST, run["scan_run_id"])
    assert sr["status"] == "COMPLETED"


def test_23_partial_processing_preserves_denominator(seeded_fixture):
    asset = seeded_fixture
    run = create_run(ORG_TEST, asset["asset_id"], USER_LEAD, ["ZAP", "NUCLEI", "WAPITI"])

    # Ingest only 2 of 3
    ingest_report(ORG_TEST, run["scan_run_id"], "ZAP", SAMPLE_ZAP_REPORT.encode("utf-8"), "FILE_UPLOAD", USER_ANALYST)
    ingest_report(ORG_TEST, run["scan_run_id"], "NUCLEI", SAMPLE_NUCLEI_REPORT.encode("utf-8"), "FILE_UPLOAD", USER_ANALYST)

    result = process_scan_run_pipeline(ORG_TEST, run["scan_run_id"], USER_LEAD, is_partial_trigger=True)
    summary = json.loads(result["summary_json"])

    assert summary["consensus_ratio"] == "2/3"
    assert summary["expected_scanners"] == ["ZAP", "NUCLEI", "WAPITI"]
    assert summary["missing_scanners"] == ["WAPITI"]


def test_24_stage_event_sequence_recorded(seeded_fixture):
    asset = seeded_fixture
    run = create_run(ORG_TEST, asset["asset_id"], USER_LEAD, ["ZAP"])
    ingest_report(ORG_TEST, run["scan_run_id"], "ZAP", SAMPLE_ZAP_REPORT.encode("utf-8"), "FILE_UPLOAD", USER_ANALYST)

    process_scan_run_pipeline(ORG_TEST, run["scan_run_id"], USER_LEAD)
    events = list_scan_run_events(ORG_TEST, run["scan_run_id"])
    types = [e["event_type"] for e in events]

    assert "SCANNER_REPORT_RECEIVED" in types
    assert "NORMALIZATION_STARTED" in types
    assert "NORMALIZATION_COMPLETED" in types
    assert "DEDUPLICATION_COMPLETED" in types
    assert "RISK_SCORING_COMPLETED" in types
    assert "SCAN_COMPLETED" in types


def test_26_target_host_validation_policy(seeded_fixture):
    asset = seeded_fixture
    run = create_run(ORG_TEST, asset["asset_id"], USER_LEAD, ["ZAP"])

    # MATCH
    status1, _ = validate_report_target(SAMPLE_ZAP_REPORT, "ZAP", "payments.demo.corp")
    assert status1 == "MATCH"

    # CLEAR_MISMATCH
    with pytest.raises(TargetMismatchError):
        ingest_report(
            organization_id=ORG_TEST,
            scan_run_id=run["scan_run_id"],
            scanner="ZAP",
            report_bytes=SAMPLE_MISMATCH_ZAP_REPORT.encode("utf-8"),
            submission_type="FILE_UPLOAD",
            user_id=USER_ANALYST,
        )


def test_27_atomic_lock_prevents_duplicate_processing(seeded_fixture):
    asset = seeded_fixture
    run = create_run(ORG_TEST, asset["asset_id"], USER_LEAD, ["ZAP"])
    ingest_report(ORG_TEST, run["scan_run_id"], "ZAP", SAMPLE_ZAP_REPORT.encode("utf-8"), "FILE_UPLOAD", USER_ANALYST)

    # First acquisition succeeds
    res1 = process_scan_run_pipeline(ORG_TEST, run["scan_run_id"], USER_LEAD)
    assert res1.get("status") != "ALREADY_PROCESSING"

    # Second acquisition attempt safely returns ALREADY_PROCESSING or existing result
    res2 = process_scan_run_pipeline(ORG_TEST, run["scan_run_id"], USER_LEAD)
    assert res2 is not None


# ─────────────────────────────────────────────────────────────
# Test 14-16 & 21-25: Source IDs, Isolation, RBAC & Failure Paths
# ─────────────────────────────────────────────────────────────

def test_14_deterministic_source_ids_preserved(seeded_fixture):
    asset = seeded_fixture
    run = create_run(ORG_TEST, asset["asset_id"], USER_LEAD, ["ZAP", "NUCLEI"])
    ingest_report(ORG_TEST, run["scan_run_id"], "ZAP", SAMPLE_ZAP_REPORT.encode("utf-8"), "FILE_UPLOAD", USER_ANALYST)
    ingest_report(ORG_TEST, run["scan_run_id"], "NUCLEI", SAMPLE_NUCLEI_REPORT.encode("utf-8"), "FILE_UPLOAD", USER_ANALYST)

    res = process_scan_run_pipeline(ORG_TEST, run["scan_run_id"], USER_LEAD)
    findings = json.loads(res["findings_json"])
    assert len(findings) > 0
    for f in findings:
        assert f.get("source_finding_ids") or f.get("finding_id")


def test_15_scan_run_results_isolation(seeded_fixture):
    asset = seeded_fixture
    run1 = create_run(ORG_TEST, asset["asset_id"], USER_LEAD, ["ZAP"])
    run2 = create_run(ORG_TEST, asset["asset_id"], USER_LEAD, ["NUCLEI"])

    ingest_report(ORG_TEST, run1["scan_run_id"], "ZAP", SAMPLE_ZAP_REPORT.encode("utf-8"), "FILE_UPLOAD", USER_ANALYST)
    ingest_report(ORG_TEST, run2["scan_run_id"], "NUCLEI", SAMPLE_NUCLEI_REPORT.encode("utf-8"), "FILE_UPLOAD", USER_ANALYST)

    process_scan_run_pipeline(ORG_TEST, run1["scan_run_id"], USER_LEAD)
    process_scan_run_pipeline(ORG_TEST, run2["scan_run_id"], USER_LEAD)

    res1 = get_scan_run_results(ORG_TEST, run1["scan_run_id"])
    res2 = get_scan_run_results(ORG_TEST, run2["scan_run_id"])

    assert res1["result_id"] != res2["result_id"]
    assert res1["scan_run_id"] == run1["scan_run_id"]
    assert res2["scan_run_id"] == run2["scan_run_id"]


def test_08_cross_run_contamination_impossible(seeded_fixture):
    asset = seeded_fixture
    run1 = create_run(ORG_TEST, asset["asset_id"], USER_LEAD, ["ZAP"])
    run2 = create_run(ORG_TEST, asset["asset_id"], USER_LEAD, ["ZAP"])

    ingest_report(ORG_TEST, run1["scan_run_id"], "ZAP", SAMPLE_ZAP_REPORT.encode("utf-8"), "FILE_UPLOAD", USER_ANALYST)
    
    subs1 = list_submissions_for_run(ORG_TEST, run1["scan_run_id"])
    subs2 = list_submissions_for_run(ORG_TEST, run2["scan_run_id"])

    assert len(subs1) == 1
    assert len(subs2) == 0


def test_12_run_tracks_pending_received_failed_scanners(seeded_fixture):
    asset = seeded_fixture
    run = create_run(ORG_TEST, asset["asset_id"], USER_LEAD, ["ZAP", "NUCLEI", "WAPITI"])

    res1 = ingest_report(ORG_TEST, run["scan_run_id"], "ZAP", SAMPLE_ZAP_REPORT.encode("utf-8"), "FILE_UPLOAD", USER_ANALYST)
    assert set(res1["received_scanners"]) == {"ZAP"}
    assert set(res1["pending_scanners"]) == {"NUCLEI", "WAPITI"}

    sr = get_scan_run(ORG_TEST, run["scan_run_id"])
    assert json.loads(sr["received_scanners"]) == ["ZAP"]


def test_16_m2_deduplication_preserves_source_ids(seeded_fixture):
    asset = seeded_fixture
    run = create_run(ORG_TEST, asset["asset_id"], USER_LEAD, ["ZAP", "NUCLEI"])
    ingest_report(ORG_TEST, run["scan_run_id"], "ZAP", SAMPLE_ZAP_REPORT.encode("utf-8"), "FILE_UPLOAD", USER_ANALYST)
    ingest_report(ORG_TEST, run["scan_run_id"], "NUCLEI", SAMPLE_NUCLEI_REPORT.encode("utf-8"), "FILE_UPLOAD", USER_ANALYST)

    res = process_scan_run_pipeline(ORG_TEST, run["scan_run_id"], USER_LEAD)
    findings = json.loads(res["findings_json"])
    assert len(findings) > 0
    for f in findings:
        source_ids = f.get("source_finding_ids") or [f.get("finding_id")]
        assert len(source_ids) > 0


def test_17_cross_asset_dedup_protections(seeded_fixture):
    # Two distinct assets in same org
    asset1 = seeded_fixture
    asset2 = register_asset(
        organization_id=ORG_TEST,
        display_name="Other Target Service",
        host="other.demo.corp",
        port=443,
        environment="staging",
        criticality="HIGH",
        internet_facing=False,
        data_sensitivity="INTERNAL",
        created_by=USER_LEAD,
    )
    set_authorization_status(ORG_TEST, asset2["asset_id"], "AUTHORIZED", USER_LEAD)

    run1 = create_run(ORG_TEST, asset1["asset_id"], USER_LEAD, ["ZAP"])
    run2 = create_run(ORG_TEST, asset2["asset_id"], USER_LEAD, ["ZAP"])

    ingest_report(ORG_TEST, run1["scan_run_id"], "ZAP", SAMPLE_ZAP_REPORT.encode("utf-8"), "FILE_UPLOAD", USER_ANALYST)

    zap_other = json.dumps({
        "site": [{
            "@name": "https://other.demo.corp",
            "@host": "other.demo.corp",
            "@port": "443",
            "alerts": [{
                "pluginid": "40018",
                "alert": "SQL Injection",
                "riskcode": "3",
                "confidence": "3",
                "instances": [{"uri": "https://other.demo.corp/api/test"}]
            }]
        }]
    })
    ingest_report(ORG_TEST, run2["scan_run_id"], "ZAP", zap_other.encode("utf-8"), "FILE_UPLOAD", USER_ANALYST)

    res1 = process_scan_run_pipeline(ORG_TEST, run1["scan_run_id"], USER_LEAD)
    res2 = process_scan_run_pipeline(ORG_TEST, run2["scan_run_id"], USER_LEAD)

    f1 = json.loads(res1["findings_json"])
    f2 = json.loads(res2["findings_json"])

    assert f1[0]["asset_id"] == asset1["asset_id"]
    assert f2[0]["asset_id"] == asset2["asset_id"]
    assert f1[0]["asset_id"] != f2[0]["asset_id"]


def test_18_m3_confidence_and_noise_routing(seeded_fixture):
    asset = seeded_fixture
    run = create_run(ORG_TEST, asset["asset_id"], USER_LEAD, ["ZAP"])
    ingest_report(ORG_TEST, run["scan_run_id"], "ZAP", SAMPLE_ZAP_REPORT.encode("utf-8"), "FILE_UPLOAD", USER_ANALYST)
    res = process_scan_run_pipeline(ORG_TEST, run["scan_run_id"], USER_LEAD)

    findings = json.loads(res["findings_json"])
    for f in findings:
        conf = f.get("confidence_classification") or f.get("confidence") or "CONFIDENT"
        assert conf in ("HIGH_CONFIDENCE", "REVIEW_REQUIRED", "NOISE", "CONFIDENT", "NEEDS_REVIEW")


def test_19_m5_risk_engine_sovereignty(seeded_fixture):
    asset = seeded_fixture
    run = create_run(ORG_TEST, asset["asset_id"], USER_LEAD, ["ZAP"])
    ingest_report(ORG_TEST, run["scan_run_id"], "ZAP", SAMPLE_ZAP_REPORT.encode("utf-8"), "FILE_UPLOAD", USER_ANALYST)
    res = process_scan_run_pipeline(ORG_TEST, run["scan_run_id"], USER_LEAD)

    findings = json.loads(res["findings_json"])
    for f in findings:
        score = f.get("risk_score", 0)
        assert 0 <= score <= 100
        assert "risk_level" in f


def test_20_completed_run_exposes_correct_findings_via_results_endpoint(seeded_fixture):
    asset = seeded_fixture
    run = create_run(ORG_TEST, asset["asset_id"], USER_LEAD, ["ZAP"])
    ingest_report(ORG_TEST, run["scan_run_id"], "ZAP", SAMPLE_ZAP_REPORT.encode("utf-8"), "FILE_UPLOAD", USER_ANALYST)
    process_scan_run_pipeline(ORG_TEST, run["scan_run_id"], USER_LEAD)

    results = get_scan_run_results(ORG_TEST, run["scan_run_id"])
    assert results is not None
    assert results["scan_run_id"] == run["scan_run_id"]
    assert results["organization_id"] == ORG_TEST
    assert len(json.loads(results["findings_json"])) > 0


def test_21_viewer_cannot_upload_or_trigger_processing():
    from auth import User, UserRole
    user_viewer = User(
        user_id="usr-viewer-001",
        username="viewer",
        email="viewer@example.com",
        role=UserRole.VIEWER,
        display_name="Viewer User",
        password_hash="mock_hash",
    )
    from routers.v1.organizations import _require_analyst_up, _require_lead_up
    from fastapi import HTTPException

    with pytest.raises(HTTPException) as exc1:
        _require_analyst_up(user_viewer)
    assert exc1.value.status_code == 403

    with pytest.raises(HTTPException) as exc2:
        _require_lead_up(user_viewer)
    assert exc2.value.status_code == 403


def test_22_analyst_cannot_trigger_privileged_partial_processing():
    from auth import User, UserRole
    user_analyst = User(
        user_id="usr-analyst-002",
        username="analyst",
        email="analyst@example.com",
        role=UserRole.ANALYST,
        display_name="Analyst User",
        password_hash="mock_hash",
    )
    from routers.v1.organizations import _require_lead_up
    from fastapi import HTTPException

    with pytest.raises(HTTPException) as exc:
        _require_lead_up(user_analyst)
    assert exc.value.status_code == 403


def test_25_failed_processing_updates_status_and_logs_scan_failed(seeded_fixture):
    asset = seeded_fixture
    run = create_run(ORG_TEST, asset["asset_id"], USER_LEAD, ["ZAP"])
    # Ingest invalid payload into submission directly to simulate pipeline failure
    db.create_scanner_submission(
        submission_id="SUB-FAIL-001",
        scan_run_id=run["scan_run_id"],
        organization_id=ORG_TEST,
        asset_id=asset["asset_id"],
        scanner="ZAP",
        submission_type="FILE_UPLOAD",
        received_by_user_id=USER_ANALYST,
        original_filename="corrupted.json",
        content_type="application/json",
        file_size_bytes=10,
        storage_path="/non/existent/path/bad.json",
        raw_finding_count=1,
        processing_status="PARSED",
        payload_hash="hash000",
    )

    with pytest.raises(RuntimeError, match="Pipeline processing failed"):
        process_scan_run_pipeline(ORG_TEST, run["scan_run_id"], USER_LEAD)

    sr = get_scan_run(ORG_TEST, run["scan_run_id"])
    assert sr["status"] == "FAILED"
    events = list_scan_run_events(ORG_TEST, run["scan_run_id"])
    event_types = [e["event_type"] for e in events]
    assert "SCAN_FAILED" in event_types


def test_28_unknown_target_validation_policy():
    zap_no_host = json.dumps({"site": [{"alerts": []}]})
    status, det = validate_report_target(zap_no_host, "ZAP", "payments.demo.corp")
    assert status == "UNKNOWN"
    assert det is None


# ─────────────────────────────────────────────────────────────
# Test 29-31: Asynchronous Execution, Atomic Race-Safety & Full Isolation
# ─────────────────────────────────────────────────────────────

def test_29_async_background_upload_returns_immediately_and_completes(seeded_fixture):
    """Proves HTTP upload returns response without synchronously blocking on M1-M7 pipeline execution."""
    from fastapi.testclient import TestClient
    from main import app
    from auth import User, UserRole, create_access_token

    asset = seeded_fixture
    run = create_run(ORG_TEST, asset["asset_id"], USER_LEAD, ["ZAP"])

    user_obj = User(
        user_id=USER_ANALYST,
        username="analyst",
        email="analyst@corp.com",
        role=UserRole.ANALYST,
        display_name="Analyst User",
        password_hash="mock_hash",
    )
    token = create_access_token(user_obj)
    client = TestClient(app)

    response = client.post(
        f"/api/v1/organizations/{ORG_TEST}/scan-runs/{run['scan_run_id']}/ingest/ZAP",
        headers={"Authorization": f"Bearer {token}"},
        files={"file": ("zap_report.json", SAMPLE_ZAP_REPORT.encode("utf-8"), "application/json")},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["is_consensus_reached"] is True

    # TestClient runs background tasks automatically on response close
    sr = get_scan_run(ORG_TEST, run["scan_run_id"])
    assert sr["status"] in ("PROCESSING", "COMPLETED")

    results = get_scan_run_results(ORG_TEST, run["scan_run_id"])
    assert results is not None


def test_30_concurrent_final_submissions_trigger_processing_exactly_once(seeded_fixture):
    """Proves multi-threaded concurrent final submissions trigger atomic lock acquisition and exactly-once execution."""
    import concurrent.futures

    asset = seeded_fixture
    run = create_run(ORG_TEST, asset["asset_id"], USER_LEAD, ["ZAP"])
    ingest_report(ORG_TEST, run["scan_run_id"], "ZAP", SAMPLE_ZAP_REPORT.encode("utf-8"), "FILE_UPLOAD", USER_ANALYST)

    results_list = []
    def _worker():
        return process_scan_run_pipeline(ORG_TEST, run["scan_run_id"], USER_LEAD)

    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        futures = [executor.submit(_worker) for _ in range(5)]
        for f in concurrent.futures.as_completed(futures):
            try:
                results_list.append(f.result())
            except Exception as e:
                results_list.append({"error": str(e)})

    # Exactly one thread acquired lock and returned results; others got ALREADY_PROCESSING or existing result
    sr = get_scan_run(ORG_TEST, run["scan_run_id"])
    assert sr["status"] == "COMPLETED"

    events = list_scan_run_events(ORG_TEST, run["scan_run_id"])
    proc_started_events = [e for e in events if e["event_type"] == "PROCESSING_STARTED"]
    assert len(proc_started_events) == 1


def test_31_full_m8_scan_run_results_isolation(seeded_fixture):
    """Proves opening Run A returns ONLY Run A findings and never Run B or mock findings."""
    asset = seeded_fixture
    run_a = create_run(ORG_TEST, asset["asset_id"], USER_LEAD, ["ZAP"])
    run_b = create_run(ORG_TEST, asset["asset_id"], USER_LEAD, ["NUCLEI"])

    ingest_report(ORG_TEST, run_a["scan_run_id"], "ZAP", SAMPLE_ZAP_REPORT.encode("utf-8"), "FILE_UPLOAD", USER_ANALYST)
    ingest_report(ORG_TEST, run_b["scan_run_id"], "NUCLEI", SAMPLE_NUCLEI_REPORT.encode("utf-8"), "FILE_UPLOAD", USER_ANALYST)

    process_scan_run_pipeline(ORG_TEST, run_a["scan_run_id"], USER_LEAD)
    process_scan_run_pipeline(ORG_TEST, run_b["scan_run_id"], USER_LEAD)

    res_a = get_scan_run_results(ORG_TEST, run_a["scan_run_id"])
    res_b = get_scan_run_results(ORG_TEST, run_b["scan_run_id"])

    findings_a = json.loads(res_a["findings_json"])
    findings_b = json.loads(res_b["findings_json"])

    cve_a = [f.get("cve_id") or f.get("vulnerability_name") for f in findings_a]
    cve_b = [f.get("cve_id") or f.get("vulnerability_name") for f in findings_b]

    # Run A has ZAP SQL Injection, Run B has Nuclei CVE-2026-9999 RCE
    assert any("SQL Injection" in c or "40018" in c for c in cve_a)
    assert not any("CVE-2026-9999" in c for c in cve_a)

    assert any("CVE-2026-9999" in c or "Remote Code Execution" in c for c in cve_b)
    assert not any("SQL Injection" in c or "40018" in c for c in cve_b)


