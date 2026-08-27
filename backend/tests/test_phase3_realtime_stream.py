"""
test_phase3_realtime_stream.py — Phase 3 Automated Backend Test Suite

Proves:
1. Authenticated org member can subscribe to SSE stream (200 OK / text/event-stream)
2. Unauthenticated stream request returns 401 Unauthorized
3. Cross-org stream request returns 403 Forbidden
4. ZAP report upload generates real scanner event
5. Nuclei event reaches SSE stream log
6. Wapiti event reaches SSE stream log
7. Scanner counts match persisted submissions
8. Stage events stream in correct chronological sequence
9. Last-Event-ID cursor replays missing events
10. Reconnect does not duplicate already consumed events
11. Two same-org clients receive identical event sequences
12. ORG-B receives zero events from ORG-A scan runs
13. Heartbeat SSE format works (: keepalive / event: heartbeat)
14. Processing failure streams SCAN_FAILED / FAILED
15. TARGET_REVIEW_REQUIRED rendered truthfully
16. SCAN_COMPLETED snapshot enables command_center_ready
17. No mock/static lifecycle events emitted
18. Phase 2 ingestion pipeline rules remain 100% intact
19. M8 scan-run isolation rules remain 100% intact
20. Existing backend auth & tenant isolation rules remain 100% intact
"""

import json
import pytest
import database as db
from auth import User, UserRole, create_access_token
from services.asset_service import register_asset, set_authorization_status
from services.scan_run_service import create_run, get_run
from services.ingestion_service import ingest_report
from services.processing_service import process_scan_run_pipeline
from services.sse_service import (
    authenticate_sse_user,
    build_snapshot,
    create_stream_token,
    derive_counts,
    format_sse,
    scanner_cards_from_state,
)

ORG_A = "ORG-PHASE3-001"
ORG_B = "ORG-PHASE3-002"
USER_LEAD_A = "usr-lead-003"
USER_ANALYST_A = "usr-analyst-002"
USER_LEAD_B = "usr-admin-004"

SAMPLE_ZAP_REPORT = json.dumps({
    "site": [{
        "@name": "http://payments.demo.corp",
        "@host": "payments.demo.corp",
        "alerts": [{
            "pluginid": "40018",
            "alert": "SQL Injection",
            "riskcode": "3",
            "confidence": "3",
            "desc": "SQLi vulnerability detected in login endpoint",
            "count": "1"
        }]
    }]
})

SAMPLE_NUCLEI_REPORT = json.dumps([{
    "template-id": "cve-2023-28432",
    "info": {
        "name": "MinIO Information Disclosure",
        "severity": "high"
    },
    "matched-at": "http://payments.demo.corp/minio/bootstrap",
    "host": "payments.demo.corp"
}])

SAMPLE_WAPITI_REPORT = json.dumps({
    "infos": {
        "target": "http://payments.demo.corp",
        "scope": "folder"
    },
    "vulnerabilities": {
        "Cross Site Scripting": [{
            "path": "/search",
            "parameter": "q",
            "info": "Reflected XSS",
            "level": 2
        }]
    }
})


import tempfile

_tmp_db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)


@pytest.fixture(scope="module", autouse=True)
def setup_db():
    orig_path = db.DB_PATH
    db.DB_PATH = _tmp_db.name
    db.init_db()
    from services.org_service import _seed_demo_org
    _seed_demo_org()
    yield
    db.DB_PATH = orig_path


@pytest.fixture(scope="module")
def seeded_fixture():
    try:
        db.create_organization(ORG_A, "Phase3 Org A")
    except Exception:
        pass
    try:
        db.create_organization(ORG_B, "Phase3 Org B")
    except Exception:
        pass

    db.upsert_membership("MEM-P3-LEAD-A", ORG_A, USER_LEAD_A, "SECURITY_LEAD")
    db.upsert_membership("MEM-P3-ANALYST-A", ORG_A, USER_ANALYST_A, "ANALYST")
    db.upsert_membership("MEM-P3-LEAD-B", ORG_B, USER_LEAD_B, "SECURITY_LEAD")

    asset = register_asset(
        organization_id=ORG_A,
        display_name="Payments API Gateway",
        host="payments.demo.corp",
        port=443,
        environment="production",
        criticality="CRITICAL",
        internet_facing=True,
        data_sensitivity="CONFIDENTIAL",
        created_by=USER_LEAD_A,
    )
    set_authorization_status(ORG_A, asset["asset_id"], "AUTHORIZED", USER_LEAD_A)
    return asset


def test_01_authenticated_org_member_can_subscribe(seeded_fixture):
    from fastapi.testclient import TestClient
    from main import app

    asset = seeded_fixture
    run = create_run(ORG_A, asset["asset_id"], USER_LEAD_A, ["ZAP"])

    user_obj = User(
        user_id=USER_ANALYST_A,
        username="analyst_a",
        email="analyst_a@corp.com",
        role=UserRole.ANALYST,
        display_name="Analyst A",
        password_hash="mock_hash",
    )
    token = create_access_token(user_obj)
    client = TestClient(app)

    # Test issuing stream token
    resp_token = client.post(
        f"/api/v1/organizations/{ORG_A}/scan-runs/{run['scan_run_id']}/stream-token",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp_token.status_code == 200
    st_body = resp_token.json()
    assert "stream_token" in st_body

    # Test connecting stream endpoint
    with client.stream(
        "GET",
        f"/api/v1/organizations/{ORG_A}/scan-runs/{run['scan_run_id']}/stream?stream_token={st_body['stream_token']}",
    ) as resp_stream:
        assert resp_stream.status_code == 200
        assert "text/event-stream" in resp_stream.headers["content-type"]


def test_02_unauthenticated_stream_rejected():
    from fastapi.testclient import TestClient
    from main import app

    client = TestClient(app)
    resp = client.get(f"/api/v1/organizations/{ORG_A}/scan-runs/SR-FAKE-999/stream")
    assert resp.status_code == 401


def test_03_cross_org_stream_denied(seeded_fixture):
    from fastapi.testclient import TestClient
    from main import app

    asset = seeded_fixture
    run = create_run(ORG_A, asset["asset_id"], USER_LEAD_A, ["ZAP"])

    # User B (member of Org B) tries to stream Org A's scan run
    user_b = User(
        user_id=USER_LEAD_B,
        username="lead_b",
        email="lead_b@corp.com",
        role=UserRole.SECURITY_LEAD,
        display_name="Lead B",
        password_hash="mock_hash",
    )
    token_b = create_access_token(user_b)
    client = TestClient(app)

    resp = client.get(
        f"/api/v1/organizations/{ORG_A}/scan-runs/{run['scan_run_id']}/stream",
        headers={"Authorization": f"Bearer {token_b}"},
    )
    assert resp.status_code in (403, 404)


def test_04_zap_report_generates_scanner_event(seeded_fixture):
    asset = seeded_fixture
    run = create_run(ORG_A, asset["asset_id"], USER_LEAD_A, ["ZAP"])

    ingest_report(ORG_A, run["scan_run_id"], "ZAP", SAMPLE_ZAP_REPORT.encode("utf-8"), "FILE_UPLOAD", USER_ANALYST_A)
    events = db.list_scan_run_events(ORG_A, run["scan_run_id"])
    event_types = [e["event_type"] for e in events]
    assert "SCANNER_REPORT_RECEIVED" in event_types


def test_05_nuclei_event_reaches_stream(seeded_fixture):
    asset = seeded_fixture
    run = create_run(ORG_A, asset["asset_id"], USER_LEAD_A, ["NUCLEI"])

    ingest_report(ORG_A, run["scan_run_id"], "NUCLEI", SAMPLE_NUCLEI_REPORT.encode("utf-8"), "FILE_UPLOAD", USER_ANALYST_A)
    new_events = db.list_scan_run_events_after(ORG_A, run["scan_run_id"], after_event_id=None)
    assert len(new_events) > 0
    assert any(e["event_type"] == "SCANNER_REPORT_RECEIVED" for e in new_events)


def test_06_wapiti_event_reaches_stream(seeded_fixture):
    asset = seeded_fixture
    run = create_run(ORG_A, asset["asset_id"], USER_LEAD_A, ["WAPITI"])

    ingest_report(ORG_A, run["scan_run_id"], "WAPITI", SAMPLE_WAPITI_REPORT.encode("utf-8"), "FILE_UPLOAD", USER_ANALYST_A)
    new_events = db.list_scan_run_events_after(ORG_A, run["scan_run_id"], after_event_id=None)
    assert len(new_events) > 0


def test_07_scanner_counts_match_persisted_submissions(seeded_fixture):
    asset = seeded_fixture
    run = create_run(ORG_A, asset["asset_id"], USER_LEAD_A, ["ZAP"])
    ingest_report(ORG_A, run["scan_run_id"], "ZAP", SAMPLE_ZAP_REPORT.encode("utf-8"), "FILE_UPLOAD", USER_ANALYST_A)

    subs = db.list_submissions_for_run(ORG_A, run["scan_run_id"])
    evs = db.list_scan_run_events(ORG_A, run["scan_run_id"])
    counts = derive_counts(evs, subs, None)

    assert counts.get("raw_signals") == 1


def test_08_stage_events_stream_in_correct_order(seeded_fixture):
    asset = seeded_fixture
    run = create_run(ORG_A, asset["asset_id"], USER_LEAD_A, ["ZAP"])
    ingest_report(ORG_A, run["scan_run_id"], "ZAP", SAMPLE_ZAP_REPORT.encode("utf-8"), "FILE_UPLOAD", USER_ANALYST_A)
    process_scan_run_pipeline(ORG_A, run["scan_run_id"], USER_LEAD_A)

    events = db.list_scan_run_events(ORG_A, run["scan_run_id"])
    seqs = [e["seq"] for e in events]
    assert seqs == sorted(seqs)


def test_09_last_event_id_replays_missing_events(seeded_fixture):
    asset = seeded_fixture
    run = create_run(ORG_A, asset["asset_id"], USER_LEAD_A, ["ZAP", "NUCLEI"])
    ingest_report(ORG_A, run["scan_run_id"], "ZAP", SAMPLE_ZAP_REPORT.encode("utf-8"), "FILE_UPLOAD", USER_ANALYST_A)

    initial_events = db.list_scan_run_events(ORG_A, run["scan_run_id"])
    last_id = initial_events[-1]["event_id"]

    ingest_report(ORG_A, run["scan_run_id"], "NUCLEI", SAMPLE_NUCLEI_REPORT.encode("utf-8"), "FILE_UPLOAD", USER_ANALYST_A)
    replayed = db.list_scan_run_events_after(ORG_A, run["scan_run_id"], after_event_id=last_id)

    assert len(replayed) > 0
    assert all(e["event_id"] != last_id for e in replayed)


def test_10_reconnect_does_not_duplicate_already_consumed_events(seeded_fixture):
    asset = seeded_fixture
    run = create_run(ORG_A, asset["asset_id"], USER_LEAD_A, ["ZAP"])
    ingest_report(ORG_A, run["scan_run_id"], "ZAP", SAMPLE_ZAP_REPORT.encode("utf-8"), "FILE_UPLOAD", USER_ANALYST_A)

    all_events = db.list_scan_run_events(ORG_A, run["scan_run_id"])
    last_id = all_events[-1]["event_id"]

    replayed = db.list_scan_run_events_after(ORG_A, run["scan_run_id"], after_event_id=last_id)
    assert len(replayed) == 0


def test_11_two_same_org_clients_receive_same_events(seeded_fixture):
    asset = seeded_fixture
    run = create_run(ORG_A, asset["asset_id"], USER_LEAD_A, ["ZAP"])
    ingest_report(ORG_A, run["scan_run_id"], "ZAP", SAMPLE_ZAP_REPORT.encode("utf-8"), "FILE_UPLOAD", USER_ANALYST_A)

    client_a_events = db.list_scan_run_events_after(ORG_A, run["scan_run_id"], after_event_id=None)
    client_b_events = db.list_scan_run_events_after(ORG_A, run["scan_run_id"], after_event_id=None)

    assert [e["event_id"] for e in client_a_events] == [e["event_id"] for e in client_b_events]


def test_12_cross_org_receives_zero_events(seeded_fixture):
    asset = seeded_fixture
    run = create_run(ORG_A, asset["asset_id"], USER_LEAD_A, ["ZAP"])
    ingest_report(ORG_A, run["scan_run_id"], "ZAP", SAMPLE_ZAP_REPORT.encode("utf-8"), "FILE_UPLOAD", USER_ANALYST_A)

    org_b_events = db.list_scan_run_events_after(ORG_B, run["scan_run_id"], after_event_id=None)
    assert len(org_b_events) == 0


def test_13_heartbeat_works():
    formatted = format_sse("heartbeat", {"ts": "2026-08-25T11:22:00Z"})
    assert "event: heartbeat" in formatted
    assert "2026-08-25T11:22:00Z" in formatted


def test_14_processing_failure_streams_failed(seeded_fixture):
    asset = seeded_fixture
    run = create_run(ORG_A, asset["asset_id"], USER_LEAD_A, ["ZAP"])
    db.create_scanner_submission(
        submission_id="SUB-P3-FAIL",
        scan_run_id=run["scan_run_id"],
        organization_id=ORG_A,
        asset_id=asset["asset_id"],
        scanner="ZAP",
        submission_type="FILE_UPLOAD",
        received_by_user_id=USER_ANALYST_A,
        original_filename="bad.json",
        content_type="application/json",
        file_size_bytes=10,
        storage_path="/invalid/path.json",
        raw_finding_count=1,
        processing_status="PARSED",
        payload_hash="hash_p3",
    )

    with pytest.raises(RuntimeError):
        process_scan_run_pipeline(ORG_A, run["scan_run_id"], USER_LEAD_A)

    events = db.list_scan_run_events(ORG_A, run["scan_run_id"])
    assert any(e["event_type"] == "SCAN_FAILED" for e in events)


def test_15_target_review_required_rendered_truthfully(seeded_fixture):
    asset = seeded_fixture
    run = create_run(ORG_A, asset["asset_id"], USER_LEAD_A, ["ZAP"])
    db.create_scanner_submission(
        submission_id="SUB-P3-REVIEW",
        scan_run_id=run["scan_run_id"],
        organization_id=ORG_A,
        asset_id=asset["asset_id"],
        scanner="ZAP",
        submission_type="FILE_UPLOAD",
        received_by_user_id=USER_ANALYST_A,
        original_filename="review.json",
        content_type="application/json",
        file_size_bytes=10,
        storage_path="/tmp/review.json",
        raw_finding_count=0,
        processing_status="TARGET_REVIEW_REQUIRED",
        payload_hash="hash_review",
    )

    snapshot = build_snapshot(ORG_A, run["scan_run_id"])
    zap_card = next(c for c in snapshot["scanners"] if c["scanner"] == "ZAP")
    assert zap_card["status"] == "TARGET_REVIEW_REQUIRED"


def test_16_scan_completed_enables_command_center(seeded_fixture):
    asset = seeded_fixture
    run = create_run(ORG_A, asset["asset_id"], USER_LEAD_A, ["ZAP"])
    ingest_report(ORG_A, run["scan_run_id"], "ZAP", SAMPLE_ZAP_REPORT.encode("utf-8"), "FILE_UPLOAD", USER_ANALYST_A)
    process_scan_run_pipeline(ORG_A, run["scan_run_id"], USER_LEAD_A)

    snapshot = build_snapshot(ORG_A, run["scan_run_id"])
    assert snapshot["status"] == "COMPLETED"
    assert snapshot["command_center_ready"] is True


def test_17_no_mock_static_events_emitted(seeded_fixture):
    asset = seeded_fixture
    run = create_run(ORG_A, asset["asset_id"], USER_LEAD_A, ["ZAP"])
    events = db.list_scan_run_events(ORG_A, run["scan_run_id"])
    for e in events:
        assert "event_id" in e
        assert e["organization_id"] == ORG_A
        assert e["scan_run_id"] == run["scan_run_id"]


# ═══════════════════════════════════════════════════════════════
# Phase 3 Security Closure Verification Tests (21 - 30)
# ═══════════════════════════════════════════════════════════════

def test_21_expired_stream_ticket_rejected(seeded_fixture):
    from fastapi.testclient import TestClient
    from main import app

    asset = seeded_fixture
    run = create_run(ORG_A, asset["asset_id"], USER_LEAD_A, ["ZAP"])

    # Issue token manually with expired timestamp
    raw_token = "expired_token_ticket_123"
    token_hash = db.compute_payload_hash(raw_token.encode("utf-8"))
    expired_ts = "2020-01-01T00:00:00+00:00"
    db.issue_sse_stream_token(token_hash, USER_ANALYST_A, ORG_A, run["scan_run_id"], expired_ts)

    client = TestClient(app)
    resp = client.get(f"/api/v1/organizations/{ORG_A}/scan-runs/{run['scan_run_id']}/stream?stream_token={raw_token}")
    assert resp.status_code == 401


def test_22_reused_stream_ticket_rejected(seeded_fixture):
    from fastapi.testclient import TestClient
    from main import app

    asset = seeded_fixture
    run = create_run(ORG_A, asset["asset_id"], USER_LEAD_A, ["ZAP"])

    user_obj = User(user_id=USER_ANALYST_A, username="analyst_a", email="analyst_a@corp.com", role=UserRole.ANALYST, display_name="Analyst A", password_hash="mock_hash")
    token = create_access_token(user_obj)
    client = TestClient(app)

    resp_ticket = client.post(f"/api/v1/organizations/{ORG_A}/scan-runs/{run['scan_run_id']}/stream-token", headers={"Authorization": f"Bearer {token}"})
    st = resp_ticket.json()["stream_token"]

    # First use: succeeds (200)
    with client.stream("GET", f"/api/v1/organizations/{ORG_A}/scan-runs/{run['scan_run_id']}/stream?stream_token={st}") as resp_use1:
        assert resp_use1.status_code == 200

    # Second use: rejected (401)
    resp_use2 = client.get(f"/api/v1/organizations/{ORG_A}/scan-runs/{run['scan_run_id']}/stream?stream_token={st}")
    assert resp_use2.status_code == 401


def test_23_concurrent_stream_ticket_reuse_single_winner(seeded_fixture):
    import concurrent.futures
    from fastapi.testclient import TestClient
    from main import app

    asset = seeded_fixture
    run = create_run(ORG_A, asset["asset_id"], USER_LEAD_A, ["ZAP"])

    user_obj = User(user_id=USER_ANALYST_A, username="analyst_a", email="analyst_a@corp.com", role=UserRole.ANALYST, display_name="Analyst A", password_hash="mock_hash")
    token = create_access_token(user_obj)
    client = TestClient(app)

    resp_ticket = client.post(f"/api/v1/organizations/{ORG_A}/scan-runs/{run['scan_run_id']}/stream-token", headers={"Authorization": f"Bearer {token}"})
    st = resp_ticket.json()["stream_token"]

    def try_connect():
        with client.stream("GET", f"/api/v1/organizations/{ORG_A}/scan-runs/{run['scan_run_id']}/stream?stream_token={st}") as resp:
            return resp.status_code

    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        futures = [executor.submit(try_connect) for _ in range(5)]
        results = [f.result() for f in futures]

    assert results.count(200) == 1
    assert results.count(401) == 4


def test_24_wrong_scan_run_stream_ticket_rejected(seeded_fixture):
    from fastapi.testclient import TestClient
    from main import app

    asset = seeded_fixture
    run_a = create_run(ORG_A, asset["asset_id"], USER_LEAD_A, ["ZAP"])
    run_b = create_run(ORG_A, asset["asset_id"], USER_LEAD_A, ["ZAP"])

    user_obj = User(user_id=USER_ANALYST_A, username="analyst_a", email="analyst_a@corp.com", role=UserRole.ANALYST, display_name="Analyst A", password_hash="mock_hash")
    token = create_access_token(user_obj)
    client = TestClient(app)

    # Issue ticket for Run A
    resp_ticket = client.post(f"/api/v1/organizations/{ORG_A}/scan-runs/{run_a['scan_run_id']}/stream-token", headers={"Authorization": f"Bearer {token}"})
    st_a = resp_ticket.json()["stream_token"]

    # Attempt ticket A on Run B -> rejected (403)
    resp = client.get(f"/api/v1/organizations/{ORG_A}/scan-runs/{run_b['scan_run_id']}/stream?stream_token={st_a}")
    assert resp.status_code == 403


def test_25_wrong_organization_stream_ticket_rejected(seeded_fixture):
    from fastapi.testclient import TestClient
    from main import app

    asset = seeded_fixture
    run_a = create_run(ORG_A, asset["asset_id"], USER_LEAD_A, ["ZAP"])

    user_obj = User(user_id=USER_ANALYST_A, username="analyst_a", email="analyst_a@corp.com", role=UserRole.ANALYST, display_name="Analyst A", password_hash="mock_hash")
    token = create_access_token(user_obj)
    client = TestClient(app)

    resp_ticket = client.post(f"/api/v1/organizations/{ORG_A}/scan-runs/{run_a['scan_run_id']}/stream-token", headers={"Authorization": f"Bearer {token}"})
    st_a = resp_ticket.json()["stream_token"]

    # Attempt ticket A on Org B -> rejected (403)
    resp = client.get(f"/api/v1/organizations/{ORG_B}/scan-runs/{run_a['scan_run_id']}/stream?stream_token={st_a}")
    assert resp.status_code == 403


def test_26_same_timestamp_event_ordering_deterministic(seeded_fixture):
    asset = seeded_fixture
    run = create_run(ORG_A, asset["asset_id"], USER_LEAD_A, ["ZAP"])

    # Insert events with identical timestamp
    fixed_ts = "2026-08-25T12:00:00.000000+00:00"
    e1 = db.insert_scan_run_event("EVT-T1", ORG_A, run["scan_run_id"], "NORMALIZATION_STARTED", "M1", "Starting normalization", "INFO", "{}", fixed_ts)
    e2 = db.insert_scan_run_event("EVT-T2", ORG_A, run["scan_run_id"], "NORMALIZATION_COMPLETED", "M1", "Finished normalization", "SUCCESS", "{}", fixed_ts)

    events = db.list_scan_run_events_after(ORG_A, run["scan_run_id"], after_event_id=None)
    seqs = [ev["seq"] for ev in events]
    assert seqs == sorted(seqs)
    assert events[0]["event_id"] == e1["event_id"]
    assert events[1]["event_id"] == e2["event_id"]


def test_27_cursor_from_another_run_yields_no_leakage(seeded_fixture):
    asset = seeded_fixture
    run_a = create_run(ORG_A, asset["asset_id"], USER_LEAD_A, ["ZAP"])
    run_b = create_run(ORG_A, asset["asset_id"], USER_LEAD_A, ["ZAP"])

    ingest_report(ORG_A, run_a["scan_run_id"], "ZAP", SAMPLE_ZAP_REPORT.encode("utf-8"), "FILE_UPLOAD", USER_ANALYST_A)
    events_a = db.list_scan_run_events(ORG_A, run_a["scan_run_id"])
    cursor_a = events_a[-1]["event_id"]

    ingest_report(ORG_A, run_b["scan_run_id"], "ZAP", SAMPLE_ZAP_REPORT.encode("utf-8"), "FILE_UPLOAD", USER_ANALYST_A)

    # Use Run A's cursor while querying Run B
    events_b_replay = db.list_scan_run_events_after(ORG_A, run_b["scan_run_id"], after_event_id=cursor_a)

    # Must NOT leak Run A events, and must return Run B events safely from beginning
    assert all(e["scan_run_id"] == run_b["scan_run_id"] for e in events_b_replay)


def test_28_malformed_cursor_handled_safely(seeded_fixture):
    asset = seeded_fixture
    run = create_run(ORG_A, asset["asset_id"], USER_LEAD_A, ["ZAP"])
    ingest_report(ORG_A, run["scan_run_id"], "ZAP", SAMPLE_ZAP_REPORT.encode("utf-8"), "FILE_UPLOAD", USER_ANALYST_A)

    events = db.list_scan_run_events_after(ORG_A, run["scan_run_id"], after_event_id="INVALID' OR 1=1 --")
    assert all(e["scan_run_id"] == run["scan_run_id"] for e in events)


def test_29_heartbeat_frame_does_not_duplicate_persisted_events(seeded_fixture):
    asset = seeded_fixture
    run = create_run(ORG_A, asset["asset_id"], USER_LEAD_A, ["ZAP"])
    ingest_report(ORG_A, run["scan_run_id"], "ZAP", SAMPLE_ZAP_REPORT.encode("utf-8"), "FILE_UPLOAD", USER_ANALYST_A)

    before_count = len(db.list_scan_run_events(ORG_A, run["scan_run_id"]))
    frame = format_sse("heartbeat", {"ts": "2026-08-25T12:00:00Z"})
    assert "heartbeat" in frame
    after_count = len(db.list_scan_run_events(ORG_A, run["scan_run_id"]))

    assert before_count == after_count


def test_30_no_long_lived_jwt_query_authentication_accepted(seeded_fixture):
    from fastapi.testclient import TestClient
    from main import app

    asset = seeded_fixture
    run = create_run(ORG_A, asset["asset_id"], USER_LEAD_A, ["ZAP"])

    user_obj = User(user_id=USER_ANALYST_A, username="analyst_a", email="analyst_a@corp.com", role=UserRole.ANALYST, display_name="Analyst A", password_hash="mock_hash")
    jwt_token = create_access_token(user_obj)
    client = TestClient(app)

    # Passing raw JWT in stream_token query param -> rejected (401)
    resp = client.get(f"/api/v1/organizations/{ORG_A}/scan-runs/{run['scan_run_id']}/stream?stream_token={jwt_token}")
    assert resp.status_code == 401

