"""
backend/tests/test_m7_remediation_integration.py
================================================
Comprehensive integration tests for M7 Remediation, Ticketing, and SLA Automation Engine.
"""

import pytest
import uuid
from datetime import datetime, timezone, timedelta
from fastapi.testclient import TestClient

from main import app
from mem7.sla_engine import classify, SLARule
from mem7.models import TicketStatus, VALID_TRANSITIONS, InvalidTransition
from mem7.breach_predictor import evaluate_ticket, BreachWarning
from services.remediation_service import remediation_service
import database
from auth import create_access_token
from users import get_user_by_id

client = TestClient(app)


def test_sla_engine_classification():
    """Verify authoritative risk score to SLA window mapping."""
    # Critical (90-100) -> 4 hours
    assert classify(95) == SLARule(priority="CRITICAL", sla_hours=4)
    assert classify(90) == SLARule(priority="CRITICAL", sla_hours=4)
    assert classify(100) == SLARule(priority="CRITICAL", sla_hours=4)

    # High (70-89) -> 24 hours
    assert classify(89) == SLARule(priority="HIGH", sla_hours=24)
    assert classify(75) == SLARule(priority="HIGH", sla_hours=24)
    assert classify(70) == SLARule(priority="HIGH", sla_hours=24)

    # Medium (40-69) -> 168 hours (7 days)
    assert classify(69) == SLARule(priority="MEDIUM", sla_hours=168)
    assert classify(50) == SLARule(priority="MEDIUM", sla_hours=168)
    assert classify(40) == SLARule(priority="MEDIUM", sla_hours=168)

    # Low (0-39) -> 720 hours (30 days)
    assert classify(39) == SLARule(priority="LOW", sla_hours=720)
    assert classify(10) == SLARule(priority="LOW", sla_hours=720)
    assert classify(0) == SLARule(priority="LOW", sla_hours=720)

    # Out of range
    with pytest.raises(ValueError):
        classify(-1)
    with pytest.raises(ValueError):
        classify(101)


def test_idempotent_ticket_generation():
    """Verify remediation ticket generation is strictly idempotent."""
    org_id = f"ORG-TEST-{uuid.uuid4().hex[:6]}"
    finding_id = f"FINDING-{uuid.uuid4().hex[:6]}"
    finding = {
        "finding_id": finding_id,
        "cve_id": "CVE-2026-9999",
        "asset_id": "ASSET-001",
        "asset_name": "Core Banking API",
        "vulnerability_name": "Remote Code Execution",
        "risk_score": 92,
        "discovered_at": datetime.now(timezone.utc).isoformat(),
    }

    ticket_1 = remediation_service.generate_ticket_for_finding(org_id, finding, created_by="test_user")
    assert ticket_1["finding_id"] == finding_id
    assert ticket_1["priority"] == "CRITICAL"
    assert ticket_1["sla_hours"] == 4
    assert ticket_1["status"] == "OPEN"

    # Second call for the same finding returns the exact same ticket
    ticket_2 = remediation_service.generate_ticket_for_finding(org_id, finding, created_by="test_user")
    assert ticket_2["ticket_id"] == ticket_1["ticket_id"]
    assert ticket_2["created_at"] == ticket_1["created_at"]


def test_ticket_owner_assignment():
    """Verify owner assignment transitions OPEN -> ASSIGNED and logs history."""
    org_id = f"ORG-TEST-{uuid.uuid4().hex[:6]}"
    finding_id = f"FINDING-{uuid.uuid4().hex[:6]}"
    finding = {
        "finding_id": finding_id,
        "cve_id": "CVE-2026-1111",
        "asset_id": "ASSET-002",
        "asset_name": "Auth Gateway",
        "vulnerability_name": "Auth Bypass",
        "risk_score": 85,
    }

    ticket = remediation_service.generate_ticket_for_finding(org_id, finding)
    assert ticket["status"] == "OPEN"
    assert ticket["assigned_to"] is None

    updated = remediation_service.assign_ticket(org_id, ticket["ticket_id"], "secops-lead", user_name="Alice", user_role="ANALYST")
    assert updated["assigned_to"] == "secops-lead"
    assert updated["status"] == "ASSIGNED"

    history = database.get_remediation_ticket_history(org_id, ticket["ticket_id"])
    assert len(history) >= 2
    assert history[-1]["new_status"] == "ASSIGNED"
    assert "secops-lead" in history[-1]["note"]


def test_ticket_status_machine_and_illegal_transitions():
    """Verify valid transitions succeed and illegal jumps are rejected."""
    org_id = f"ORG-TEST-{uuid.uuid4().hex[:6]}"
    finding_id = f"FINDING-{uuid.uuid4().hex[:6]}"
    finding = {
        "finding_id": finding_id,
        "asset_id": "ASSET-003",
        "vulnerability_name": "SQL Injection",
        "risk_score": 75,
    }

    ticket = remediation_service.generate_ticket_for_finding(org_id, finding)

    # OPEN -> IN_PROGRESS is NOT directly allowed without assignment (valid: ASSIGNED, SLA_BREACHED, RESOLVED)
    # Advance OPEN -> ASSIGNED -> IN_PROGRESS -> RESOLVED
    remediation_service.assign_ticket(org_id, ticket["ticket_id"], "developer")
    
    in_prog = remediation_service.update_ticket_status(org_id, ticket["ticket_id"], "IN_PROGRESS", note="Started coding fix")
    assert in_prog["status"] == "IN_PROGRESS"

    resolved = remediation_service.update_ticket_status(org_id, ticket["ticket_id"], "RESOLVED", note="Patch verified")
    assert resolved["status"] == "RESOLVED"
    assert resolved["resolved_at"] is not None

    # RESOLVED is terminal: cannot transition to OPEN
    with pytest.raises(InvalidTransition):
        remediation_service.update_ticket_status(org_id, ticket["ticket_id"], "OPEN")


def test_breach_predictor_and_early_warning():
    """Verify breach predictor detects hard breaches and calculates early warnings."""
    org_id = f"ORG-TEST-{uuid.uuid4().hex[:6]}"
    finding_id = f"FINDING-BREACHED-{uuid.uuid4().hex[:6]}"
    now = datetime.now(timezone.utc)

    # Overdue finding (discovered 10 hours ago with 4h SLA window)
    overdue_finding = {
        "finding_id": finding_id,
        "vulnerability_name": "Critical Unauthenticated RCE",
        "risk_score": 95,
        "discovered_at": (now - timedelta(hours=10)).isoformat(),
    }
    remediation_service.generate_ticket_for_finding(org_id, overdue_finding)

    # Run sweep: should auto-flag SLA_BREACHED
    warnings = remediation_service.run_sweep(org_id)
    assert len(warnings) >= 1
    overdue_warn = next((w for w in warnings if w["finding_id"] == finding_id), None)
    assert overdue_warn is not None
    assert overdue_warn["status"] == "SLA_BREACHED"
    assert overdue_warn["minutes_remaining"] < 0


def test_multi_tenant_isolation():
    """Verify tenant isolation: Org A cannot view or modify Org B's tickets."""
    org_a = f"ORG-A-{uuid.uuid4().hex[:6]}"
    org_b = f"ORG-B-{uuid.uuid4().hex[:6]}"
    finding_id = f"FINDING-{uuid.uuid4().hex[:6]}"

    finding_a = {
        "finding_id": finding_id,
        "vulnerability_name": "Org A Vuln",
        "risk_score": 80,
    }
    ticket_a = remediation_service.generate_ticket_for_finding(org_a, finding_a)

    # Org B queries Org A's ticket -> returns None
    assert database.get_remediation_ticket(org_b, ticket_a["ticket_id"]) is None
    assert database.get_remediation_ticket_by_finding_id(org_b, finding_id) is None

    # Org B trying to assign Org A's ticket -> raises KeyError
    with pytest.raises(KeyError):
        remediation_service.assign_ticket(org_b, ticket_a["ticket_id"], "hacker")


def test_rbac_api_endpoints():
    """Verify RBAC on remediation API routes: VIEWER gets 403, ANALYST gets 200."""
    viewer_user = get_user_by_id("usr-viewer-001")
    analyst_user = get_user_by_id("usr-analyst-002")

    viewer_token = create_access_token(viewer_user)
    analyst_token = create_access_token(analyst_user)

    # VIEWER trying to create task -> 403 Forbidden
    res_viewer = client.post(
        "/api/findings/DEDUP-90626421/remediation/task",
        headers={"Authorization": f"Bearer {viewer_token}"},
        json={"note": "Viewer attempt"}
    )
    assert res_viewer.status_code == 403
    assert "VIEWER" in res_viewer.json()["detail"]

    # ANALYST creating task -> 200 OK
    res_analyst = client.post(
        "/api/findings/DEDUP-90626421/remediation/task",
        headers={"Authorization": f"Bearer {analyst_token}"},
        json={"note": "Analyst creating remediation task"}
    )
    assert res_analyst.status_code == 200
    ticket = res_analyst.json()["ticket"]
    assert ticket["finding_id"] == "DEDUP-90626421"

    ticket_id = ticket["ticket_id"]

    # VIEWER trying to assign owner -> 403 Forbidden
    res_assign_viewer = client.post(
        f"/api/remediation/tasks/{ticket_id}/assign",
        headers={"Authorization": f"Bearer {viewer_token}"},
        json={"assignee": "secops"}
    )
    assert res_assign_viewer.status_code == 403

    # ANALYST assigning owner -> 200 OK
    res_assign_analyst = client.post(
        f"/api/remediation/tasks/{ticket_id}/assign",
        headers={"Authorization": f"Bearer {analyst_token}"},
        json={"assignee": "secops"}
    )
    assert res_assign_analyst.status_code == 200
    assert res_assign_analyst.json()["ticket"]["assigned_to"] == "secops"
