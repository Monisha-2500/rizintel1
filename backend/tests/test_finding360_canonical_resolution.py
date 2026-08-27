"""
test_finding360_canonical_resolution.py
======================================
Automated integration and regression tests for Finding360 / Canonical Scan-Run Finding
ID resolution, multi-tenant safety, provenance preservation, and audit trail integrity.
"""

from __future__ import annotations

import os
import sys
import json
import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from main import app
import database
from auth import create_access_token, UserRole, User

client = TestClient(app)

ORG_A = "ORG-TEST-CANONICAL-A"
ORG_B = "ORG-TEST-CANONICAL-B"
USER_A = "usr-test-canon-a"
USER_B = "usr-test-canon-b"

user_obj_a = User(
    user_id=USER_A,
    email="usera@canonical.test",
    display_name="User A",
    role=UserRole.ANALYST,
    password_hash="h",
    is_active=True,
    created_at="2026-08-20T00:00:00Z"
)

user_obj_b = User(
    user_id=USER_B,
    email="userb@canonical.test",
    display_name="User B",
    role=UserRole.ANALYST,
    password_hash="h",
    is_active=True,
    created_at="2026-08-20T00:00:00Z"
)


@pytest.fixture(scope="module", autouse=True)
def setup_test_data():
    # 1. Create or get test organizations
    if not database.get_organization(ORG_A):
        database.create_organization(ORG_A, "Canonical Test Org A")
    if not database.get_organization(ORG_B):
        database.create_organization(ORG_B, "Canonical Test Org B")

    # 2. Add memberships
    database.upsert_membership("mem-ca-1", ORG_A, USER_A, UserRole.ANALYST.value)
    database.upsert_membership("mem-cb-1", ORG_B, USER_B, UserRole.ANALYST.value)

    # 3. Create asset and scan run in Org A
    if not database.get_registered_asset(ORG_A, "ASSET-CANON-01"):
        database.create_registered_asset(
            asset_id="ASSET-CANON-01",
            organization_id=ORG_A,
            display_name="Payment API Service",
            host="pay.canonical.test",
            normalized_host="pay.canonical.test",
            port=443,
            criticality="HIGH",
            environment="PRODUCTION",
            internet_facing=True,
            data_sensitivity="CONFIDENTIAL",
            created_by=USER_A
        )

    if not database.get_scan_run(ORG_A, "SR-CANONICAL-TEST"):
        database.create_scan_run(
            scan_run_id="SR-CANONICAL-TEST",
            organization_id=ORG_A,
            asset_id="ASSET-CANON-01",
            scanner_selections=["ZAP", "NUCLEI", "WAPITI"],
            created_by_user_id=USER_A,
            data_origin="LIVE_SCAN"
        )

    # 4. Persist canonical scan run results in Org A
    findings_payload = [
        {
            "schema_version": "1.0",
            "finding_id": "DEDUP-TEST-SQLI",
            "cve_id": None,
            "asset_id": "ASSET-CANON-01",
            "vulnerability_name": "SQL Injection in Search Endpoint",
            "vulnerability_type": "SQL_INJECTION",
            "risk_score": 30,
            "risk_level": "MEDIUM",
            "confidence_classification": "NEEDS_REVIEW",
            "asset_criticality": "HIGH",
            "internet_exposure": True,
            "recommended_action": "Apply parameterized statements.",
            "workflow": {
                "ticket_id": None,
                "status": "PENDING_REVIEW",
                "assigned_to": None,
                "sla_hours": 720,
                "sla_due_at": None,
                "sla_status": "PENDING_REVIEW",
                "escalation_level": 0
            },
            "discovered_at": "2026-08-26T14:18:50Z",
            "updated_at": "2026-08-26T19:46:00Z",
            "detail": {
                "scanner_consensus": {
                    "score": 0.67,
                    "scanner_names": ["NUCLEI", "ZAP"],
                    "detected_by_count": 2,
                    "total_scanners": 3
                },
                "finding_confidence": {
                    "score": 0.7325,
                    "classification": "NEEDS_REVIEW"
                },
                "threat_intelligence": {
                    "cvss_score": None,
                    "epss_score": None,
                    "kev_listed": False,
                    "exploit_available": False
                },
                "asset_context": {
                    "asset_name": "Payment API Service",
                    "environment": "PRODUCTION",
                    "criticality": "HIGH",
                    "internet_facing": True,
                    "data_sensitivity": "CONFIDENTIAL"
                },
                "risk_assessment": {
                    "score_breakdown": {
                        "cvss_contribution": 5.0,
                        "epss_contribution": 2.0,
                        "kev_contribution": 0.0,
                        "exploit_contribution": 0.0,
                        "asset_criticality_contribution": 8.0,
                        "exposure_contribution": 10.0,
                        "scanner_confidence_contribution": 5.0
                    },
                    "scoring_version": "M5-v1.0"
                },
                "explanation": {
                    "technical": "SQL Injection on Payment API Service scored 30.0/100 (MEDIUM).",
                    "management": "A medium-risk security finding was identified on Payment API Service.",
                    "top_risk_drivers": ["INTERNET_FACING", "CRITICAL_ASSET"]
                },
                "provenance": {
                    "source_findings": [
                        {"finding_id": "ZAP-raw-001", "scanner": "ZAP"},
                        {"finding_id": "NUCLEI-raw-002", "scanner": "NUCLEI"}
                    ],
                    "journey": [
                        {"stage": "DETECTED", "status": "DONE"},
                        {"stage": "CORRELATED", "status": "DONE"},
                        {"stage": "VALIDATED", "status": "NEEDS_REVIEW"}
                    ]
                }
            }
        }
    ]

    summary_payload = {
        "raw_finding_count": 2,
        "canonical_finding_count": 1,
        "expected_scanners": ["ZAP", "NUCLEI", "WAPITI"],
        "received_scanners": ["ZAP", "NUCLEI"]
    }

    database.save_scan_run_results(
        result_id="RES-CANONICAL-01",
        organization_id=ORG_A,
        scan_run_id="SR-CANONICAL-TEST",
        asset_id="ASSET-CANON-01",
        raw_finding_count=2,
        canonical_finding_count=1,
        findings_json=json.dumps(findings_payload),
        summary_json=json.dumps(summary_payload)
    )

    yield


def test_01_user_a_can_retrieve_canonical_finding_by_id():
    token_a = create_access_token(user_obj_a)
    res = client.get("/api/findings/DEDUP-TEST-SQLI", headers={"Authorization": f"Bearer {token_a}"})
    assert res.status_code == 200
    data = res.json()
    assert data["finding_id"] == "DEDUP-TEST-SQLI"
    assert data["vulnerability_name"] == "SQL Injection in Search Endpoint"
    assert data["risk_score"] == 30
    assert data["risk_level"] == "MEDIUM"
    assert data["confidence_classification"] == "NEEDS_REVIEW"
    assert len(data["detail"]["provenance"]["source_findings"]) == 2
    assert data["detail"]["scanner_consensus"]["scanner_names"] == ["NUCLEI", "ZAP"]


def test_02_pipeline_endpoint_resolves_canonical_finding_for_user_a():
    token_a = create_access_token(user_obj_a)
    res = client.get("/api/integration/pipeline/findings/DEDUP-TEST-SQLI", headers={"Authorization": f"Bearer {token_a}"})
    assert res.status_code == 200
    data = res.json()
    assert data["finding_id"] == "DEDUP-TEST-SQLI"


def test_03_tenant_isolation_user_b_cannot_access_org_a_canonical_finding():
    # User B is in ORG_B only. Should receive 404 Not Found when attempting to access Org A's scan finding
    token_b = create_access_token(user_obj_b)
    res = client.get("/api/findings/DEDUP-TEST-SQLI", headers={"Authorization": f"Bearer {token_b}"})
    assert res.status_code == 404


def test_04_nonexistent_finding_returns_404():
    token_a = create_access_token(user_obj_a)
    res = client.get("/api/findings/DEDUP-NONEXISTENT-999", headers={"Authorization": f"Bearer {token_a}"})
    assert res.status_code == 404


def test_05_analyst_decision_on_canonical_finding():
    token_a = create_access_token(user_obj_a)
    audit_body = {
        "analyst_action": "ACCEPT_PRIORITY",
        "rationale": "Analyst verified in staging environment.",
        "m5_risk_score": 30
    }
    res = client.post("/api/findings/DEDUP-TEST-SQLI/audit", headers={"Authorization": f"Bearer {token_a}"}, json=audit_body)
    assert res.status_code == 200
    data = res.json()
    assert data["finding_id"] == "DEDUP-TEST-SQLI"
    assert data["m5_risk_score"] == 30
    assert data["analyst_action"] == "ACCEPT_PRIORITY"
    assert data["event_hash"] is not None

    # Verify SHA-256 chain integrity
    v_res = client.get("/api/findings/DEDUP-TEST-SQLI/audit/verify", headers={"Authorization": f"Bearer {token_a}"})
    assert v_res.status_code == 200
    v_data = v_res.json()
    assert v_data["valid"] is True
    assert v_data["total"] >= 1
