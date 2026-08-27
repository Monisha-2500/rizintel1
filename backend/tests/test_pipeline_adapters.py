"""
test_pipeline_adapters.py
=========================
Integration and unit test suite for M1, M5, M7 adapters and UnifiedPipelineRunner.
Validates strict Schema v1.0 contract conformance, provenance retention,
and M5 score sovereignty.
"""

import os
import sys
import pytest
from pathlib import Path

# Add backend directory to sys.path
backend_dir = Path(__file__).resolve().parent.parent
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

from adapters.m1_adapter import M1NormalizedFindingAdapter
from adapters.m5_adapter import M5RiskEngineAdapter
from adapters.m7_adapter import M7ActionableFindingAdapter
from services.pipeline_service import UnifiedPipelineRunner
from models import FindingSchema


def test_m1_adapter_field_mapping():
    """Verify M1 adapter correctly maps fields and normalizes types."""
    raw_m1 = {
        "finding_id": "FIND-abcdef123456",
        "scanner": "ZAP",
        "cve": "CVE-2026-9999",
        "cwe": "CWE-89",
        "vulnerability_name": "SQL Injection in Login Endpoint",
        "severity": "High",
        "host": "http://payments.internal:8080",
        "endpoint": "/api/v1/auth",
        "parameter": "user",
        "description": "SQL Injection found via automated scan",
        "evidence": "' OR '1'='1",
        "timestamp": "2026-08-20T10:00:00Z",
    }

    adapted = M1NormalizedFindingAdapter.adapt_single(raw_m1, default_asset_id="ASSET-PAY-001")

    assert adapted["schema_version"] == "1.0"
    assert adapted["finding_id"] == "FIND-abcdef123456"
    assert adapted["cve_id"] == "CVE-2026-9999"
    assert adapted["vulnerability_type"] == "SQL_INJECTION"
    assert adapted["severity"] == "HIGH"
    assert adapted["asset_id"] == "ASSET-PAY-001"
    assert adapted["host"] == "payments.internal"
    assert adapted["port"] == 8080
    assert adapted["url"] == "http://payments.internal:8080/api/v1/auth"
    assert adapted["parameter"] == "user"


def test_m1_adapter_missing_cve():
    """Verify M1 adapter handles missing CVE gracefully."""
    raw_m1 = {
        "finding_id": "FIND-11112222",
        "scanner": "NUCLEI",
        "cve": None,
        "cwe": "CWE-1004",
        "vulnerability_name": "Missing Content-Security-Policy Header",
        "severity": "Low",
        "host": "example.com",
        "endpoint": "/",
    }

    adapted = M1NormalizedFindingAdapter.adapt_single(raw_m1)
    assert adapted["cve_id"] is None
    assert adapted["vulnerability_type"] == "SECURITY_HEADER"
    assert adapted["severity"] == "LOW"
    assert adapted["port"] == 80


def test_m5_adapter_input_and_output():
    """Verify M5 adapter formats inputs for M5 and translates to Section 8."""
    m4_output = {
        "schema_version": "1.0",
        "finding_id": "DEDUP-TEST-01",
        "cve_id": "CVE-2026-1234",
        "asset_id": "ASSET-WEB-001",
        "vulnerability_name": "SQL Injection",
        "vulnerability_type": "SQL_INJECTION",
        "scanner_sources": ["ZAP", "NUCLEI"],
        "scanner_consensus_score": 1.0,
        "finding_confidence_score": 0.95,
        "finding_confidence_classification": "CONFIRMED",
        "threat_intelligence": {
            "cvss_score": 9.0,
            "epss_score": 0.85,
            "epss_percentile": 0.95,
            "kev_listed": True,
            "exploit_available": None,  # M4 leaves as None -> adapter must handle safely
        }
    }

    asset_ctx = {
        "asset_id": "ASSET-WEB-001",
        "asset_name": "web-gateway",
        "environment": "PRODUCTION",
        "criticality": "CRITICAL",
        "internet_facing": True,
        "data_sensitivity": "PCI",
    }

    # Step 1: Input preparation
    m5_input = M5RiskEngineAdapter.prepare_m5_input(m4_output, asset_ctx)
    assert m5_input["schema_version"] == "1.0"
    assert m5_input["threat_intelligence"]["kev_listed"] is True
    assert m5_input["threat_intelligence"]["exploit_available"] is False  # Safe boolean fallback

    # Step 2: Simulate M5 output structure
    mock_m5_output = {
        "schema_version": "1.0",
        "scoring_version": "1.0",
        "finding_id": "DEDUP-TEST-01",
        "cve_id": "CVE-2026-1234",
        "vulnerability_name": "SQL Injection",
        "scanner_consensus": {
            "scanner_sources": ["ZAP", "NUCLEI"],
            "scanner_consensus_score": 1.0,
        },
        "finding_confidence": {
            "finding_confidence_score": 0.95,
            "finding_confidence_classification": "CONFIRMED",
        },
        "threat_intelligence": m5_input["threat_intelligence"],
        "asset_context": m5_input["asset_context"],
        "risk_assessment": {
            "risk_score": 94.0,
            "risk_level": "CRITICAL",
            "score_breakdown": {
                "cvss": {"input": 9.0, "points": 25},
                "epss": {"input": 0.85, "points": 20},
                "kev": {"input": True, "points": 15},
                "exploit_available": {"input": False, "points": 0},
                "asset_criticality": {"input": "CRITICAL", "points": 15},
                "internet_exposure": {"input": True, "points": 10},
                "finding_confidence": {"input": 0.95, "points": 9},
            },
            "risk_drivers": ["HIGH_CVSS", "HIGH_EPSS", "KEV_LISTED", "CRITICAL_ASSET"],
            "scoring_version": "M5-v1.0"
        },
        "metadata": {"generated_by": "M5", "timestamp": "2026-08-20T12:00:00Z"}
    }

    # Step 3: Adaptation to Section 8
    sec8 = M5RiskEngineAdapter.adapt_to_section8(mock_m5_output)
    assert sec8["schema_version"] == "1.0"
    assert sec8["risk_assessment"]["risk_score"] == 94.0
    assert sec8["risk_assessment"]["risk_level"] == "CRITICAL"
    assert sec8["risk_assessment"]["score_breakdown"]["cvss_contribution"] == 25.0
    assert sec8["risk_assessment"]["score_breakdown"]["epss_contribution"] == 20.0
    assert sec8["asset_context"]["criticality"] == "CRITICAL"
    assert sec8["asset_context"]["internet_facing"] is True


def test_m7_adapter_builds_valid_finding_schema():
    """Verify M7 adapter produces a valid FindingSchema object."""
    m6_finding = {
        "schema_version": "1.0",
        "finding_id": "DEDUP-0001",
        "cve_id": "CVE-2026-1234",
        "asset_id": "ASSET-WEB-001",
        "vulnerability_name": "SQL Injection",
        "risk_score": 94.0,
        "risk_level": "CRITICAL",
        "finding_confidence_classification": "CONFIRMED",
        "explanation": {
            "technical": "High exploitation likelihood with KEV listing.",
            "management": "Critical internet facing payment endpoint is exposed.",
            "top_risk_drivers": ["KEV_LISTED", "HIGH_EPSS"]
        },
        "remediation": {
            "recommended_action": "Apply patch and update WAF rules.",
            "priority": "IMMEDIATE",
            "references": ["https://nvd.nist.gov/vuln/detail/CVE-2026-1234"]
        },
        "generated_at": "2026-08-20T12:00:00Z",
    }

    m7_ticket = {
        "ticket_id": "VULN-0001",
        "status": "OPEN",
        "assigned_to": "Unassigned",
        "sla_hours": 4,
        "sla_deadline": "2026-08-20 16:00:00",
        "sla_status": "ON_TRACK",
    }

    pipeline_ctx = {
        "vulnerability_type": "SQL_INJECTION",
        "source_findings": [
            {"finding_id": "ZAP-001", "scanner": "ZAP"},
            {"finding_id": "NUCLEI-044", "scanner": "NUCLEI"}
        ],
        "scanner_consensus": {
            "score": 1.0,
            "scanner_names": ["ZAP", "NUCLEI"],
            "detected_by_count": 2,
            "total_scanners": 2,
        },
        "finding_confidence": {
            "score": 0.95,
            "classification": "CONFIRMED"
        },
        "threat_intelligence": {
            "cvss_score": 9.0,
            "epss_score": 0.85,
            "kev_listed": True,
            "exploit_available": False,
        },
        "asset_context": {
            "asset_name": "payments-prod-api-01",
            "environment": "PRODUCTION",
            "criticality": "CRITICAL",
            "internet_facing": True,
            "data_sensitivity": "PCI",
        },
        "risk_assessment": {
            "score_breakdown": {"cvss_contribution": 25.0, "epss_contribution": 20.0},
            "scoring_version": "M5-v1.0"
        }
    }

    actionable = M7ActionableFindingAdapter.build_actionable_finding(
        m6_finding=m6_finding,
        m7_ticket=m7_ticket,
        pipeline_context=pipeline_ctx
    )

    # Validate against M8 Pydantic FindingSchema
    finding_obj = FindingSchema(**actionable)
    assert finding_obj.finding_id == "DEDUP-0001"
    assert finding_obj.risk_score == 94
    assert finding_obj.risk_level == "CRITICAL"
    assert finding_obj.workflow.ticket_id == "VULN-0001"
    assert finding_obj.workflow.sla_hours == 4
    assert finding_obj.workflow.sla_status == "ON_TRACK"
    assert len(finding_obj.detail.provenance.source_findings) == 2
    assert finding_obj.detail.provenance.source_findings[0].finding_id == "ZAP-001"
    assert len(finding_obj.detail.provenance.journey) == 8


def test_end_to_end_pipeline_execution():
    """Verify full M1 -> M7 -> M8 execution with UnifiedPipelineRunner."""
    runner = UnifiedPipelineRunner()
    validated_findings, summary = runner.execute_pipeline()

    assert len(validated_findings) > 0
    assert summary["summary"]["raw_findings"] > 0
    assert summary["summary"]["unique_findings"] == len(validated_findings)
    assert summary["schema_version"] == "1.0"

    # Verify all findings satisfy strict FindingSchema
    for f in validated_findings:
        assert isinstance(f, FindingSchema)
        assert 0 <= f.risk_score <= 100
        assert f.risk_level in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
        if f.workflow.status == "OPEN":
            assert f.workflow.ticket_id is not None
        else:
            assert f.workflow.status in {"PENDING_REVIEW", "SUPPRESSED"}
            assert f.workflow.ticket_id is None
        assert len(f.detail.provenance.journey) == 8
        assert len(f.detail.provenance.source_findings) > 0
        assert f.detail.risk_assessment.scoring_version == "M5-v1.0"



def test_assigned_status_is_pending_when_unassigned():
    """Verify ASSIGNED stage in journey is PENDING when assigned_to is null or Unassigned."""
    m6_finding = {
        "schema_version": "1.0",
        "finding_id": "DEDUP-UNASSIGNED",
        "asset_id": "ASSET-01",
        "vulnerability_name": "Test Vuln",
        "risk_score": 50.0,
        "risk_level": "MEDIUM",
        "explanation": {"technical": "...", "management": "..."},
        "remediation": {"recommended_action": "...", "priority": "MEDIUM"},
    }

    # Case 1: Unassigned ticket
    m7_ticket_unassigned = {
        "ticket_id": "TKT-01",
        "status": "OPEN",
        "assigned_to": "Unassigned",
        "sla_hours": 24,
        "sla_deadline": "2026-08-21 12:00:00",
        "sla_status": "ON_TRACK",
    }
    actionable_unassigned = M7ActionableFindingAdapter.build_actionable_finding(
        m6_finding=m6_finding,
        m7_ticket=m7_ticket_unassigned,
        pipeline_context={}
    )
    assigned_stage_1 = next(s for s in actionable_unassigned["detail"]["provenance"]["journey"] if s["stage"] == "ASSIGNED")
    assert assigned_stage_1["status"] == "PENDING"
    assert actionable_unassigned["workflow"]["assigned_to"] is None

    # Case 2: Assigned ticket
    m7_ticket_assigned = {
        "ticket_id": "TKT-02",
        "status": "OPEN",
        "assigned_to": "alice@secops.corp",
        "sla_hours": 24,
        "sla_deadline": "2026-08-21 12:00:00",
        "sla_status": "ON_TRACK",
    }
    actionable_assigned = M7ActionableFindingAdapter.build_actionable_finding(
        m6_finding=m6_finding,
        m7_ticket=m7_ticket_assigned,
        pipeline_context={}
    )
    assigned_stage_2 = next(s for s in actionable_assigned["detail"]["provenance"]["journey"] if s["stage"] == "ASSIGNED")
    assert assigned_stage_2["status"] == "DONE"
    assert actionable_assigned["workflow"]["assigned_to"] == "alice@secops.corp"


def test_high_cvss_never_emitted_for_cvss_5_4():
    """Verify that HIGH_CVSS is never emitted as a risk driver when CVSS is 5.4."""
    from services.pipeline_service import _isolated_module_context
    with _isolated_module_context(backend_dir / "mem6"):
        from app.models.input_models import RiskAssessedFinding, ScoreBreakdown, RiskAssessment, AssetContext, ThreatIntelligence
        from app.services.risk_driver_service import extract_top_risk_drivers

        # Case with CVSS 5.4 (12 pts out of 25)
        finding_cvss_5_4 = RiskAssessedFinding(
            schema_version="1.0",
            finding_id="FIND-5.4",
            vulnerability_name="SQL Injection",
            asset_context=AssetContext(asset_id="AST-1", criticality="CRITICAL", internet_facing=True),
            threat_intelligence=ThreatIntelligence(cvss_score=5.4, epss_score=0.0159, kev_listed=False, exploit_available=False),
            risk_assessment=RiskAssessment(
                risk_score=44.0,
                risk_level="MEDIUM",
                score_breakdown=ScoreBreakdown(
                    cvss_contribution=12.0,
                    epss_contribution=2.0,
                    kev_contribution=0.0,
                    exploit_contribution=0.0,
                    asset_criticality_contribution=10.0,
                    exposure_contribution=10.0,
                    scanner_confidence_contribution=10.0
                )
            )
        )

        drivers = extract_top_risk_drivers(finding_cvss_5_4)
        assert "HIGH_CVSS" not in drivers
        assert "HIGH_EPSS" not in drivers
        assert "CRITICAL_ASSET" in drivers
        assert "INTERNET_FACING" in drivers


def test_clean_phrasing_without_duplicated_criticality():
    """Verify fallback management explanation does not produce 'CRITICAL-criticality'."""
    from services.pipeline_service import _isolated_module_context
    with _isolated_module_context(backend_dir / "mem6"):
        from app.models.input_models import RiskAssessedFinding, RiskAssessment, AssetContext
        from app.services.fallback_service import build_fallback_explanation

        finding = RiskAssessedFinding(
            schema_version="1.0",
            finding_id="FIND-CLEAN",
            vulnerability_name="SQL Injection",
            asset_context=AssetContext(asset_id="AST-1", asset_name="payments-api", criticality="CRITICAL", internet_facing=True),
            risk_assessment=RiskAssessment(risk_score=50.0, risk_level="MEDIUM")
        )

        res = build_fallback_explanation(finding)
        assert "CRITICAL-criticality" not in res.management
        assert "critical-criticality" not in res.management.lower()
        assert "a critical asset" in res.management


def test_fastapi_integration_endpoints():
    """Verify FastAPI integration router endpoints respond with valid Schema v1.0 data."""
    from fastapi.testclient import TestClient
    from main import app
    from users import get_user_by_email
    from auth import create_access_token

    client = TestClient(app)
    lead_user = get_user_by_email("lead@rizintel.demo")
    token = create_access_token(lead_user)
    headers = {"Authorization": f"Bearer {token}"}

    # 1. Health check
    health_resp = client.get("/api/integration/health")
    assert health_resp.status_code == 200
    health_data = health_resp.json()
    assert health_data["overall_status"] == "HEALTHY"
    assert len(health_data["modules"]) == 8

    # 2. Run pipeline endpoint
    run_resp = client.post("/api/integration/pipeline/run", headers=headers, json={"use_demo_dataset": True})
    assert run_resp.status_code == 200
    run_data = run_resp.json()
    assert run_data["status"] == "SUCCESS"
    assert run_data["total_findings"] > 0
    assert len(run_data["findings"]) == run_data["total_findings"]

    # 3. Get findings endpoint
    findings_resp = client.get("/api/integration/pipeline/findings", headers=headers)
    assert findings_resp.status_code == 200
    findings_list = findings_resp.json()
    assert len(findings_list) > 0
    first_fid = findings_list[0]["finding_id"]

    # 4. Get single finding detail
    single_resp = client.get(f"/api/integration/pipeline/findings/{first_fid}", headers=headers)
    assert single_resp.status_code == 200
    single_finding = single_resp.json()
    assert single_finding["finding_id"] == first_fid
    assert single_finding["schema_version"] == "1.0"
    assert single_finding["detail"]["risk_assessment"]["scoring_version"] == "M5-v1.0"

    # 5. Get pipeline summary
    summary_resp = client.get("/api/integration/pipeline/summary", headers=headers)
    assert summary_resp.status_code == 200
    summary_data = summary_resp.json()
    assert summary_data["schema_version"] == "1.0"
    assert "summary" in summary_data
