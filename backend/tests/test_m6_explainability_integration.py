import pytest
from datetime import datetime, timezone
from models import Explanation, FindingDetail, FindingSchema
from adapters.m7_adapter import M7ActionableFindingAdapter


def test_m6_explanation_pydantic_model_backward_compatibility():
    """Verify Explanation model deserializes legacy records without generated_at or references."""
    # Legacy data without generated_at or references
    legacy_data = {
        "technical": "Legacy technical rationale.",
        "management": "Legacy management summary.",
        "top_risk_drivers": ["HIGH_CVSS", "INTERNET_FACING"],
    }
    exp = Explanation(**legacy_data)
    assert exp.technical == "Legacy technical rationale."
    assert exp.management == "Legacy management summary."
    assert exp.top_risk_drivers == ["HIGH_CVSS", "INTERNET_FACING"]
    assert exp.generated_at is None
    assert exp.references == []

    # New M6 data with generated_at and references
    m6_data = {
        "technical": "Modern technical rationale.",
        "management": "Modern management summary.",
        "top_risk_drivers": ["CRITICAL_ASSET", "KEV_LISTED"],
        "generated_at": "2026-08-27T12:00:00Z",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"],
    }
    exp2 = Explanation(**m6_data)
    assert exp2.generated_at == "2026-08-27T12:00:00Z"
    assert exp2.references == ["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"]


def test_m7_adapter_preserves_m6_explanation_and_m5_risk_score():
    """Verify m7_adapter preserves M6 explanation fields and does not mutate M5 risk score."""
    m6_sample = {
        "finding_id": "DEDUP-90626421",
        "cve_id": "CVE-2021-44228",
        "risk_score": 68,
        "risk_level": "HIGH",
        "score_breakdown": {
            "cvss_contribution": 20,
            "epss_contribution": 14,
            "kev_contribution": 15,
            "exploit_contribution": 0,
            "asset_criticality_contribution": 8,
            "exposure_contribution": 10,
            "scanner_confidence_contribution": 8,
        },
        "explanation": {
            "technical": "Remote Code Execution vulnerability in Log4j core on asset ERP-PROD-APP01.",
            "management": "Critical Log4Shell exposure on production ERP application requiring immediate action.",
            "top_risk_drivers": ["CRITICAL_ASSET", "KEV_LISTED", "INTERNET_FACING"],
            "generated_at": "2026-08-27T14:00:00Z",
            "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"],
        },
        "remediation": {
            "recommended_action": "Upgrade org.apache.logging.log4j:log4j-core to version 2.17.1 or newer.",
            "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"],
            "suggested_priority": "HIGH",
        },
        "generated_at": "2026-08-27T14:00:00Z",
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"],
    }

    m7_ticket = {
        "ticket_id": "TICK-9062",
        "status": "OPEN",
        "assigned_to": "secops",
        "sla_hours": 168,
        "sla_due_at": "2026-09-03T14:00:00Z",
        "sla_status": "ON_TRACK",
        "priority": "MEDIUM",
    }

    pipeline_ctx = {
        "asset_id": "AST-ERP-001",
        "vulnerability_name": "Apache Log4j Remote Code Execution (Log4Shell)",
        "vulnerability_type": "RCE",
        "risk_score": 68,
        "risk_level": "HIGH",
        "asset_context": {
            "asset_name": "ERP-PROD-APP01",
            "criticality": "HIGH",
            "environment": "PRODUCTION",
            "internet_facing": True,
            "data_sensitivity": "CONFIDENTIAL",
        },
        "threat_intelligence": {
            "cve_id": "CVE-2021-44228",
            "cvss_score": 9.1,
            "epss_score": 0.91,
            "kev_listed": True,
            "exploit_available": False,
        },
        "scanner_consensus": {
            "score": 0.95,
            "scanner_names": ["Nuclei"],
            "detected_by_count": 1,
            "total_scanners": 3,
        },
        "finding_confidence": {
            "score": 0.85,
            "classification": "HIGH_CONFIDENCE",
        },
        "risk_assessment": {
            "score_breakdown": m6_sample["score_breakdown"],
            "scoring_version": "M5-v1.0",
        },
        "provenance": {
            "source_findings": [
                {
                    "finding_id": "NUC-001",
                    "scanner": "Nuclei",
                    "timestamp": "2026-08-27T13:55:00Z",
                }
            ]
        },
    }

    actionable_dict = M7ActionableFindingAdapter.build_actionable_finding(
        m6_finding=m6_sample,
        m7_ticket=m7_ticket,
        pipeline_context=pipeline_ctx,
    )

    # 1. Passthrough M5 immutability: risk_score must remain 68 and risk_level HIGH
    assert actionable_dict["risk_score"] == 68
    assert actionable_dict["risk_level"] == "HIGH"

    # 2. M7 SLA assignment must govern operational priority
    assert actionable_dict["workflow"]["sla_hours"] == 168
    assert actionable_dict["workflow"]["sla_status"] == "ON_TRACK"

    # 3. Explanation detail preservation
    finding_obj = FindingSchema(**actionable_dict)
    exp = finding_obj.detail.explanation
    assert exp.technical.startswith("Remote Code Execution")
    assert exp.management.startswith("Critical Log4Shell")
    assert exp.top_risk_drivers == ["CRITICAL_ASSET", "KEV_LISTED", "INTERNET_FACING"]
    assert exp.generated_at == "2026-08-27T14:00:00Z"
    assert exp.references == ["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"]
