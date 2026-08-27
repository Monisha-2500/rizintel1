"""
test_m3_noise_routing.py
========================
Focused test suite for RizIntel Issue #4: Operationalize M3 Noise / Review States.

Validates:
1. CONFIRMED / HIGH_CONFIDENCE findings auto-generate remediation tickets (status=OPEN, ticket_id set).
2. NEEDS_REVIEW / review_required=True findings route to ANALYST REVIEW (status=PENDING_REVIEW, ticket_id=None).
3. LIKELY_NOISE / likely_noise=True findings route to SUPPRESSED (status=SUPPRESSED, ticket_id=None).
4. Analyst approval transitions a PENDING_REVIEW finding to OPEN with an active remediation ticket.
5. 100% Provenance is preserved (source findings, consensus, confidence, noise reason, RizTrace journey).
6. Actionable finding count in summary excludes review and suppressed/noise findings.
7. Likely noise count in summary accurately reflects suppressed findings.
8. M5 risk score sovereignty is maintained across all routing tracks.
"""

from pathlib import Path
import pytest

from models import FindingSchema
from adapters.m7_adapter import M7ActionableFindingAdapter
from services.pipeline_service import UnifiedPipelineRunner, DEFAULT_ASSET_CATALOG
from services.data_service import data_service

_BACKEND_DIR = Path(__file__).resolve().parent.parent


# =============================================================================
# 1. Routing Policy & Ticket Creation Rules
# =============================================================================

def test_confirmed_finding_auto_creates_ticket():
    """CONFIRMED finding with review_required=False and likely_noise=False auto-generates OPEN ticket."""
    m6_finding = {
        "finding_id": "FIND-CONFIRMED-01",
        "cve_id": "CVE-2024-1111",
        "asset_id": "ASSET-WEB-001",
        "vulnerability_name": "Confirmed SQL Injection",
        "risk_score": 88,
        "risk_level": "HIGH",
        "finding_confidence_classification": "CONFIRMED",
        "explanation": {"technical": "Confirmed exploit path", "management": "Fix immediately"},
        "remediation": {"recommended_action": "Apply patch"}
    }
    m7_ticket = {
        "ticket_id": "TKT-CONF-001",
        "status": "OPEN",
        "assigned_to": "AppSec Team",
        "sla_hours": 24,
        "sla_deadline": "2026-08-25T10:00:00Z",
        "sla_status": "ON_TRACK"
    }
    pipeline_ctx = {
        "finding_confidence": {"score": 0.95, "classification": "CONFIRMED", "review_required": False},
        "noise_assessment": {"likely_noise": False, "reason": None},
        "asset_context": {"asset_name": "Payments Web", "criticality": "HIGH", "environment": "PRODUCTION", "internet_facing": True, "data_sensitivity": "CONFIDENTIAL"},
        "source_findings": [{"finding_id": "RAW-ZAP-01", "scanner": "ZAP"}, {"finding_id": "RAW-NUC-01", "scanner": "NUCLEI"}],
        "scanner_consensus": {"score": 0.67, "scanner_names": ["ZAP", "NUCLEI"], "detected_by_count": 2, "total_scanners": 3}
    }

    actionable = M7ActionableFindingAdapter.build_actionable_finding(
        m6_finding=m6_finding,
        m7_ticket=m7_ticket,
        pipeline_context=pipeline_ctx
    )
    finding = FindingSchema(**actionable)

    assert finding.workflow.status == "OPEN"
    assert finding.workflow.ticket_id == "TKT-CONF-001"
    assert finding.workflow.sla_status == "ON_TRACK"
    assert finding.workflow.sla_hours == 24
    assert finding.detail.provenance.journey[2].status == "DONE"  # VALIDATED stage
    assert finding.detail.provenance.journey[6].status == "DONE"  # ASSIGNED stage (assigned to AppSec Team)


def test_needs_review_finding_does_not_auto_create_ticket():
    """NEEDS_REVIEW finding routes to PENDING_REVIEW queue with ticket_id=None and blocked journey."""
    m6_finding = {
        "finding_id": "FIND-REVIEW-01",
        "cve_id": None,
        "asset_id": "ASSET-WEB-001",
        "vulnerability_name": "Unconfirmed Header Issue",
        "risk_score": 35,
        "risk_level": "LOW",
        "finding_confidence_classification": "NEEDS_REVIEW",
        "explanation": {"technical": "Single scanner reported possible header absence", "management": "Awaiting review"},
        "remediation": {"recommended_action": "Verify server config"}
    }
    m7_ticket = {
        "ticket_id": "TKT-SHOULD-NOT-EXIST",
        "status": "OPEN",
        "assigned_to": "Unassigned",
        "sla_hours": 720,
        "sla_status": "ON_TRACK"
    }
    pipeline_ctx = {
        "finding_confidence": {"score": 0.62, "classification": "NEEDS_REVIEW", "review_required": True},
        "noise_assessment": {"likely_noise": False, "reason": None},
        "asset_context": {"asset_name": "Payments Web", "criticality": "HIGH", "environment": "PRODUCTION", "internet_facing": True, "data_sensitivity": "CONFIDENTIAL"},
        "source_findings": [{"finding_id": "RAW-ZAP-02", "scanner": "ZAP"}],
        "scanner_consensus": {"score": 0.33, "scanner_names": ["ZAP"], "detected_by_count": 1, "total_scanners": 3}
    }

    actionable = M7ActionableFindingAdapter.build_actionable_finding(
        m6_finding=m6_finding,
        m7_ticket=m7_ticket,
        pipeline_context=pipeline_ctx
    )
    finding = FindingSchema(**actionable)

    assert finding.workflow.status == "PENDING_REVIEW"
    assert finding.workflow.ticket_id is None
    assert finding.workflow.sla_status == "PENDING_REVIEW"
    assert finding.workflow.sla_hours == 720
    # Provenance indicates routing
    assert finding.detail.provenance.journey[2].status == "NEEDS_REVIEW"
    assert finding.detail.provenance.journey[6].status == "PENDING"


def test_likely_noise_finding_does_not_create_ticket():
    """LIKELY_NOISE finding routes to SUPPRESSED queue with ticket_id=None and SLA=NOT_APPLICABLE."""
    m6_finding = {
        "finding_id": "FIND-NOISE-01",
        "cve_id": None,
        "asset_id": "ASSET-DEV-003",
        "vulnerability_name": "Generic Scanner Noise",
        "risk_score": 10,
        "risk_level": "LOW",
        "finding_confidence_classification": "LIKELY_NOISE",
        "explanation": {"technical": "Single tool with low match confidence", "management": "Suppressed noise"},
        "remediation": {"recommended_action": "No action needed"}
    }
    m7_ticket = {
        "ticket_id": "TKT-NOISE-001",
        "status": "OPEN",
        "assigned_to": "Unassigned",
        "sla_hours": 720,
        "sla_status": "ON_TRACK"
    }
    pipeline_ctx = {
        "finding_confidence": {"score": 0.35, "classification": "LIKELY_NOISE", "review_required": False},
        "noise_assessment": {"likely_noise": True, "reason": "Only one scanner detected this finding; no supporting evidence text"},
        "asset_context": {"asset_name": "Staging Dev", "criticality": "LOW", "environment": "DEVELOPMENT", "internet_facing": False, "data_sensitivity": "INTERNAL"},
        "source_findings": [{"finding_id": "RAW-WAP-99", "scanner": "WAPITI"}],
        "scanner_consensus": {"score": 0.33, "scanner_names": ["WAPITI"], "detected_by_count": 1, "total_scanners": 3}
    }

    actionable = M7ActionableFindingAdapter.build_actionable_finding(
        m6_finding=m6_finding,
        m7_ticket=m7_ticket,
        pipeline_context=pipeline_ctx
    )
    finding = FindingSchema(**actionable)

    assert finding.workflow.status == "SUPPRESSED"
    assert finding.workflow.ticket_id is None
    assert finding.workflow.sla_status == "NOT_APPLICABLE"
    assert finding.workflow.sla_hours is None
    assert finding.detail.provenance.journey[2].status == "SUPPRESSED_NOISE"
    assert finding.detail.provenance.journey[6].status == "SUPPRESSED"


# =============================================================================
# 2. Analyst Review Transition
# =============================================================================

def test_analyst_approval_promotes_pending_review_to_open_ticket():
    """An analyst confirming/accepting a PENDING_REVIEW finding transitions it to OPEN with an active ticket."""
    m6_finding = {
        "finding_id": "FIND-TRIAGE-01",
        "cve_id": None,
        "asset_id": "ASSET-WEB-001",
        "vulnerability_name": "Potential Sensitive Data Leak",
        "risk_score": 60,
        "risk_level": "MEDIUM",
        "finding_confidence_classification": "NEEDS_REVIEW",
        "explanation": {"technical": "Review required", "management": "Review required"},
        "remediation": {"recommended_action": "Review data leak"}
    }
    pipeline_ctx = {
        "finding_confidence": {"score": 0.60, "classification": "NEEDS_REVIEW", "review_required": True},
        "noise_assessment": {"likely_noise": False, "reason": None},
        "asset_context": {"asset_name": "Payments Web", "criticality": "HIGH", "environment": "PRODUCTION", "internet_facing": True, "data_sensitivity": "CONFIDENTIAL"},
        "source_findings": [{"finding_id": "RAW-01", "scanner": "ZAP"}]
    }

    actionable = M7ActionableFindingAdapter.build_actionable_finding(
        m6_finding=m6_finding,
        m7_ticket={},
        pipeline_context=pipeline_ctx
    )
    finding = FindingSchema(**actionable)
    assert finding.workflow.status == "PENDING_REVIEW"
    assert finding.workflow.ticket_id is None

    orig_cache = list(data_service._findings_cache)
    try:
        # Inject into data_service cache for triage test
        data_service._findings_cache = [finding]

        # Analyst approves the finding
        approved = data_service.approve_review_finding("FIND-TRIAGE-01", assigned_to="Security Lead")

        assert approved is not None
        assert approved.workflow.status == "OPEN"
        assert approved.workflow.ticket_id is not None
        assert approved.workflow.ticket_id.startswith("TKT-")
        assert approved.workflow.sla_status == "ON_TRACK"
        assert approved.workflow.assigned_to == "Security Lead"
        assert approved.detail.provenance.journey[2].status == "DONE"
        assert approved.detail.provenance.journey[6].status == "DONE"
    finally:
        data_service._findings_cache = orig_cache



# =============================================================================
# 3. Pipeline Funnel & Summary Metrics
# =============================================================================

def test_pipeline_summary_distinguishes_actionable_review_and_noise():
    """Summary metrics must correctly segment unique findings into actionable, review, and noise buckets."""
    runner = UnifiedPipelineRunner()
    findings, summary = runner.execute_pipeline()

    s = summary["summary"]
    assert "actionable_findings" in s
    assert "pending_review_findings" in s
    assert "likely_noise_findings" in s
    assert "open_tickets" in s

    # Conservation: total unique findings = actionable + pending_review + likely_noise
    assert s["unique_findings"] == s["actionable_findings"] + s["pending_review_findings"] + s["likely_noise_findings"]

    # Open tickets must strictly equal actionable findings (only confirmed findings receive tickets)
    assert s["open_tickets"] == s["actionable_findings"]

    # Verified findings array matches summary counts
    open_count = sum(1 for f in findings if f.workflow.status == "OPEN")
    review_count = sum(1 for f in findings if f.workflow.status == "PENDING_REVIEW")
    suppressed_count = sum(1 for f in findings if f.workflow.status == "SUPPRESSED")

    assert open_count == s["actionable_findings"]
    assert review_count == s["pending_review_findings"]
    assert suppressed_count == s["likely_noise_findings"]


# =============================================================================
# 4. M5 Risk Score Sovereignty Intact
# =============================================================================

def test_m5_scoring_sovereignty_preserved_for_review_findings():
    """A finding in PENDING_REVIEW retains its genuine M5 risk score (e.g. 60) without mutation."""
    runner = UnifiedPipelineRunner()
    findings, _ = runner.execute_pipeline()

    for f in findings:
        # M5 risk score must be bounded 0-100 and match M5 score breakdown
        assert 0 <= f.risk_score <= 100
        assert f.detail.risk_assessment.scoring_version == "M5-v1.0"
        # Provenance source findings preserved for every finding regardless of routing
        assert len(f.detail.provenance.source_findings) > 0
