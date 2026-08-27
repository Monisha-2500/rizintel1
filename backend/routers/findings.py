from fastapi import APIRouter, HTTPException, Depends, status, Path, Header
from typing import List, Optional, Union
import re
import logging
from models import (
    FindingSchema,
    AnalystFeedbackInput,
    AuditEventCreate,
    AuditEventResponse,
    AuditVerifyResponse,
    compute_finding_fingerprint
)
from services.data_service import data_service
from auth import get_current_user, check_analyst_decision_permission, AuthenticatedUser, UserRole

logger = logging.getLogger("rizintel.findings")
router = APIRouter(prefix="/findings", tags=["Findings Operations"])

_FINDING_ID_PATTERN = re.compile(r"^[A-Za-z0-9_\-]{1,64}$")

def _validate_finding_id(finding_id: str) -> str:
    cleaned = (finding_id or "").strip()
    if not _FINDING_ID_PATTERN.match(cleaned):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid finding_id format. Must be alphanumeric with hyphens or underscores (max 64 characters)."
        )
    return cleaned


from fastapi import APIRouter, HTTPException, Depends, status, Path, Header, Query, Response

@router.get("", response_model=List[FindingSchema])
def list_findings(
    response: Response,
    organization_id: Optional[str] = Query(None, description="Organization ID to scope findings"),
    scan_run_id: Optional[str] = Query(None, description="Scan Run ID to scope findings"),
    x_data_source: Optional[str] = Header(None, alias="X-Data-Source"),
    limit: Optional[int] = Query(None, ge=1, le=1000, description="Maximum number of findings to return"),
    offset: Optional[int] = Query(None, ge=0, description="Number of findings to skip"),
    page: Optional[int] = Query(None, ge=1, description="1-indexed page number"),
    page_size: Optional[int] = Query(None, ge=1, le=1000, description="Items per page"),
    current_user: AuthenticatedUser = Depends(get_current_user)
):
    """Retrieve all normalized & correlated unique findings. Accessible to all authenticated roles."""
    all_findings = data_service.get_findings(
        source=x_data_source,
        user=current_user,
        organization_id=organization_id,
        scan_run_id=scan_run_id,
    )
    total = len(all_findings)
    response.headers["X-Total-Count"] = str(total)

    if page is not None and page_size is not None:
        start = (page - 1) * page_size
        end = start + page_size
        response.headers["X-Page"] = str(page)
        response.headers["X-Page-Size"] = str(page_size)
        response.headers["X-Total-Pages"] = str(max(1, (total + page_size - 1) // page_size))
        return all_findings[start:end]
    elif limit is not None or offset is not None:
        off = offset or 0
        lim = limit if limit is not None else total
        response.headers["X-Offset"] = str(off)
        response.headers["X-Limit"] = str(lim)
        return all_findings[off:off + lim]

    return all_findings


@router.get("/{finding_id}", response_model=FindingSchema)
def get_finding(
    finding_id: str = Path(..., min_length=1, max_length=64),
    organization_id: Optional[str] = Query(None, description="Organization ID to scope finding"),
    x_data_source: Optional[str] = Header(None, alias="X-Data-Source"),
    current_user: AuthenticatedUser = Depends(get_current_user)
):
    """Retrieve finding details for Finding 360 view. Accessible to all authenticated roles."""
    clean_id = _validate_finding_id(finding_id)
    finding = data_service.get_finding_by_id(
        clean_id,
        source=x_data_source,
        user=current_user,
        organization_id=organization_id,
    )
    if not finding:
        src_label = f" in {x_data_source.upper()} data source" if x_data_source else ""
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Finding '{clean_id}' not found{src_label}."
        )
    return finding


@router.post("/{finding_id}/audit", response_model=AuditEventResponse)
def create_audit_event(
    audit_in: AuditEventCreate,
    finding_id: str = Path(..., min_length=1, max_length=64),
    x_data_source: Optional[str] = Header(None, alias="X-Data-Source"),
    current_user: AuthenticatedUser = Depends(get_current_user)
):
    """
    Create a persistent, tamper-evident audit record for an analyst decision.
    RBAC Protected:
      - VIEWER: 403 Forbidden
      - ANALYST: Allowed for standard decisions, 403 for ESCALATE
      - SECURITY_LEAD / ADMIN: Allowed for all decisions
    Records authenticated actor + role + data_source + finding snapshot fingerprint into SHA-256 chain.
    """
    clean_id = _validate_finding_id(finding_id)
    action = audit_in.analyst_action or audit_in.analyst_decision or "ACCEPT_PRIORITY"
    
    # Enforce RBAC least privilege authorization
    check_analyst_decision_permission(current_user, action)

    # Resolve data source: header strictly enforces source when provided
    effective_source = x_data_source.strip().upper() if x_data_source else ""
    recorded_source = (x_data_source or audit_in.data_source or "LIVE").strip().upper()

    # Source-aware finding resolution with tenant scoping
    finding = data_service.get_finding_by_id(clean_id, source=effective_source, user=current_user)
    if not finding:
        source_label = effective_source if effective_source else "active"
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Finding '{clean_id}' not found in {source_label} data source."
        )
    
    m5_score = audit_in.m5_risk_score if audit_in.m5_risk_score is not None else finding.risk_score
    rationale = audit_in.rationale or audit_in.reason or ""
    actor_role_str = f"{current_user.display_name or current_user.username} [{current_user.role.value}]"
    snapshot_hash = audit_in.finding_snapshot_hash or compute_finding_fingerprint(finding)

    # Promote finding if in PENDING_REVIEW and decision is approval
    if action in {"ACCEPT_PRIORITY", "ESCALATE", "CONFIRM"}:
        data_service.approve_review_finding(clean_id, source=recorded_source)

    try:
        event = data_service.add_audit_event(
            finding_id=clean_id,
            analyst_action=action,
            m5_risk_score=m5_score,
            rationale=rationale,
            role=actor_role_str,
            timestamp=audit_in.timestamp,
            data_source=recorded_source,
            finding_snapshot_hash=snapshot_hash
        )
        return event
    except Exception as e:
        logger.exception("Failed to insert audit event for %s", clean_id)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to record audit event in cryptographic chain."
        )


@router.get("/{finding_id}/audit", response_model=List[AuditEventResponse])
def get_audit_trail(
    finding_id: str = Path(..., min_length=1, max_length=64),
    current_user: AuthenticatedUser = Depends(get_current_user)
):
    """Retrieve full persistent audit trail of analyst decisions for a finding from SQLite."""
    clean_id = _validate_finding_id(finding_id)
    return data_service.get_audit_events(clean_id)


@router.get("/{finding_id}/audit/verify", response_model=AuditVerifyResponse)
def verify_audit_trail(
    finding_id: str = Path(..., min_length=1, max_length=64),
    current_user: AuthenticatedUser = Depends(get_current_user)
):
    """Verify cryptographic SHA-256 chain integrity for the finding's audit trail."""
    clean_id = _validate_finding_id(finding_id)
    return data_service.verify_audit_trail(clean_id)


@router.post("/{finding_id}/feedback")
def submit_feedback(
    feedback: Union[AuditEventCreate, AnalystFeedbackInput],
    finding_id: str = Path(..., min_length=1, max_length=64),
    x_data_source: Optional[str] = Header(None, alias="X-Data-Source"),
    current_user: AuthenticatedUser = Depends(get_current_user)
):
    """
    Submit Human-in-the-loop analyst priority adjustment feedback.
    Enforces RBAC permissions based on user role.
    """
    clean_id = _validate_finding_id(finding_id)
    action = getattr(feedback, "analyst_action", None) or getattr(feedback, "analyst_decision", None) or "ACCEPT_PRIORITY"
    check_analyst_decision_permission(current_user, action)

    data_source = (x_data_source or getattr(feedback, "data_source", "LIVE") or "LIVE").strip().upper()

    finding = data_service.get_finding_by_id(clean_id, source=data_source)
    if not finding:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Finding '{clean_id}' not found in {data_source} data source."
        )
    actor_role_str = f"{current_user.display_name or current_user.username} [{current_user.role.value}]"
    try:
        return data_service.add_feedback(
            clean_id,
            feedback,
            m5_score=finding.risk_score,
            source=data_source,
            actor_role=actor_role_str
        )
    except Exception as e:
        logger.exception("Failed to submit feedback for %s", clean_id)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to record feedback."
        )


@router.get("/{finding_id}/feedback")
def get_feedback(
    finding_id: str = Path(..., min_length=1, max_length=64),
    current_user: AuthenticatedUser = Depends(get_current_user)
):
    """Retrieve feedback audit trail for a finding from SQLite."""
    clean_id = _validate_finding_id(finding_id)
    return data_service.get_feedback_for_finding(clean_id)



