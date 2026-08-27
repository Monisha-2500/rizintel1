"""
backend/routers/remediation.py
==============================
Authenticated, Multi-Tenant, RBAC-protected API for Remediation, Ticketing, and SLA Automation.
"""

from fastapi import APIRouter, HTTPException, Depends, Query
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any

from auth import get_current_user, AuthenticatedUser
from services.remediation_service import remediation_service
from services.data_service import data_service
from mem7.models import TicketStatus, InvalidTransition
import database

router = APIRouter(prefix="", tags=["Remediation & SLA Automation"])


class AssignOwnerRequest(BaseModel):
    assignee: str = Field(..., min_length=1, max_length=100)


class UpdateStatusRequest(BaseModel):
    status: str = Field(..., min_length=1, max_length=30)
    note: Optional[str] = Field(default="", max_length=500)


class CreateTaskRequest(BaseModel):
    note: Optional[str] = Field(default="", max_length=500)


@router.post("/findings/{finding_id}/remediation/task")
def create_finding_task(
    finding_id: str,
    req: Optional[CreateTaskRequest] = None,
    current_user: AuthenticatedUser = Depends(get_current_user),
):
    """
    Idempotently generate or retrieve a tracked remediation ticket for a canonical finding.
    Enforces multi-tenant scoping and RBAC (VIEWER is read-only).
    """
    if current_user.role == "VIEWER":
        raise HTTPException(
            status_code=403,
            detail="Permission Denied: VIEWER role cannot generate remediation tasks."
        )

    finding = data_service.get_finding_by_id(finding_id, user=current_user)
    if not finding:
        # Check in scan runs if scoped
        raise HTTPException(status_code=404, detail=f"Finding {finding_id} not found.")

    finding_dict = finding.model_dump() if hasattr(finding, "model_dump") else (finding.dict() if hasattr(finding, "dict") else dict(finding))
    org_id = current_user.organization_id or "ORG-RIZZOLVE-DEMO"

    ticket = remediation_service.generate_ticket_for_finding(
        organization_id=org_id,
        finding=finding_dict,
        created_by=f"{current_user.display_name} [{current_user.role}]"
    )

    # Synchronize in-memory finding workflow if applicable
    if hasattr(finding, "workflow"):
        finding.workflow.ticket_id = ticket["ticket_id"]
        finding.workflow.status = ticket["status"]
        finding.workflow.sla_due_at = ticket["due_at"]
        finding.workflow.sla_hours = ticket["sla_hours"]

    return {
        "status": "success",
        "ticket": ticket,
        "history": database.get_remediation_ticket_history(org_id, ticket["ticket_id"])
    }


@router.get("/findings/{finding_id}/remediation/task")
def get_finding_task(
    finding_id: str,
    current_user: AuthenticatedUser = Depends(get_current_user),
):
    """Retrieve the remediation ticket associated with a finding."""
    org_id = current_user.organization_id or "ORG-RIZZOLVE-DEMO"
    ticket = database.get_remediation_ticket_by_finding_id(org_id, finding_id)
    if not ticket:
        return {
            "ticket": None,
            "history": []
        }

    history = database.get_remediation_ticket_history(org_id, ticket["ticket_id"])
    return {
        "ticket": ticket,
        "history": history
    }


@router.post("/remediation/tasks/{ticket_id}/assign")
def assign_task_owner(
    ticket_id: str,
    req: AssignOwnerRequest,
    current_user: AuthenticatedUser = Depends(get_current_user),
):
    """Assign an owner to a remediation task."""
    if current_user.role == "VIEWER":
        raise HTTPException(
            status_code=403,
            detail="Permission Denied (403): VIEWER role is read-only and cannot assign task owners."
        )

    org_id = current_user.organization_id or "ORG-RIZZOLVE-DEMO"
    try:
        updated = remediation_service.assign_ticket(
            organization_id=org_id,
            ticket_id=ticket_id,
            assignee=req.assignee,
            user_name=current_user.display_name,
            user_role=current_user.role,
        )
    except KeyError as e:
        raise HTTPException(status_code=404, detail=str(e))

    # Synchronize in-memory finding workflow if loaded
    finding = data_service.get_finding_by_id(updated["finding_id"])
    if finding and hasattr(finding, "workflow"):
        finding.workflow.assigned_to = updated["assigned_to"]
        finding.workflow.status = updated["status"]

    return {
        "status": "success",
        "ticket": updated,
        "history": database.get_remediation_ticket_history(org_id, ticket_id)
    }


@router.post("/remediation/tasks/{ticket_id}/status")
def update_task_status(
    ticket_id: str,
    req: UpdateStatusRequest,
    current_user: AuthenticatedUser = Depends(get_current_user),
):
    """Transition remediation task status with legal transition enforcement."""
    if current_user.role == "VIEWER":
        raise HTTPException(
            status_code=403,
            detail="Permission Denied (403): VIEWER role is read-only and cannot update task status."
        )

    org_id = current_user.organization_id or "ORG-RIZZOLVE-DEMO"
    try:
        updated = remediation_service.update_ticket_status(
            organization_id=org_id,
            ticket_id=ticket_id,
            new_status=req.status,
            note=req.note or "",
            user_name=current_user.display_name,
            user_role=current_user.role,
        )
    except KeyError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except InvalidTransition as e:
        raise HTTPException(status_code=409, detail=str(e))

    # Synchronize in-memory finding workflow if loaded
    finding = data_service.get_finding_by_id(updated["finding_id"])
    if finding and hasattr(finding, "workflow"):
        finding.workflow.status = updated["status"]
        if updated["status"] == "RESOLVED":
            finding.workflow.sla_status = "MET"
        elif updated["status"] == "SLA_BREACHED":
            finding.workflow.sla_status = "BREACHED"

    return {
        "status": "success",
        "ticket": updated,
        "history": database.get_remediation_ticket_history(org_id, ticket_id)
    }


class StepUpdateRequest(BaseModel):
    step_id: str = Field(..., min_length=1, max_length=50)
    status: str = Field(..., min_length=1, max_length=30)


@router.get("/remediation/tasks/{ticket_id}/checklist")
def get_task_checklist(
    ticket_id: str,
    current_user: AuthenticatedUser = Depends(get_current_user),
):
    """Retrieve persisted checklist steps for remediation task."""
    org_id = current_user.organization_id or "ORG-RIZZOLVE-DEMO"
    return remediation_service.get_checklist(org_id, ticket_id)


@router.post("/remediation/tasks/{ticket_id}/checklist/step")
def update_task_checklist_step(
    ticket_id: str,
    req: StepUpdateRequest,
    current_user: AuthenticatedUser = Depends(get_current_user),
):
    """Update checklist step status and persist."""
    if current_user.role == "VIEWER":
        raise HTTPException(
            status_code=403,
            detail="Permission Denied (403): VIEWER role is read-only and cannot update checklist steps."
        )

    org_id = current_user.organization_id or "ORG-RIZZOLVE-DEMO"
    try:
        updated_steps = remediation_service.update_checklist_step(
            organization_id=org_id,
            ticket_id=ticket_id,
            step_id=req.step_id,
            new_status=req.status,
            user_name=current_user.display_name,
            user_role=current_user.role,
        )
        return {"status": "success", "checklist": updated_steps}
    except KeyError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.get("/remediation/tasks")
def list_tasks(
    status: Optional[str] = Query(None),
    priority: Optional[str] = Query(None),
    limit: int = Query(100, ge=1, le=500),
    current_user: AuthenticatedUser = Depends(get_current_user),
):
    """List remediation tasks for the user's organization."""
    org_id = current_user.organization_id or "ORG-RIZZOLVE-DEMO"
    tasks = database.list_remediation_tickets(org_id, status=status, priority=priority, limit=limit)
    return tasks


@router.get("/remediation/tasks/{ticket_id}")
def get_task_details(
    ticket_id: str,
    current_user: AuthenticatedUser = Depends(get_current_user),
):
    """Get single remediation task and complete audit history."""
    org_id = current_user.organization_id or "ORG-RIZZOLVE-DEMO"
    ticket = database.get_remediation_ticket(org_id, ticket_id)
    if not ticket:
        raise HTTPException(status_code=404, detail=f"Task {ticket_id} not found.")
    history = database.get_remediation_ticket_history(org_id, ticket_id)
    return {"ticket": ticket, "history": history}


@router.get("/remediation/monitor/breach-warnings")
def get_breach_warnings(
    current_user: AuthenticatedUser = Depends(get_current_user),
):
    """
    Run monitoring sweep on active remediation commitments:
    - Auto-flags hard breaches
    - Predicts early breach risks (≤25% time window or ≤120m)
    """
    org_id = current_user.organization_id or "ORG-RIZZOLVE-DEMO"
    warnings = remediation_service.run_sweep(org_id)
    return warnings


@router.get("/remediation/stats/summary")
def get_remediation_summary(
    current_user: AuthenticatedUser = Depends(get_current_user),
):
    """Get aggregate remediation stats for organization."""
    org_id = current_user.organization_id or "ORG-RIZZOLVE-DEMO"
    tasks = database.list_remediation_tickets(org_id, limit=500)
    by_status = {}
    by_priority = {}
    for t in tasks:
        st = t["status"]
        pr = t["priority"]
        by_status[st] = by_status.get(st, 0) + 1
        by_priority[pr] = by_priority.get(pr, 0) + 1

    return {
        "total": len(tasks),
        "by_status": by_status,
        "by_priority": by_priority
    }
