from fastapi import APIRouter, Depends
from typing import Dict, List, Any
from datetime import datetime, timezone
from services.data_service import data_service
from services.remediation_service import remediation_service
from auth import get_current_user, AuthenticatedUser
import database

router = APIRouter(prefix="/sla", tags=["SLA monitoring"])

@router.get("", response_model=Dict[str, List[Dict[str, Any]]])
def get_sla(current_user: AuthenticatedUser = Depends(get_current_user)):
    """Retrieve findings categorized by their server-authoritative SLA state."""
    org_id = current_user.organization_id or "ORG-RIZZOLVE-DEMO"
    findings = data_service.get_findings()
    groups: Dict[str, List[Dict[str, Any]]] = {"BREACHED": [], "AT_RISK": [], "ON_TRACK": [], "MET": []}

    now = datetime.now(timezone.utc).replace(tzinfo=None)

    for f in findings:
        # Check if there is a persisted ticket for this finding
        ticket = database.get_remediation_ticket_by_finding_id(org_id, f.finding_id)

        wf_status = ticket["status"] if ticket else f.workflow.status
        ticket_id = ticket["ticket_id"] if ticket else (f.workflow.ticket_id or "N/A")
        owner = ticket["assigned_to"] if (ticket and ticket.get("assigned_to")) else (f.workflow.assigned_to or "—")
        sla_due_at = ticket["due_at"] if ticket else f.workflow.sla_due_at

        # Calculate SLA status server-authoritatively
        if wf_status == "RESOLVED":
            computed_sla = "MET"
        elif sla_due_at:
            try:
                due_clean = sla_due_at.replace("Z", "+00:00")
                due_dt = datetime.fromisoformat(due_clean).astimezone(timezone.utc).replace(tzinfo=None)
                if now > due_dt:
                    computed_sla = "BREACHED"
                else:
                    diff_mins = (due_dt - now).total_seconds() / 60
                    sla_hours = ticket["sla_hours"] if ticket else (f.workflow.sla_hours or 24)
                    if diff_mins <= (sla_hours * 60 * 0.25) or diff_mins <= 120:
                        computed_sla = "AT_RISK"
                    else:
                        computed_sla = "ON_TRACK"
            except Exception:
                computed_sla = f.workflow.sla_status.upper() if f.workflow.sla_status else "ON_TRACK"
        else:
            computed_sla = f.workflow.sla_status.upper() if f.workflow.sla_status else "ON_TRACK"

        # Normalize status
        if computed_sla not in groups:
            computed_sla = "ON_TRACK"

        item = {
            "finding_id": f.finding_id,
            "vulnerability_name": f.vulnerability_name,
            "risk_score": f.risk_score,
            "risk_level": f.risk_level,
            "asset_display": f.detail.asset_context.asset_name if (f.detail and f.detail.asset_context) else f.asset_id,
            "asset_id": f.asset_id,
            "ticket_id": ticket_id,
            "owner": owner,
            "sla_due_at": sla_due_at,
            "sla_status": computed_sla,
            "escalation_level": f.workflow.escalation_level if hasattr(f.workflow, "escalation_level") else 0,
            "workflow_status": wf_status
        }
        
        groups[computed_sla].append(item)

    # Sort each group by risk score descending
    for key in groups:
        groups[key].sort(key=lambda x: x["risk_score"], reverse=True)

    return groups


@router.get("/breach-warnings")
def get_sla_breach_warnings(current_user: AuthenticatedUser = Depends(get_current_user)):
    """Run sweep and return proactive breach warnings for the current organization."""
    org_id = current_user.organization_id or "ORG-RIZZOLVE-DEMO"
    return remediation_service.run_sweep(org_id)
