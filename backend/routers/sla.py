from fastapi import APIRouter
from typing import Dict, List
from services.data_service import data_service

router = APIRouter(prefix="/sla", tags=["SLA monitoring"])

@router.get("", response_model=Dict[str, List[Dict]])
def get_sla():
    """Retrieve findings categorized by their SLA state."""
    findings = data_service.get_findings()
    groups = {"BREACHED": [], "AT_RISK": [], "ON_TRACK": [], "MET": []}

    for f in findings:
        status = f.workflow.sla_status.upper()
        item = {
            "finding_id": f.finding_id,
            "vulnerability_name": f.vulnerability_name,
            "risk_score": f.risk_score,
            "risk_level": f.risk_level,
            "asset_display": f.detail.asset_context.asset_name,
            "asset_id": f.asset_id,
            "ticket_id": f.workflow.ticket_id or "N/A",
            "owner": f.workflow.assigned_to or "—",
            "sla_due_at": f.workflow.sla_due_at,
            "sla_status": status,
            "escalation_level": f.workflow.escalation_level,
            "workflow_status": f.workflow.status
        }
        
        if status in groups:
            groups[status].append(item)
        else:
            groups["ON_TRACK"].append(item)

    # Sort each group by risk score descending
    for key in groups:
        groups[key].sort(key=lambda x: x["risk_score"], reverse=True)

    return groups
