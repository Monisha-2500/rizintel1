from fastapi import APIRouter
from typing import List, Dict
from services.data_service import data_service

router = APIRouter(prefix="/assets", tags=["Asset views"])

@router.get("", response_model=List[Dict])
def get_assets():
    """
    Groups findings by asset_id and yields criticality,
    environment, exposure, sensitivity, and vuln counts.
    """
    findings = data_service.get_findings()
    asset_map = {}

    for f in findings:
        asset_id = f.asset_id
        if not asset_id:
            continue

        if asset_id not in asset_map:
            ac = f.detail.asset_context
            asset_map[asset_id] = {
                "asset_id": asset_id,
                "display_name": ac.asset_name,
                "environment": ac.environment,
                "criticality": f.asset_criticality,
                "internet_facing": f.internet_exposure,
                "data_sensitivity": ac.data_sensitivity,
                "findings": [],
                "highest_risk": 0,
                "critical_count": 0,
                "high_count": 0,
                "open_count": 0
            }

        asset = asset_map[asset_id]
        asset["findings"].append(f.dict())
        
        if f.risk_score > asset["highest_risk"]:
            asset["highest_risk"] = f.risk_score
            
        level = f.risk_level.upper()
        if level == "CRITICAL":
            asset["critical_count"] += 1
        elif level == "HIGH":
            asset["high_count"] += 1
            
        status = f.workflow.status.upper()
        if status not in ["RESOLVED", "CLOSED"]:
            asset["open_count"] += 1

    return list(asset_map.values())
