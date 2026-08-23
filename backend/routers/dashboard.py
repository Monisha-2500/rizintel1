from fastapi import APIRouter
from services.data_service import data_service

router = APIRouter(prefix="/dashboard", tags=["Dashboard operations"])

@router.get("/summary")
def get_summary():
    """Retrieve pre-calculated KPI metrics from dashboard_summary.json."""
    return data_service.get_dashboard_summary()
