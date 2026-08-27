from fastapi import APIRouter, Depends
from services.data_service import data_service
from auth import get_current_user, AuthenticatedUser

router = APIRouter(prefix="/dashboard", tags=["Dashboard operations"])

@router.get("/summary")
def get_summary(current_user: AuthenticatedUser = Depends(get_current_user)):
    """Retrieve pre-calculated KPI metrics from dashboard_summary.json. Protected by JWT."""
    return data_service.get_dashboard_summary()
