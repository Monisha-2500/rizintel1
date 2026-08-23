import logging

from fastapi import APIRouter, HTTPException
from pydantic import ValidationError

from app.models.input_models import RiskAssessedFinding
from app.models.output_models import ExplainedFinding
from app.services.explanation_service import generate_explained_finding

logger = logging.getLogger("m6.routes.explanation")

router = APIRouter(prefix="/api/v1", tags=["explanation"])


@router.post("/explain", response_model=ExplainedFinding)
def explain(finding: RiskAssessedFinding) -> ExplainedFinding:
    """
    Accepts a RiskAssessedFinding (M5 output) and returns an
    ExplainedFinding (M6 output, consumed by M7). risk_score/risk_level
    are always a direct passthrough of what M5 supplied.
    """
    if finding.risk_assessment is None:
        raise HTTPException(
            status_code=422,
            detail="Missing risk_assessment -- M6 requires M5's risk_score and risk_level.",
        )

    try:
        return generate_explained_finding(finding)
    except AssertionError as exc:
        # Should never fire in practice -- this is the score-drift guardrail.
        raise HTTPException(status_code=500, detail=f"Score integrity check failed: {exc}")
    except ValidationError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    except Exception as exc:  # noqa: BLE001
        logger.exception("M6 generation failed")
        raise HTTPException(status_code=500, detail=f"M6 generation failed: {exc}")
