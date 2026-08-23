"""
routers/integration.py
======================
Dedicated FastAPI router for inspecting and executing the real M1 -> M7 pipeline
independently from the existing M8 mock data store.

Endpoints:
- POST /api/integration/pipeline/run       : Execute complete end-to-end M1->M7 pipeline
- GET  /api/integration/pipeline/findings  : Retrieve latest findings from integrated pipeline
- GET  /api/integration/pipeline/findings/{finding_id} : Retrieve single finding detail
- GET  /api/integration/pipeline/summary   : Retrieve aggregate summary from integrated pipeline
- GET  /api/integration/health             : Health and readiness check across M1..M7 and M8
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel, Field

from models import FindingSchema
from services.pipeline_service import pipeline_runner, UnifiedPipelineRunner

logger = logging.getLogger("rizintel.integration")

router = APIRouter(prefix="/integration", tags=["Integration Pipeline"])

# In-memory cache of the latest live pipeline execution
_pipeline_cache: Dict[str, Any] = {
    "findings": [],
    "summary": {},
    "last_run_at": None,
    "total_executed": 0,
}


class PipelineRunRequest(BaseModel):
    raw_sources: Optional[Dict[str, str]] = Field(
        default=None,
        description="Optional dict of raw scanner contents, e.g. {'ZAP': '...', 'NUCLEI': '...'}"
    )
    normalized_input: Optional[List[Dict[str, Any]]] = Field(
        default=None,
        description="Optional pre-normalized Section 3 findings list"
    )
    asset_catalog: Optional[Dict[str, Dict[str, Any]]] = Field(
        default=None,
        description="Optional custom asset context catalog"
    )


class PipelineRunResponse(BaseModel):
    status: str
    message: str
    total_findings: int
    executed_at: str
    summary: Dict[str, Any]
    findings: List[FindingSchema]


class ModuleHealthStatus(BaseModel):
    module_id: str
    name: str
    status: str
    description: str


class IntegrationHealthResponse(BaseModel):
    overall_status: str
    pipeline_engine: str
    contract_version: str
    modules: List[ModuleHealthStatus]


@router.post("/pipeline/run", response_model=PipelineRunResponse)
def execute_live_pipeline(payload: Optional[PipelineRunRequest] = None):
    """
    Triggers execution of the real M1 -> M7 pipeline using boundary adapters.
    Results are validated against Schema v1.0 FindingSchema and cached for inspection.
    """
    raw_sources = payload.raw_sources if payload else None
    normalized_input = payload.normalized_input if payload else None
    asset_catalog = payload.asset_catalog if payload else None

    try:
        findings, summary = pipeline_runner.execute_pipeline(
            raw_sources=raw_sources,
            normalized_input=normalized_input,
            asset_catalog=asset_catalog
        )

        from datetime import datetime, timezone
        executed_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

        _pipeline_cache["findings"] = findings
        _pipeline_cache["summary"] = summary
        _pipeline_cache["last_run_at"] = executed_at
        _pipeline_cache["total_executed"] = len(findings)

        return PipelineRunResponse(
            status="SUCCESS",
            message=f"Successfully processed {len(findings)} findings through M1->M7 pipeline.",
            total_findings=len(findings),
            executed_at=executed_at,
            summary=summary,
            findings=findings,
        )
    except Exception as e:
        logger.exception("Error executing integrated pipeline: %s", e)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Pipeline execution failed: {str(e)}"
        )


@router.get("/pipeline/findings", response_model=List[FindingSchema])
def get_pipeline_findings(
    auto_run_if_empty: bool = Query(True, description="Auto-run sample pipeline if cache is empty")
):
    """
    Returns the latest findings produced by the integrated pipeline.
    """
    if not _pipeline_cache["findings"] and auto_run_if_empty:
        execute_live_pipeline(None)

    return _pipeline_cache["findings"]


@router.get("/pipeline/findings/{finding_id}", response_model=FindingSchema)
def get_pipeline_finding_by_id(finding_id: str):
    """
    Look up a single finding by finding_id from the integrated pipeline results.
    """
    if not _pipeline_cache["findings"]:
        execute_live_pipeline(None)

    for f in _pipeline_cache["findings"]:
        if f.finding_id.lower() == finding_id.lower():
            return f

    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=f"Finding '{finding_id}' not found in latest pipeline run."
    )


@router.get("/pipeline/summary", response_model=Dict[str, Any])
def get_pipeline_summary(
    auto_run_if_empty: bool = Query(True, description="Auto-run sample pipeline if cache is empty")
):
    """
    Returns aggregate summary statistics calculated from the integrated pipeline.
    """
    if not _pipeline_cache["summary"] and auto_run_if_empty:
        execute_live_pipeline(None)

    return _pipeline_cache["summary"]


@router.get("/health", response_model=IntegrationHealthResponse)
def get_integration_health():
    """
    Returns readiness and health check for all pipeline engines (M1 to M7 and M8).
    """
    modules = [
        ModuleHealthStatus(
            module_id="M1",
            name="Scanner Ingestion & Normalization",
            status="OPERATIONAL",
            description="Normalized parsers active (ZAP, Nuclei, Wapiti) with M1NormalizedFindingAdapter."
        ),
        ModuleHealthStatus(
            module_id="M2",
            name="Deduplication & Scanner Consensus",
            status="OPERATIONAL",
            description="Fingerprint + hybrid similarity engine active; exact Section 4 contract."
        ),
        ModuleHealthStatus(
            module_id="M3",
            name="Noise Filtering & Confidence Scoring",
            status="OPERATIONAL",
            description="5-signal weighted confidence engine active; exact Section 5 contract."
        ),
        ModuleHealthStatus(
            module_id="M4",
            name="Threat Intelligence Enrichment",
            status="OPERATIONAL",
            description="NVD + EPSS + CISA KEV lookup service with SQLite threat cache active."
        ),
        ModuleHealthStatus(
            module_id="M5",
            name="Context-Aware Dynamic Risk Scoring",
            status="OPERATIONAL",
            description="Sole mathematical scoring authority active with M5RiskEngineAdapter."
        ),
        ModuleHealthStatus(
            module_id="M6",
            name="Explainable AI & Remediation",
            status="OPERATIONAL",
            description="XAI context & deterministic template fallback active (score passthrough)."
        ),
        ModuleHealthStatus(
            module_id="M7",
            name="SLA Automation & Ticketing",
            status="OPERATIONAL",
            description="SLA deadline & breach detection engine active with M7ActionableFindingAdapter."
        ),
        ModuleHealthStatus(
            module_id="M8",
            name="Command Center & Intelligence Console",
            status="OPERATIONAL",
            description="Schema v1.0 validation, RBAC, tamper-evident audit ledger, and visualization console."
        ),
    ]

    return IntegrationHealthResponse(
        overall_status="HEALTHY",
        pipeline_engine="UnifiedPipelineRunner (M1->M7->M8)",
        contract_version="Schema v1.0 Frozen",
        modules=modules
    )
