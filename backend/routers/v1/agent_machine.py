"""
agent_machine.py — Machine Execution Router for Scanner Agents (Phase 4)

Machine Endpoints authenticated strictly via X-Scanner-Agent-Token or Authorization: AgentToken <secret>:
- POST /api/v1/agent/jobs/claim & POST /v1/agent/jobs/claim
- POST /api/v1/agent/jobs/{job_id}/started & POST /v1/agent/jobs/{job_id}/started
- POST /api/v1/agent/jobs/{job_id}/report & POST /v1/agent/jobs/{job_id}/report
- POST /api/v1/agent/jobs/{job_id}/failed & POST /v1/agent/jobs/{job_id}/failed
- POST /api/v1/agent/heartbeat & POST /v1/agent/heartbeat
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, Header, HTTPException, status, Path, Body, UploadFile, File, Form, BackgroundTasks
from pydantic import BaseModel, Field

from services.agent_service import authenticate_agent
from services.job_service import (
    claim_job_for_agent,
    mark_job_started,
    mark_job_completed,
    mark_job_failed,
)
from database import get_scanner_job, update_agent_heartbeat
from services.ingestion_service import ingest_report
from services.processing_service import process_scan_run_pipeline

router = APIRouter(prefix="/v1/agent", tags=["Scanner Agent Machine Interface"])


def get_current_agent(
    x_scanner_agent_token: Optional[str] = Header(None),
    authorization: Optional[str] = Header(None),
) -> Dict[str, Any]:
    """Dependency to authenticate machine scanner agent requests."""
    raw_token = x_scanner_agent_token
    if not raw_token and authorization:
        parts = authorization.split(" ", 1)
        if len(parts) == 2 and parts[0].lower() == "agenttoken":
            raw_token = parts[1]
    if not raw_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Machine authentication required. Provide X-Scanner-Agent-Token header.",
        )
    agent = authenticate_agent(raw_token)
    if not agent:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or revoked scanner agent token.",
        )
    return agent


class ClaimJobRequest(BaseModel):
    capabilities: Optional[List[str]] = Field(default_factory=lambda: ["ZAP", "NUCLEI", "WAPITI"])


@router.post("/jobs/claim", summary="Claim an available scanner job for execution")
def claim_job_endpoint(
    payload: Optional[ClaimJobRequest] = Body(default_factory=ClaimJobRequest),
    agent: Dict[str, Any] = Depends(get_current_agent),
) -> Dict[str, Any]:
    """
    Atomic job claim for an active scanner agent.
    Returns job configuration and authoritative target.
    If no jobs are queued, returns {"job": None}.
    """
    caps = payload.capabilities if payload and payload.capabilities is not None else ["ZAP", "NUCLEI", "WAPITI"]
    job = claim_job_for_agent(
        organization_id=agent["organization_id"],
        agent_id=agent["agent_id"],
        capabilities=caps,
    )
    return {"job": job}


@router.post("/jobs/{job_id}/started", summary="Report job execution start")
def mark_started_endpoint(
    job_id: str = Path(...),
    agent: Dict[str, Any] = Depends(get_current_agent),
) -> Dict[str, Any]:
    """Report that execution of a scanner job has started."""
    job = get_scanner_job(job_id)
    if not job or job["organization_id"] != agent["organization_id"]:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Job '{job_id}' not found for agent's organization.",
        )

    updated = mark_job_started(agent["organization_id"], job_id, agent["agent_id"])
    return {"job": updated}


@router.post("/jobs/{job_id}/report", summary="Submit raw scanner report for ingested job")
async def submit_job_report_endpoint(
    job_id: str = Path(...),
    background_tasks: BackgroundTasks = BackgroundTasks(),
    file: UploadFile = File(...),
    scanner: str = Form(...),
    agent: Dict[str, Any] = Depends(get_current_agent),
) -> Dict[str, Any]:
    """
    Agent submits raw vulnerability scanner report for a claimed job.
    Enters Phase 2 ingestion workflow directly with `data_origin = LIVE_SCAN`.
    If multi-scanner consensus is reached, schedules pipeline processing in background.
    """
    job = get_scanner_job(job_id)
    if not job or job["organization_id"] != agent["organization_id"]:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Job '{job_id}' not found for agent's organization.",
        )

    report_bytes = await file.read()

    # Pass to existing Phase 2 ingestion service
    res = ingest_report(
        organization_id=agent["organization_id"],
        scan_run_id=job["scan_run_id"],
        scanner=scanner,
        report_bytes=report_bytes,
        submission_type="AUTOMATED_AGENT",
        user_id=agent["created_by_user_id"],
        original_filename=file.filename or f"{scanner.lower()}_report.json",
        content_type=file.content_type or "application/json",
    )

    # Update scanner job status to COMPLETED
    mark_job_completed(
        organization_id=agent["organization_id"],
        job_id=job_id,
        agent_id=agent["agent_id"],
        submission_id=res["submission_id"],
    )

    # If consensus reached on all selected scanners, schedule pipeline processing
    if res.get("is_consensus_reached") and not res.get("is_duplicate"):
        background_tasks.add_task(
            process_scan_run_pipeline,
            organization_id=agent["organization_id"],
            scan_run_id=job["scan_run_id"],
            triggered_by_user_id=agent["created_by_user_id"],
        )

    return {
        "job_id": job_id,
        "submission": res,
        "status": "COMPLETED",
    }


class MarkFailedRequest(BaseModel):
    error_code: str = Field(..., min_length=2, max_length=50)
    error_message: str = Field(..., min_length=2, max_length=500)


@router.post("/jobs/{job_id}/failed", summary="Report job execution failure")
def mark_failed_endpoint(
    job_id: str = Path(...),
    payload: MarkFailedRequest = Body(...),
    agent: Dict[str, Any] = Depends(get_current_agent),
) -> Dict[str, Any]:
    """Report that a scanner job execution failed."""
    job = get_scanner_job(job_id)
    if not job or job["organization_id"] != agent["organization_id"]:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Job '{job_id}' not found for agent's organization.",
        )

    updated = mark_job_failed(
        organization_id=agent["organization_id"],
        job_id=job_id,
        agent_id=agent["agent_id"],
        error_code=payload.error_code,
        error_message=payload.error_message,
    )
    return {"job": updated}


class HeartbeatRequest(BaseModel):
    capabilities: Optional[Dict[str, Any]] = None


@router.post("/heartbeat", summary="Agent periodic heartbeat and capability report")
def agent_heartbeat_endpoint(
    payload: Optional[HeartbeatRequest] = Body(default_factory=HeartbeatRequest),
    agent: Dict[str, Any] = Depends(get_current_agent),
) -> Dict[str, Any]:
    """Update agent heartbeat and capabilities."""
    cap_json = json.dumps(payload.capabilities) if (payload and payload.capabilities) else None
    update_agent_heartbeat(agent["agent_id"], cap_json)
    return {
        "agent_id": agent["agent_id"],
        "status": "ACTIVE",
        "message": "Heartbeat recorded.",
    }
