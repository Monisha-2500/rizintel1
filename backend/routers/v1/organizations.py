"""
routers/v1/organizations.py — Versioned Organization API (Phase 1)

All endpoints are prefixed /api/v1/organizations and require Bearer JWT.

SECURITY:
  - User identity and role derive EXCLUSIVELY from verified JWT (existing auth.py).
  - Membership is a belongs-to check (org isolation), not a permission elevator.
  - Only SECURITY_LEAD and ADMIN may register, authorize, or disable assets.
  - All asset and scan-run lookups are double-scoped by organization_id to prevent
    cross-org data leakage.

Supported Scanners (validated at creation): ZAP, NUCLEI, WAPITI
Phase 1 guarantee: scan runs stop at WAITING_FOR_INPUT; no scanner execution.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status, Header
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field, validator

from auth import AuthenticatedUser, get_current_user, require_roles
from users import UserRole
from services.org_service import (
    get_org_or_404,
    assert_membership,
    get_user_organizations,
)
from services.asset_service import (
    register_asset,
    get_asset,
    list_assets,
    set_authorization_status,
    ConflictError,
)
from services.scan_run_service import (
    create_run,
    get_run,
    list_runs,
    cancel_run,
)
from database import SUPPORTED_SCANNERS

logger = logging.getLogger("rizintel.v1.organizations")

router = APIRouter(prefix="/api/v1/organizations", tags=["v1-organizations"])

# ── RBAC helper shortcuts ─────────────────────────────────────
_require_analyst_up = require_roles([UserRole.ANALYST, UserRole.SECURITY_LEAD, UserRole.ADMIN])
_require_lead_up = require_roles([UserRole.SECURITY_LEAD, UserRole.ADMIN])


# ── Pydantic request / response models ───────────────────────

class OrgSummary(BaseModel):
    organization_id: str
    display_name: str
    created_at: str
    is_active: bool


class AssetCreateRequest(BaseModel):
    display_name: str = Field(..., min_length=1, max_length=200)
    host: str = Field(..., min_length=1, max_length=500)
    port: Optional[int] = Field(None, ge=1, le=65535)
    environment: str = Field("production")
    criticality: str = Field("HIGH")
    internet_facing: Optional[bool] = None
    data_sensitivity: str = Field("CONFIDENTIAL")

    @validator("environment")
    def check_env(cls, v):
        valid = {"production", "staging", "development", "lab"}
        if v not in valid:
            raise ValueError(f"environment must be one of {sorted(valid)}")
        return v

    @validator("criticality")
    def check_crit(cls, v):
        valid = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
        if v not in valid:
            raise ValueError(f"criticality must be one of {sorted(valid)}")
        return v

    @validator("data_sensitivity")
    def check_sens(cls, v):
        valid = {"RESTRICTED", "CONFIDENTIAL", "INTERNAL", "PUBLIC"}
        if v not in valid:
            raise ValueError(f"data_sensitivity must be one of {sorted(valid)}")
        return v


class AuthorizationPatchRequest(BaseModel):
    authorization_status: str

    @validator("authorization_status")
    def check_status(cls, v):
        valid = {"PENDING", "AUTHORIZED", "DISABLED"}
        if v not in valid:
            raise ValueError(f"authorization_status must be one of {sorted(valid)}")
        return v


class ScanRunCreateRequest(BaseModel):
    asset_id: str = Field(..., min_length=1)
    scanner_selections: List[str] = Field(..., min_items=1)
    data_origin: str = Field("LIVE_SCAN")

    @validator("scanner_selections", each_item=True)
    def check_scanner(cls, v):
        if v.upper() not in SUPPORTED_SCANNERS:
            raise ValueError(
                f"Unsupported scanner '{v}'. Supported: {sorted(SUPPORTED_SCANNERS)}"
            )
        return v.upper()

    @validator("data_origin")
    def check_data_origin(cls, v):
        valid = {"LIVE_SCAN", "MOCK_SCAN"}
        if v not in valid:
            raise ValueError(f"data_origin must be one of {sorted(valid)}")
        return v


# ── Isolation helper ──────────────────────────────────────────

def _resolve_org_and_membership(
    organization_id: str, user: AuthenticatedUser
) -> Dict[str, Any]:
    """
    Verify org exists and that the caller is a member.
    Returns org dict.
    Raises HTTPException(404) or HTTPException(403) on failure.
    """
    try:
        org = get_org_or_404(organization_id)
    except KeyError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))

    try:
        assert_membership(organization_id, user.user_id)
    except PermissionError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))

    return org


# ── Endpoints ─────────────────────────────────────────────────

@router.get("", response_model=List[OrgSummary], summary="List user's organizations")
def list_my_organizations(
    user: AuthenticatedUser = Depends(get_current_user),
) -> List[Dict[str, Any]]:
    """Return all active organizations the authenticated user belongs to."""
    orgs = get_user_organizations(user.user_id)
    return [
        {
            "organization_id": o["organization_id"],
            "display_name": o["display_name"],
            "created_at": o["created_at"],
            "is_active": bool(o["is_active"]),
        }
        for o in orgs
    ]


@router.get("/{organization_id}", summary="Get organization details")
def get_organization_detail(
    organization_id: str,
    user: AuthenticatedUser = Depends(get_current_user),
) -> Dict[str, Any]:
    """Return organization details. Caller must be a member."""
    org = _resolve_org_and_membership(organization_id, user)
    return {
        "organization_id": org["organization_id"],
        "display_name": org["display_name"],
        "created_at": org["created_at"],
        "is_active": bool(org["is_active"]),
    }


# ── Asset Endpoints ────────────────────────────────────────────

@router.get("/{organization_id}/assets", summary="List registered assets")
def list_org_assets(
    organization_id: str,
    user: AuthenticatedUser = Depends(get_current_user),
) -> List[Dict[str, Any]]:
    """List all registered assets for an organization. All members may read."""
    _resolve_org_and_membership(organization_id, user)
    return list_assets(organization_id)


@router.post(
    "/{organization_id}/assets",
    status_code=status.HTTP_201_CREATED,
    summary="Register a new asset",
)
def create_org_asset(
    organization_id: str,
    body: AssetCreateRequest,
    user: AuthenticatedUser = Depends(_require_lead_up),
) -> Dict[str, Any]:
    """
    Register a new asset (PENDING status).
    Requires SECURITY_LEAD or ADMIN role.
    Enforces normalized host/port uniqueness within the organization.
    """
    _resolve_org_and_membership(organization_id, user)
    try:
        return register_asset(
            organization_id=organization_id,
            display_name=body.display_name,
            host=body.host,
            port=body.port,
            environment=body.environment,
            criticality=body.criticality,
            internet_facing=body.internet_facing,
            data_sensitivity=body.data_sensitivity,
            created_by=user.user_id,
        )
    except ConflictError as e:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(e))


@router.get("/{organization_id}/assets/{asset_id}", summary="Get a registered asset")
def get_org_asset(
    organization_id: str,
    asset_id: str,
    user: AuthenticatedUser = Depends(get_current_user),
) -> Dict[str, Any]:
    """Fetch a single registered asset. All members may read."""
    _resolve_org_and_membership(organization_id, user)
    asset = get_asset(organization_id, asset_id)
    if asset is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Asset {asset_id} not found in organization {organization_id}.",
        )
    return asset


@router.patch(
    "/{organization_id}/assets/{asset_id}",
    summary="Update asset authorization status",
)
def patch_org_asset(
    organization_id: str,
    asset_id: str,
    body: AuthorizationPatchRequest,
    user: AuthenticatedUser = Depends(_require_lead_up),
) -> Dict[str, Any]:
    """
    Transition an asset's authorization status (PENDING/AUTHORIZED/DISABLED).
    Requires SECURITY_LEAD or ADMIN role.
    Scoped to organization_id — cross-org updates are rejected.
    """
    _resolve_org_and_membership(organization_id, user)
    try:
        return set_authorization_status(
            organization_id=organization_id,
            asset_id=asset_id,
            new_status=body.authorization_status,
            updated_by=user.user_id,
        )
    except KeyError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(e))


# ── Scan Run Endpoints ─────────────────────────────────────────

@router.get("/{organization_id}/scan-runs", summary="List scan runs")
def list_org_scan_runs(
    organization_id: str,
    user: AuthenticatedUser = Depends(get_current_user),
) -> List[Dict[str, Any]]:
    """List scan runs for an organization (newest first). All members may read."""
    _resolve_org_and_membership(organization_id, user)
    return list_runs(organization_id)


@router.post(
    "/{organization_id}/scan-runs",
    status_code=status.HTTP_201_CREATED,
    summary="Create a scan run",
)
def create_org_scan_run(
    organization_id: str,
    body: ScanRunCreateRequest,
    user: AuthenticatedUser = Depends(_require_analyst_up),
) -> Dict[str, Any]:
    """
    Create a new scan run for an AUTHORIZED asset.
    Requires ANALYST or above.
    Validates scanner_selections against [ZAP, NUCLEI, WAPITI].
    Phase 1: run is created and reaches WAITING_FOR_INPUT. Scanners are NOT executed.
    """
    _resolve_org_and_membership(organization_id, user)

    # Verify the asset belongs to this org and is AUTHORIZED
    asset = get_asset(organization_id, body.asset_id)
    if asset is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Asset {body.asset_id} not found in organization {organization_id}.",
        )
    if asset["authorization_status"] != "AUTHORIZED":
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=(
                f"Asset {body.asset_id} has status '{asset['authorization_status']}'. "
                "Only AUTHORIZED assets may have scan runs created."
            ),
        )

    try:
        return create_run(
            organization_id=organization_id,
            asset_id=body.asset_id,
            created_by_user_id=user.user_id,
            scanner_selections=body.scanner_selections,
            data_origin=body.data_origin,
        )
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(e))


@router.get("/{organization_id}/scan-runs/{scan_run_id}", summary="Get a scan run")
def get_org_scan_run(
    organization_id: str,
    scan_run_id: str,
    user: AuthenticatedUser = Depends(get_current_user),
) -> Dict[str, Any]:
    """Fetch a single scan run scoped to the organization. All members may read."""
    _resolve_org_and_membership(organization_id, user)
    run = get_run(organization_id, scan_run_id)
    if run is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan run {scan_run_id} not found in organization {organization_id}.",
        )
    return run


# ═══════════════════════════════════════════════════════════════
# Phase 2 Endpoints — Ingestion & Pipeline Processing
# ═══════════════════════════════════════════════════════════════

from fastapi import File, UploadFile, BackgroundTasks
from services.ingestion_service import ingest_report, TargetMismatchError
from services.processing_service import process_scan_run_pipeline
from database import list_submissions_for_run, list_scan_run_events, get_scan_run_results


class ApiEventIngestRequest(BaseModel):
    payload: str = Field(..., min_length=1, description="Raw scanner report payload content string")
    idempotency_key: Optional[str] = Field("", description="Optional client idempotency key")


@router.post(
    "/{organization_id}/scan-runs/{scan_run_id}/ingest/{scanner}",
    summary="Ingest raw scanner report file upload",
)
async def upload_scanner_report(
    organization_id: str,
    scan_run_id: str,
    scanner: str,
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    user: AuthenticatedUser = Depends(_require_analyst_up),
) -> Dict[str, Any]:
    """
    Method A: Report File Upload Ingestion.
    Requires ANALYST or above role.
    Ingests, validates target host, parses safely, stores raw payload via StorageService,
    emits stage events, and schedules background processing if multi-scanner consensus is reached.
    """
    _resolve_org_and_membership(organization_id, user)

    contents = await file.read()

    try:
        res = ingest_report(
            organization_id=organization_id,
            scan_run_id=scan_run_id,
            scanner=scanner,
            report_bytes=contents,
            submission_type="FILE_UPLOAD",
            user_id=user.user_id,
            original_filename=file.filename,
            content_type=file.content_type,
        )

        # Trigger background processing asynchronously if consensus reached
        if res.get("is_consensus_reached") and not res.get("is_duplicate"):
            background_tasks.add_task(
                process_scan_run_pipeline,
                organization_id=organization_id,
                scan_run_id=scan_run_id,
                triggered_by_user_id=user.user_id,
            )

        return res
    except KeyError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except TargetMismatchError as e:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(e))


@router.post(
    "/{organization_id}/scan-runs/{scan_run_id}/events/{scanner}",
    summary="Ingest scanner API event payload",
)
def ingest_scanner_api_event(
    organization_id: str,
    scan_run_id: str,
    scanner: str,
    body: ApiEventIngestRequest,
    background_tasks: BackgroundTasks,
    user: AuthenticatedUser = Depends(_require_analyst_up),
) -> Dict[str, Any]:
    """
    Method B: Direct JSON/API Event Ingestion.
    Requires ANALYST or above role (trusted JWT identity).
    Ingests payload text, checks idempotency, parses safely, and manages multi-scanner consensus.
    """
    _resolve_org_and_membership(organization_id, user)

    report_bytes = body.payload.encode("utf-8")

    try:
        res = ingest_report(
            organization_id=organization_id,
            scan_run_id=scan_run_id,
            scanner=scanner,
            report_bytes=report_bytes,
            submission_type="API_EVENT",
            user_id=user.user_id,
            idempotency_key=body.idempotency_key or "",
        )

        if res.get("is_consensus_reached") and not res.get("is_duplicate"):
            background_tasks.add_task(
                process_scan_run_pipeline,
                organization_id=organization_id,
                scan_run_id=scan_run_id,
                triggered_by_user_id=user.user_id,
            )

        return res
    except KeyError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except TargetMismatchError as e:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(e))


@router.get(
    "/{organization_id}/scan-runs/{scan_run_id}/submissions",
    summary="List scanner submissions for scan run",
)
def list_scan_run_submissions(
    organization_id: str,
    scan_run_id: str,
    user: AuthenticatedUser = Depends(get_current_user),
) -> List[Dict[str, Any]]:
    """List raw scanner submissions for a scan run. All members may read."""
    _resolve_org_and_membership(organization_id, user)
    return list_submissions_for_run(organization_id, scan_run_id)


@router.get(
    "/{organization_id}/scan-runs/{scan_run_id}/events",
    summary="List real stage events for scan run",
)
def list_scan_run_events_endpoint(
    organization_id: str,
    scan_run_id: str,
    user: AuthenticatedUser = Depends(get_current_user),
) -> List[Dict[str, Any]]:
    """List persistent stage event log for scan run timeline. All members may read."""
    _resolve_org_and_membership(organization_id, user)
    return list_scan_run_events(organization_id, scan_run_id)


@router.post(
    "/{organization_id}/scan-runs/{scan_run_id}/process",
    summary="Process available scan run results (Partial or Manual Trigger)",
)
def trigger_scan_run_processing(
    organization_id: str,
    scan_run_id: str,
    background_tasks: BackgroundTasks,
    user: AuthenticatedUser = Depends(_require_lead_up),
) -> Dict[str, Any]:
    """
    Privileged partial processing trigger for SECURITY_LEAD or ADMIN.
    Allows processing when some selected scanners have submitted even if others are pending/failed.
    Preserves truthful consensus denominator (e.g. 2 of 3).
    """
    _resolve_org_and_membership(organization_id, user)

    scan_run = get_run(organization_id, scan_run_id)
    if not scan_run:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Scan run {scan_run_id} not found.")

    if scan_run["status"] not in ("INGESTING", "WAITING_FOR_INPUT"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Scan run {scan_run_id} is in status '{scan_run['status']}' and cannot be processed.",
        )

    # Schedule race-safe pipeline execution
    background_tasks.add_task(
        process_scan_run_pipeline,
        organization_id=organization_id,
        scan_run_id=scan_run_id,
        triggered_by_user_id=user.user_id,
        is_partial_trigger=True,
    )

    return {
        "scan_run_id": scan_run_id,
        "status": "PROCESSING_SCHEDULED",
        "message": "Background pipeline execution triggered for available scanner reports.",
    }


@router.get(
    "/{organization_id}/scan-runs/{scan_run_id}/results",
    summary="Get final M1-M7 pipeline findings for scan run",
)
def get_scan_run_pipeline_results(
    organization_id: str,
    scan_run_id: str,
    user: AuthenticatedUser = Depends(get_current_user),
) -> Dict[str, Any]:
    """
    Retrieve final actionable findings & executive summary metrics for a completed scan run.
    Scoped strictly to organization_id + scan_run_id. All members may read.
    """
    _resolve_org_and_membership(organization_id, user)
    results = get_scan_run_results(organization_id, scan_run_id)
    if not results:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Pipeline results not found for scan run {scan_run_id}.",
        )

    findings = json.loads(results.get("findings_json", "[]"))
    summary = json.loads(results.get("summary_json", "{}"))

    return {
        "result_id": results["result_id"],
        "organization_id": results["organization_id"],
        "scan_run_id": results["scan_run_id"],
        "asset_id": results["asset_id"],
        "raw_finding_count": results["raw_finding_count"],
        "canonical_finding_count": results["canonical_finding_count"],
        "findings": findings,
        "summary": summary,
        "completed_at": results["completed_at"],
    }


# ═══════════════════════════════════════════════════════════════
# Phase 3 Endpoints — Real-Time Server-Sent Events (SSE) Stream
# ═══════════════════════════════════════════════════════════════

from fastapi import Header, Query, Request
from fastapi.responses import StreamingResponse
from services.sse_service import (
    authenticate_sse_user,
    create_stream_token,
    scan_run_sse_generator,
)


@router.post(
    "/{organization_id}/scan-runs/{scan_run_id}/stream-token",
    summary="Issue short-lived stream token for SSE connection",
)
def issue_scan_run_stream_token(
    organization_id: str,
    scan_run_id: str,
    user: AuthenticatedUser = Depends(get_current_user),
) -> Dict[str, Any]:
    """
    Issue a 90-second single-use stream ticket for EventSource connection.
    Requires authenticated organization membership.
    """
    _resolve_org_and_membership(organization_id, user)
    run = get_run(organization_id, scan_run_id)
    if not run:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan run {scan_run_id} not found in organization {organization_id}.",
        )
    return create_stream_token(user.user_id, organization_id, scan_run_id)


@router.get(
    "/{organization_id}/scan-runs/{scan_run_id}/stream",
    summary="Subscribe to live SSE stream for ScanRun updates",
)
async def stream_scan_run_events(
    organization_id: str,
    scan_run_id: str,
    request: Request,
    authorization: Optional[str] = Header(None),
    stream_token: Optional[str] = Query(None),
    token: Optional[str] = Query(None),
    last_event_id_header: Optional[str] = Header(None, alias="Last-Event-ID"),
    last_event_id_query: Optional[str] = Query(None, alias="last_event_id"),
) -> StreamingResponse:
    """
    Stream real-time ScanRun updates, scanner status changes, pipeline stage transitions, and counts.
    Enforces authentication & tenant isolation. Supports Last-Event-ID event replay cursor.
    """
    # 1. Authenticate user via Bearer JWT header or single-use stream_token query param
    effective_auth = authorization
    effective_stream_token = stream_token or token

    user = authenticate_sse_user(
        authorization=effective_auth,
        stream_token=effective_stream_token,
        organization_id=organization_id,
        scan_run_id=scan_run_id,
    )

    # 2. Verify organization membership & scan run ownership
    _resolve_org_and_membership(organization_id, user)
    run = get_run(organization_id, scan_run_id)
    if not run:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan run {scan_run_id} not found in organization {organization_id}.",
        )

    # 3. Determine event replay cursor
    cursor = last_event_id_header or last_event_id_query

    generator = scan_run_sse_generator(
        request=request,
        organization_id=organization_id,
        scan_run_id=scan_run_id,
        last_event_id=cursor,
    )

    return StreamingResponse(
        generator,
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache, no-transform",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )

