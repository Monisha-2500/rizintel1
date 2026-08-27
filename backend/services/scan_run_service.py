"""
scan_run_service.py — Scan Run Lifecycle Service (Phase 1)

State Machine (Phase 1 stops at WAITING_FOR_INPUT):
  CREATED -> WAITING_FOR_INPUT -> INGESTING -> PROCESSING -> COMPLETED
                              \\-> CANCELLED                -> FAILED

Phase 1 guarantee: Scanners are NEVER executed here.
All scan runs created by this service reach WAITING_FOR_INPUT and stop.
Phase 2 will implement the INGESTING transition and scanner execution.

Supported scanners (validated): ZAP, NUCLEI, WAPITI
"""

from __future__ import annotations

import logging
import secrets
from typing import Any, Dict, List, Optional

import json

from database import (
    create_scan_run,
    get_scan_run,
    insert_scan_run_event,
    list_scan_runs,
    transition_scan_run,
    SUPPORTED_SCANNERS,
)


# Phase 4: scanner job dispatch (lazy import to avoid circular dependency)
def _dispatch_jobs(organization_id: str, scan_run_id: str, asset_id: str, scanner_selections: list):
    """Best-effort job dispatch. Failures log but do not break scan run creation."""
    try:
        from services.job_service import dispatch_jobs_for_scan_run
        dispatch_jobs_for_scan_run(organization_id, scan_run_id, asset_id, scanner_selections)
    except Exception as exc:  # pragma: no cover
        logger.error("Failed to dispatch scanner jobs for scan run %s: %s", scan_run_id, exc)

logger = logging.getLogger("rizintel.scan_run_service")


def generate_scan_run_id() -> str:
    """Generate a collision-safe scan run ID: SR-<12 hex chars>."""
    return f"SR-{secrets.token_hex(6).upper()}"


def create_run(
    organization_id: str,
    asset_id: str,
    created_by_user_id: str,
    scanner_selections: List[str],
    data_origin: str = "LIVE_SCAN",
) -> Dict[str, Any]:
    """
    Create a new scan run and immediately advance it to WAITING_FOR_INPUT.

    Phase 1 guarantee: stops at WAITING_FOR_INPUT. No scanner execution.
    Validates scanner_selections against SUPPORTED_SCANNERS.

    Returns the scan run record at WAITING_FOR_INPUT status.
    Raises:
        ValueError: invalid scanner selections or empty selection
        KeyError: asset not found / cross-org asset_id
    """
    if not scanner_selections:
        raise ValueError("At least one scanner must be selected.")

    invalid = [s for s in scanner_selections if s.upper() not in SUPPORTED_SCANNERS]
    if invalid:
        raise ValueError(
            f"Unsupported scanner(s): {invalid}. "
            f"Supported: {sorted(SUPPORTED_SCANNERS)}"
        )

    scan_run_id = generate_scan_run_id()

    # Create in CREATED status
    run = create_scan_run(
        scan_run_id=scan_run_id,
        organization_id=organization_id,
        asset_id=asset_id,
        created_by_user_id=created_by_user_id,
        scanner_selections=scanner_selections,
        data_origin=data_origin,
    )
    if not run:
        raise RuntimeError("Scan run creation failed unexpectedly.")

    # Immediately transition to WAITING_FOR_INPUT (Phase 1 terminal state)
    run = transition_scan_run(organization_id, scan_run_id, "WAITING_FOR_INPUT")
    if not run:
        raise RuntimeError("Scan run state transition to WAITING_FOR_INPUT failed.")

    logger.info(
        "Scan run %s created for org=%s asset=%s scanners=%s status=WAITING_FOR_INPUT",
        scan_run_id, organization_id, asset_id, scanner_selections,
    )

    # Phase 4: dispatch QUEUED scanner jobs for active agents to claim
    _dispatch_jobs(organization_id, scan_run_id, asset_id, [s.upper() for s in scanner_selections])

    return _serialize_run(run)


def get_run(organization_id: str, scan_run_id: str) -> Optional[Dict[str, Any]]:
    """Fetch a scan run scoped to its organization. Returns None if not found or cross-org."""
    row = get_scan_run(organization_id, scan_run_id)
    return _serialize_run(row) if row else None


def list_runs(organization_id: str, limit: int = 50) -> List[Dict[str, Any]]:
    """List scan runs for an organization, newest first."""
    rows = list_scan_runs(organization_id, limit=limit)
    return [_serialize_run(r) for r in rows]


def cancel_run(organization_id: str, scan_run_id: str, cancelled_by_user_id: str) -> Dict[str, Any]:
    """
    Cancel a scan run that has not started processing.
    Uses the existing Phase 1/2 status machine (WAITING_FOR_INPUT|INGESTING -> CANCELLED).
    """
    run = get_scan_run(organization_id, scan_run_id)
    if not run:
        raise KeyError(f"Scan run {scan_run_id} not found in organization {organization_id}.")

    updated = transition_scan_run(
        organization_id,
        scan_run_id,
        "CANCELLED",
        error_message=f"Cancelled by {cancelled_by_user_id}",
    )
    insert_scan_run_event(
        f"EVT-{secrets.token_hex(6).upper()}",
        organization_id,
        scan_run_id,
        "SCAN_CANCELLED",
        "COMPLETED",
        f"Scan run cancelled by {cancelled_by_user_id}.",
        "INFO",
        json.dumps({"cancelled_by": cancelled_by_user_id}),
    )
    return _serialize_run(updated) if updated else _serialize_run(run)


def _serialize_run(row: Dict[str, Any]) -> Dict[str, Any]:
    """Convert raw DB row to API-safe dict (JSON scanner_selections parsed)."""
    result = dict(row)
    raw_scanners = result.get("scanner_selections", "[]")
    if isinstance(raw_scanners, str):
        try:
            result["scanner_selections"] = json.loads(raw_scanners)
        except (ValueError, TypeError):
            result["scanner_selections"] = []
    for key in ("scanner_selections", "received_scanners", "pending_scanners", "failed_scanners"):
        raw = result.get(key, "[]")
        if isinstance(raw, str):
            try:
                result[key] = json.loads(raw)
            except (ValueError, TypeError):
                result[key] = []
    return result
