"""
job_service.py — Scanner Job Queue & Authoritative Target Resolution Service (Phase 4)

Responsibilities:
- Dispatch QUEUED scanner jobs upon ScanRun creation for each selected scanner.
- Enforce Authoritative Target Resolution: target scheme, host, and port are constructed
  strictly from the organization's registered asset with AUTHORIZED status.
- Prevent scanner execution if target asset authorization is revoked/disabled/pending.
- Atomic job claiming for active agents.
- Track execution status, attempt counts, retries, and job cancellation.
- Emit real stage events to scan_run_events.
"""

from __future__ import annotations

import json
import secrets
from typing import Any, Dict, List, Optional

from database import (
    create_scanner_job,
    get_scanner_job,
    list_scanner_jobs_for_run,
    claim_scanner_job_atomically,
    update_scanner_job_status,
    cancel_jobs_for_scan_run,
    get_scan_run,
    get_registered_asset,
    insert_scan_run_event,
)

def generate_job_id() -> str:
    """Generate collision-safe scanner job ID: JOB-<10 hex chars>."""
    return f"JOB-{secrets.token_hex(5).upper()}"


def generate_event_id() -> str:
    """Generate collision-safe event ID: EVT-<12 hex chars>."""
    return f"EVT-{secrets.token_hex(6).upper()}"


def resolve_authoritative_target(organization_id: str, scan_run_id: str, job_id: str) -> Dict[str, Any]:
    """
    AUTHORITATIVE TARGET RESOLVER
    Resolves authoritative target configuration for a scanner job.
    Requires:
      - scan_run exists in organization
      - asset exists and has authorization_status == 'AUTHORIZED'
    Constructs target URL: scheme://host[:port]
    Does NOT accept arbitrary target overrides from client or agent.
    """
    job = get_scanner_job(job_id)
    if not job or job["organization_id"] != organization_id:
        raise KeyError(f"Scanner job '{job_id}' not found in organization '{organization_id}'.")

    scan_run = get_scan_run(organization_id, scan_run_id)
    if not scan_run:
        raise KeyError(f"Scan run '{scan_run_id}' not found in organization '{organization_id}'.")

    asset = get_registered_asset(organization_id, scan_run["asset_id"])
    if not asset:
        raise KeyError(f"Asset '{scan_run['asset_id']}' not found in organization '{organization_id}'.")

    if asset["authorization_status"] != "AUTHORIZED":
        # Target authorization has been revoked or is pending -> cancel/fail job
        update_scanner_job_status(job_id, "FAILED", "TARGET_NOT_AUTHORIZED", "Asset is not AUTHORIZED for vulnerability scanning.")
        insert_scan_run_event(
            generate_event_id(),
            organization_id,
            scan_run_id,
            "SCANNER_FAILED",
            "EXECUTION",
            f"{job['scanner']} execution blocked: Asset host '{asset['normalized_host']}' authorization status is {asset['authorization_status']}.",
            "FAILED",
            json.dumps({"scanner": job["scanner"], "asset_id": asset["asset_id"], "status": asset["authorization_status"]}),
        )
        raise ValueError(f"Asset '{asset['asset_id']}' is not AUTHORIZED for scanning (status: {asset['authorization_status']}).")

    host = asset["normalized_host"]
    port = asset.get("port")
    scheme = "https" if (port == 443 or "https" in asset.get("host", "").lower()) else "http"

    if port and port not in (80, 443):
        target_url = f"{scheme}://{host}:{port}"
    else:
        target_url = f"{scheme}://{host}"

    return {
        "target_url": target_url,
        "host": host,
        "port": port,
        "scheme": scheme,
        "asset_id": asset["asset_id"],
        "authorization_status": asset["authorization_status"],
        "environment": asset["environment"],
        "criticality": asset["criticality"],
    }


def dispatch_jobs_for_scan_run(
    organization_id: str,
    scan_run_id: str,
    asset_id: str,
    scanner_selections: List[str],
) -> List[Dict[str, Any]]:
    """
    Create QUEUED scanner jobs for each selected scanner when a Scan Run is created.
    Emits SCANNER_JOB_QUEUED event for each scanner.
    """
    jobs = []
    for s in scanner_selections:
        scanner_upper = s.upper()
        job_id = generate_job_id()
        job = create_scanner_job(
            scanner_job_id=job_id,
            organization_id=organization_id,
            scan_run_id=scan_run_id,
            asset_id=asset_id,
            scanner=scanner_upper,
        )
        jobs.append(job)

        insert_scan_run_event(
            generate_event_id(),
            organization_id,
            scan_run_id,
            "SCANNER_JOB_QUEUED",
            "DISPATCH",
            f"Queued scanner job {job_id} for {scanner_upper}.",
            "INFO",
            json.dumps({"job_id": job_id, "scanner": scanner_upper, "asset_id": asset_id}),
        )
    return jobs


def claim_job_for_agent(
    organization_id: str,
    agent_id: str,
    capabilities: List[str],
    scan_run_id: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    """
    Race-safe atomic claim of the next QUEUED job matching agent's supported scanners.
    Resolves authoritative target for the claimed job.
    Emits SCANNER_JOB_CLAIMED event.
    """
    job = claim_scanner_job_atomically(organization_id, agent_id, capabilities, scan_run_id=scan_run_id)
    if not job:
        return None

    try:
        target_info = resolve_authoritative_target(organization_id, job["scan_run_id"], job["scanner_job_id"])
        job["target"] = target_info

        insert_scan_run_event(
            generate_event_id(),
            organization_id,
            job["scan_run_id"],
            "SCANNER_JOB_CLAIMED",
            "DISPATCH",
            f"Scanner Agent {agent_id} claimed job {job['scanner_job_id']} for {job['scanner']}.",
            "INFO",
            json.dumps({"job_id": job["scanner_job_id"], "agent_id": agent_id, "scanner": job["scanner"], "target": target_info["target_url"]}),
        )
        return job
    except Exception as e:
        # Target resolution failed (e.g. non-authorized asset)
        update_scanner_job_status(job["scanner_job_id"], "FAILED", "TARGET_RESOLUTION_FAILED", str(e))
        return None


def mark_job_started(organization_id: str, job_id: str, agent_id: str) -> Dict[str, Any]:
    """Mark job status RUNNING and emit SCANNER_STARTED event."""
    job = update_scanner_job_status(job_id, "RUNNING")
    if job:
        insert_scan_run_event(
            generate_event_id(),
            organization_id,
            job["scan_run_id"],
            "SCANNER_STARTED",
            "EXECUTION",
            f"Scanner {job['scanner']} execution started by Agent {agent_id}.",
            "INFO",
            json.dumps({"job_id": job_id, "agent_id": agent_id, "scanner": job["scanner"]}),
        )
    return job or {}


def mark_job_completed(organization_id: str, job_id: str, agent_id: str, submission_id: str) -> Dict[str, Any]:
    """Mark job status COMPLETED and emit SCANNER_COMPLETED event."""
    job = update_scanner_job_status(job_id, "COMPLETED")
    if job:
        insert_scan_run_event(
            generate_event_id(),
            organization_id,
            job["scan_run_id"],
            "SCANNER_COMPLETED",
            "INGESTION",
            f"Scanner {job['scanner']} execution completed cleanly. Report submission {submission_id} received.",
            "SUCCESS",
            json.dumps({"job_id": job_id, "agent_id": agent_id, "scanner": job["scanner"], "submission_id": submission_id}),
        )
    return job or {}


def mark_job_failed(organization_id: str, job_id: str, agent_id: str, error_code: str, error_message: str) -> Dict[str, Any]:
    """Mark job status FAILED and emit SCANNER_FAILED event."""
    job = update_scanner_job_status(job_id, "FAILED", error_code, error_message)
    if job:
        insert_scan_run_event(
            generate_event_id(),
            organization_id,
            job["scan_run_id"],
            "SCANNER_FAILED",
            "EXECUTION",
            f"Scanner {job['scanner']} execution failed: [{error_code}] {error_message}",
            "FAILED",
            json.dumps({"job_id": job_id, "agent_id": agent_id, "scanner": job["scanner"], "error_code": error_code}),
        )
    return job or {}
