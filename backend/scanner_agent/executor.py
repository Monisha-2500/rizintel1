"""
executor.py — Single-Job Execution Orchestrator

Manages the execution lifecycle of a single claimed scanner job:
  CLAIMED → RUNNING → (report uploaded) → COMPLETED / FAILED
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from scanner_agent.api_client import ApiClient
from scanner_agent.connectors import get_connector

logger = logging.getLogger("rizintel.scanner_agent.executor")


class JobExecutor:
    """Executes a single scanner job end-to-end with truthful validation."""

    def __init__(self, api_client: ApiClient, timeout: int = 120):
        self.api = api_client
        self.default_timeout = timeout

    def run(self, job: Dict[str, Any], scanner_timeout: Optional[int] = None) -> bool:
        """
        Execute a claimed job. Returns True on success, False on failure.
        """
        job_id = job.get("scanner_job_id") or job.get("job_id", "")
        scanner = (job.get("scanner") or "").upper()
        
        # Authoritative target resolution from job payload
        target_info = job.get("target") or {}
        target_url = job.get("target_url") or target_info.get("target_url", "")
        
        org_id = job.get("organization_id") or job.get("org_id", "")
        scan_run_id = job.get("scan_run_id", "")

        if not job_id:
            logger.error("Invalid job payload: missing scanner_job_id.")
            return False

        if not target_url:
            logger.error("[job:%s] Missing authoritative target_url in job payload.", job_id)
            self.api.mark_failed(job_id, "TARGET_NOT_RESOLVED", "Job target URL could not be resolved.")
            return False

        exec_timeout = scanner_timeout or self.default_timeout
        logger.info("[job:%s] Starting execution — scanner=%s target=%s (timeout: %ds)", job_id, scanner, target_url, exec_timeout)

        # Mark RUNNING
        if not self.api.mark_started(job_id):
            logger.warning("[job:%s] Could not mark started — continuing execution anyway.", job_id)

        try:
            connector = get_connector(scanner)
        except KeyError as e:
            logger.error("[job:%s] Unsupported scanner '%s': %s", job_id, scanner, e)
            self.api.mark_failed(job_id, "UNSUPPORTED_SCANNER", str(e))
            return False

        # Validate scanner availability
        is_avail, avail_reason = connector.validate_available()
        if not is_avail:
            logger.error("[job:%s] Scanner %s unavailable on host: %s", job_id, scanner, avail_reason)
            self.api.mark_failed(job_id, "BINARY_NOT_FOUND", avail_reason)
            return False

        try:
            report_bytes = connector.execute(target_url, timeout=exec_timeout)
        except TimeoutError as e:
            logger.error("[job:%s] Scanner timed out: %s", job_id, e)
            self.api.mark_failed(job_id, "EXECUTION_TIMEOUT", str(e))
            return False
        except FileNotFoundError as e:
            logger.error("[job:%s] Scanner executable missing: %s", job_id, e)
            self.api.mark_failed(job_id, "BINARY_NOT_FOUND", str(e))
            return False
        except Exception as e:
            logger.error("[job:%s] Scanner execution failed: %s", job_id, e)
            self.api.mark_failed(job_id, "EXECUTION_FAILED", str(e)[:400])
            return False

        # Empty check: if report_bytes is None, treat as empty error
        if report_bytes is None:
            logger.error("[job:%s] Scanner produced None output.", job_id)
            self.api.mark_failed(job_id, "EMPTY_REPORT", "Scanner execution produced no data.")
            return False

        # Submit report
        success = self.api.submit_report(
            job_id=job_id,
            org_id=org_id,
            scan_run_id=scan_run_id,
            scanner=scanner,
            report_bytes=report_bytes,
        )

        if success:
            logger.info("[job:%s] Report submitted successfully. Job completed.", job_id)
            return True
        else:
            logger.error("[job:%s] Report submission failed.", job_id)
            self.api.mark_failed(job_id, "REPORT_UPLOAD_FAILED", "Report upload to RizIntel server failed.")
            return False
