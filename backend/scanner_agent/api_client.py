"""
api_client.py — Machine API Client for Scanner Agents

Handles machine-authenticated HTTP communication with RizIntel backend:
- Atomic job claiming: POST /v1/agent/jobs/claim
- Lifecycle updates: POST /v1/agent/jobs/{job_id}/started
- Report submission: POST /v1/agent/jobs/{job_id}/report
- Failure reporting: POST /v1/agent/jobs/{job_id}/failed
- Periodic capability heartbeats: POST /v1/agent/heartbeat
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional
import httpx

logger = logging.getLogger("rizintel.scanner_agent.api_client")


class ApiClient:
    """Authenticated HTTP client for scanner agent machine endpoints."""

    def __init__(self, server_url: str, agent_token: str):
        self.server_url = server_url.rstrip("/")
        self.agent_token = agent_token
        self._auth_headers = {
            "X-Scanner-Agent-Token": agent_token,
            "Authorization": f"AgentToken {agent_token}",
        }

    def _url(self, path: str) -> str:
        return self.server_url + path

    def claim_job(self, capabilities: Optional[List[str]] = None) -> Optional[Dict[str, Any]]:
        """
        Attempt to claim a QUEUED job matching the agent's available scanner capabilities.
        Returns job dictionary or None if no matching jobs are queued.
        """
        caps = capabilities if capabilities is not None else ["NUCLEI", "ZAP", "WAPITI"]
        try:
            headers = {**self._auth_headers, "Content-Type": "application/json"}
            resp = httpx.post(
                self._url("/v1/agent/jobs/claim"),
                headers=headers,
                json={"capabilities": caps},
                timeout=15.0,
            )
            if resp.status_code == 200:
                data = resp.json()
                # Backend returns {"job": job_dict_or_null}
                if isinstance(data, dict) and "job" in data:
                    return data["job"]
                return data
            if resp.status_code == 204:
                return None
            logger.warning("claim_job unexpected status %d: %s", resp.status_code, resp.text[:200])
            return None
        except Exception as e:
            logger.error("claim_job request failed: %s", e)
            return None

    def mark_started(self, job_id: str) -> bool:
        """Notify server that job execution has started."""
        try:
            resp = httpx.post(
                self._url(f"/v1/agent/jobs/{job_id}/started"),
                headers=self._auth_headers,
                timeout=10.0,
            )
            return resp.status_code in (200, 201)
        except Exception as e:
            logger.error("mark_started request failed for job %s: %s", job_id, e)
            return False

    def submit_report(
        self,
        job_id: str,
        org_id: str,
        scan_run_id: str,
        scanner: str,
        report_bytes: bytes,
        content_type: str = "application/json",
    ) -> bool:
        """Submit native scanner report bytes via machine agent report endpoint."""
        try:
            scanner_upper = scanner.upper()
            if scanner_upper == "ZAP":
                filename = "zap_report.json"
                mime = "application/json"
            elif scanner_upper == "NUCLEI":
                filename = "nuclei_report.jsonl"
                mime = "application/x-ndjson"
            elif scanner_upper == "WAPITI":
                filename = "wapiti_report.json"
                mime = "application/json"
            else:
                filename = f"{scanner.lower()}_report.json"
                mime = content_type

            # Use official machine endpoint: POST /v1/agent/jobs/{job_id}/report
            upload_url = self._url(f"/v1/agent/jobs/{job_id}/report")

            resp = httpx.post(
                upload_url,
                headers=self._auth_headers,
                files={"file": (filename, report_bytes, mime)},
                data={"scanner": scanner_upper},
                timeout=60.0,
            )
            if resp.status_code in (200, 201):
                logger.info("Report submitted successfully for job %s", job_id)
                return True
            logger.warning(
                "submit_report unexpected status %d for job %s: %s",
                resp.status_code, job_id, resp.text[:300]
            )
            return False
        except Exception as e:
            logger.error("submit_report failed for job %s: %s", job_id, e)
            return False

    def mark_failed(self, job_id: str, error_code: str = "EXECUTION_ERROR", error_message: str = "") -> bool:
        """Report job execution failure to the server."""
        try:
            headers = {**self._auth_headers, "Content-Type": "application/json"}
            resp = httpx.post(
                self._url(f"/v1/agent/jobs/{job_id}/failed"),
                headers=headers,
                json={"error_code": error_code, "error_message": error_message[:500]},
                timeout=10.0,
            )
            return resp.status_code in (200, 201)
        except Exception as e:
            logger.error("mark_failed request failed for job %s: %s", job_id, e)
            return False

    def heartbeat(self, capabilities: Optional[Dict[str, Any]] = None) -> bool:
        """Send agent liveness heartbeat and advertise truthful capabilities."""
        try:
            headers = {**self._auth_headers, "Content-Type": "application/json"}
            payload = {"capabilities": capabilities} if capabilities is not None else {}
            resp = httpx.post(
                self._url("/v1/agent/heartbeat"),
                headers=headers,
                json=payload,
                timeout=10.0,
            )
            return resp.status_code in (200, 201)
        except Exception as e:
            logger.debug("heartbeat failed: %s", e)
            return False
