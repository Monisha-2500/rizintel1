"""
services/epss_service.py
========================
EPSS (Exploit Prediction Scoring System) Threat Intelligence Service.

Retrieves EPSS probability score and percentile for a given CVE ID using the
official FIRST EPSS REST API (https://api.first.org/data/v1/epss).

Outputs strictly conform to:
{
    "epss_score": float | None,
    "epss_percentile": float | None
}

Contract constraints:
- epss_score: range [0.0, 1.0] (probability of exploitation in the wild in next 30 days)
- epss_percentile: range [0.0, 1.0] (relative ranking among all scored CVEs)
- If unavailable or invalid, returns None without crashing or fabricating values.
"""

from __future__ import annotations

import logging
import os
import re
from typing import Any, Dict, Optional
import httpx
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)

# Official FIRST EPSS API Endpoint
DEFAULT_EPSS_API_URL = "https://api.first.org/data/v1/epss"
DEFAULT_TIMEOUT_SECONDS = 10.0

# Regex for standard CVE format (e.g., CVE-2021-44228)
CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$")


class EPSSService:
    """Service to fetch and parse EPSS metrics from the official FIRST EPSS API."""

    def __init__(
        self,
        api_url: Optional[str] = None,
        timeout: Optional[float] = None,
    ):
        self.api_url = (
            api_url
            or os.getenv("EPSS_API_URL", DEFAULT_EPSS_API_URL)
        ).rstrip("/")

        timeout_env = os.getenv("REQUEST_TIMEOUT_SECONDS")
        if timeout is not None:
            self.timeout = float(timeout)
        elif timeout_env:
            try:
                self.timeout = float(timeout_env)
            except ValueError:
                self.timeout = DEFAULT_TIMEOUT_SECONDS
        else:
            self.timeout = DEFAULT_TIMEOUT_SECONDS

    def _get_headers(self) -> Dict[str, str]:
        """Build request headers for FIRST EPSS API."""
        return {
            "User-Agent": "RizIntel-Member4-ThreatIntel/1.0",
            "Accept": "application/json",
        }

    def validate_cve_id(self, cve_id: Optional[str]) -> bool:
        """Check if CVE ID is well-formed according to standard CVE naming rules."""
        if not cve_id or not isinstance(cve_id, str):
            return False
        return bool(CVE_PATTERN.match(cve_id.strip()))

    def extract_epss(self, response_json: Dict[str, Any]) -> Dict[str, Optional[float]]:
        """
        Extract and validate epss_score and epss_percentile from FIRST EPSS API JSON.

        Validates:
        - 0.0 <= epss_score <= 1.0
        - 0.0 <= epss_percentile <= 1.0
        """
        null_result: Dict[str, Optional[float]] = {
            "epss_score": None,
            "epss_percentile": None,
        }

        if not isinstance(response_json, dict):
            return null_result

        data_list = response_json.get("data")
        if not isinstance(data_list, list) or len(data_list) == 0:
            return null_result

        record = data_list[0]
        if not isinstance(record, dict):
            return null_result

        raw_epss = record.get("epss")
        raw_percentile = record.get("percentile")

        # Parse and validate epss score
        epss_score: Optional[float] = None
        if raw_epss is not None:
            try:
                parsed_score = float(raw_epss)
                if 0.0 <= parsed_score <= 1.0:
                    epss_score = round(parsed_score, 4)
                else:
                    logger.warning("EPSS score out of [0.0, 1.0] range: %s", raw_epss)
            except (ValueError, TypeError):
                logger.warning("Failed to parse EPSS score as float: %s", raw_epss)

        # Parse and validate epss percentile
        epss_percentile: Optional[float] = None
        if raw_percentile is not None:
            try:
                parsed_percentile = float(raw_percentile)
                if 0.0 <= parsed_percentile <= 1.0:
                    epss_percentile = round(parsed_percentile, 4)
                else:
                    logger.warning("EPSS percentile out of [0.0, 1.0] range: %s", raw_percentile)
            except (ValueError, TypeError):
                logger.warning("Failed to parse EPSS percentile as float: %s", raw_percentile)

        return {
            "epss_score": epss_score,
            "epss_percentile": epss_percentile,
        }

    def fetch_epss(self, cve_id: Optional[str]) -> Dict[str, Optional[float]]:
        """
        Fetch EPSS details for a CVE ID from the official FIRST API.

        Gracefully handles invalid CVE formats, timeouts, network issues,
        HTTP errors, empty records, and malformed data without raising unhandled exceptions.
        """
        default_empty: Dict[str, Optional[float]] = {
            "epss_score": None,
            "epss_percentile": None,
        }

        if not self.validate_cve_id(cve_id):
            logger.info("EPSS lookup skipped: invalid or missing CVE ID '%s'", cve_id)
            return default_empty

        assert cve_id is not None
        cve_id_clean = cve_id.strip()

        params = {"cve": cve_id_clean}
        headers = self._get_headers()

        try:
            with httpx.Client(timeout=self.timeout) as client:
                response = client.get(
                    self.api_url,
                    params=params,
                    headers=headers,
                )

                if response.status_code == 404:
                    logger.warning("EPSS API returned 404 for CVE %s", cve_id_clean)
                    return default_empty

                if response.status_code != 200:
                    logger.warning(
                        "EPSS API returned HTTP status %d for %s",
                        response.status_code,
                        cve_id_clean,
                    )
                    return default_empty

                data = response.json()
                return self.extract_epss(data)

        except httpx.TimeoutException as ex:
            logger.warning("EPSS API request timed out for %s: %s", cve_id_clean, ex)
            return default_empty
        except httpx.RequestError as ex:
            logger.warning("EPSS API network error for %s: %s", cve_id_clean, ex)
            return default_empty
        except Exception as ex:
            logger.error("Unexpected error during EPSS lookup for %s: %s", cve_id_clean, ex)
            return default_empty


# Convenience singleton function
_default_epss_service = EPSSService()


def get_epss(cve_id: Optional[str]) -> Dict[str, Optional[float]]:
    """Retrieve normalized EPSS score and percentile for a given CVE ID using default service."""
    return _default_epss_service.fetch_epss(cve_id)


if __name__ == "__main__":
    import sys
    test_cve = sys.argv[1] if len(sys.argv) > 1 else "CVE-2021-44228"
    print(f"Querying live FIRST EPSS API for {test_cve}...")
    service = EPSSService()
    result = service.fetch_epss(test_cve)
    print(f"Result: {result}")
