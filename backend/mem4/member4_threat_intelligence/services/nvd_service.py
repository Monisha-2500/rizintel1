"""
services/nvd_service.py
=======================
NVD (National Vulnerability Database) Threat Intelligence Service.

Retrieves CVSS base score and vector string for a given CVE ID using the
official NVD 2.0 REST API (https://services.nvd.nist.gov/rest/json/cves/2.0).

Outputs strictly conform to:
{
    "cvss_score": float | None,
    "cvss_vector": str | None
}

CVSS Version & Source Precedence Strategy:
1. Version Priority: CVSS v3.1 -> CVSS v4.0 -> CVSS v3.0 -> CVSS v2.0
2. Source Priority: "Primary" (official NVD analysis) -> "Secondary" (CNA analysis)
"""

from __future__ import annotations

import logging
import os
import re
from typing import Any, Dict, List, Optional
import httpx
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)

# Official NVD 2.0 API Endpoint
DEFAULT_NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
DEFAULT_TIMEOUT_SECONDS = 10.0

# Regex for standard CVE format (e.g., CVE-2021-44228)
CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$")


class NVDService:
    """Service to fetch and parse CVSS metrics from the official NVD API."""

    def __init__(
        self,
        api_url: Optional[str] = None,
        api_key: Optional[str] = None,
        timeout: Optional[float] = None,
    ):
        self.api_url = (
            api_url
            or os.getenv("NVD_API_URL", DEFAULT_NVD_API_URL)
        ).rstrip("/")
        self.api_key = api_key or os.getenv("NVD_API_KEY")
        
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
        """Build request headers including optional API key."""
        headers = {
            "User-Agent": "RizIntel-Member4-ThreatIntel/1.0",
            "Accept": "application/json",
        }
        if self.api_key:
            headers["apiKey"] = self.api_key
        return headers

    def validate_cve_id(self, cve_id: Optional[str]) -> bool:
        """Check if CVE ID is well-formed according to standard CVE naming rules."""
        if not cve_id or not isinstance(cve_id, str):
            return False
        return bool(CVE_PATTERN.match(cve_id.strip()))

    def extract_cvss(self, nvd_json: Dict[str, Any]) -> Dict[str, Optional[Any]]:
        """
        Extract the best available CVSS score and vector from NVD 2.0 response JSON.

        Strategy:
        1. Checks metrics in order: cvssMetricV31, cvssMetricV40, cvssMetricV30, cvssMetricV2.
        2. Within the chosen version list, prefers entry where type == 'Primary'.
        3. Extracts cvssData.baseScore and cvssData.vectorString.
        """
        null_result: Dict[str, Optional[Any]] = {
            "cvss_score": None,
            "cvss_vector": None,
        }

        if not isinstance(nvd_json, dict):
            return null_result

        vulnerabilities = nvd_json.get("vulnerabilities")
        if not isinstance(vulnerabilities, list) or len(vulnerabilities) == 0:
            return null_result

        cve_item = vulnerabilities[0].get("cve", {})
        metrics = cve_item.get("metrics", {})
        if not isinstance(metrics, dict) or not metrics:
            return null_result

        # Metric containers in descending order of precedence
        metric_version_keys = [
            "cvssMetricV31",
            "cvssMetricV40",
            "cvssMetricV30",
            "cvssMetricV2",
        ]

        for metric_key in metric_version_keys:
            metric_list = metrics.get(metric_key)
            if not isinstance(metric_list, list) or len(metric_list) == 0:
                continue

            # Prioritize Primary over Secondary
            selected_entry = None
            for entry in metric_list:
                if isinstance(entry, dict) and entry.get("type") == "Primary":
                    selected_entry = entry
                    break

            # Fallback to the first entry if no Primary
            if not selected_entry and isinstance(metric_list[0], dict):
                selected_entry = metric_list[0]

            if not selected_entry:
                continue

            cvss_data = selected_entry.get("cvssData")
            if not isinstance(cvss_data, dict):
                continue

            raw_score = cvss_data.get("baseScore")
            raw_vector = cvss_data.get("vectorString")

            # Validate and normalize score
            score: Optional[float] = None
            if raw_score is not None:
                try:
                    parsed_score = float(raw_score)
                    if 0.0 <= parsed_score <= 10.0:
                        score = round(parsed_score, 1)
                except (ValueError, TypeError):
                    score = None

            # Validate vector
            vector: Optional[str] = None
            if raw_vector and isinstance(raw_vector, str) and raw_vector.strip():
                vector = raw_vector.strip()

            if score is not None or vector is not None:
                return {
                    "cvss_score": score,
                    "cvss_vector": vector,
                }

        return null_result

    def fetch_cvss(self, cve_id: Optional[str]) -> Dict[str, Optional[Any]]:
        """
        Fetch CVSS details for a CVE ID from the official NVD API.

        Gracefully handles invalid formats, timeouts, network issues,
        HTTP errors, and missing data without raising unhandled exceptions.
        """
        default_empty: Dict[str, Optional[Any]] = {
            "cvss_score": None,
            "cvss_vector": None,
        }

        # Validate CVE ID format
        if not self.validate_cve_id(cve_id):
            logger.info("NVD lookup skipped: invalid or missing CVE ID '%s'", cve_id)
            return default_empty

        assert cve_id is not None
        cve_id_clean = cve_id.strip()

        params = {"cveId": cve_id_clean}
        headers = self._get_headers()

        try:
            with httpx.Client(timeout=self.timeout) as client:
                response = client.get(
                    self.api_url,
                    params=params,
                    headers=headers,
                )

                if response.status_code == 404:
                    logger.warning("NVD API returned 404 for CVE %s", cve_id_clean)
                    return default_empty

                if response.status_code == 403:
                    logger.warning("NVD API returned 403 Forbidden (check API key / rate limit) for %s", cve_id_clean)
                    return default_empty

                if response.status_code != 200:
                    logger.warning(
                        "NVD API returned unexpected HTTP status %d for %s",
                        response.status_code,
                        cve_id_clean,
                    )
                    return default_empty

                data = response.json()
                return self.extract_cvss(data)

        except httpx.TimeoutException as ex:
            logger.warning("NVD API request timed out for %s: %s", cve_id_clean, ex)
            return default_empty
        except httpx.RequestError as ex:
            logger.warning("NVD API network error for %s: %s", cve_id_clean, ex)
            return default_empty
        except Exception as ex:
            logger.error("Unexpected error during NVD lookup for %s: %s", cve_id_clean, ex)
            return default_empty


# Convenience singleton function
_default_nvd_service = NVDService()


def get_nvd_cvss(cve_id: Optional[str]) -> Dict[str, Optional[Any]]:
    """Retrieve normalized CVSS information for a given CVE ID using default NVD service."""
    return _default_nvd_service.fetch_cvss(cve_id)


if __name__ == "__main__":
    import sys
    test_cve = sys.argv[1] if len(sys.argv) > 1 else "CVE-2021-44228"
    print(f"Querying NVD for {test_cve}...")
    service = NVDService()
    result = service.fetch_cvss(test_cve)
    print(f"Result: {result}")
