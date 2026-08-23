"""
services/kev_service.py
=======================
CISA KEV (Known Exploited Vulnerabilities) Threat Intelligence Service.

Queries the official CISA Known Exploited Vulnerabilities Catalog
(https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json)
to determine whether a vulnerability is actively exploited in the wild.

Outputs strictly conform to:
{
    "kev_listed": bool | None,
    "kev_date_added": str | None
}

Key Distinctions:
- Listed in KEV        -> {"kev_listed": True,  "kev_date_added": "YYYY-MM-DD"}
- Not in KEV (Queried) -> {"kev_listed": False, "kev_date_added": None}
- Source Unreachable   -> {"kev_listed": None,  "kev_date_added": None}

Source of truth: Official CISA KEV Catalog.
Never infer KEV status from CVSS, EPSS, or severity.
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

# Official CISA KEV Catalog JSON Feed
DEFAULT_CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
DEFAULT_TIMEOUT_SECONDS = 10.0

# Regex for standard CVE and ISO date (YYYY-MM-DD)
CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$")
DATE_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}$")


class KEVService:
    """Service to download CISA KEV catalog and check CVE exploitation status."""

    def __init__(
        self,
        catalog_url: Optional[str] = None,
        timeout: Optional[float] = None,
    ):
        self.catalog_url = (
            catalog_url
            or os.getenv("CISA_KEV_URL", DEFAULT_CISA_KEV_URL)
        ).strip()

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

        # In-memory index of cveID -> dateAdded
        self._catalog_map: Optional[Dict[str, Optional[str]]] = None

    def _get_headers(self) -> Dict[str, str]:
        return {
            "User-Agent": "RizIntel-Member4-ThreatIntel/1.0",
            "Accept": "application/json",
        }

    def validate_cve_id(self, cve_id: Optional[str]) -> bool:
        """Check if CVE ID is well-formed according to standard CVE naming rules."""
        if not cve_id or not isinstance(cve_id, str):
            return False
        return bool(CVE_PATTERN.match(cve_id.strip()))

    def parse_catalog(self, raw_json: Dict[str, Any]) -> Dict[str, Optional[str]]:
        """
        Parse raw CISA KEV JSON catalog into a mapping of cveID -> dateAdded.

        Extracts vulnerabilities list and validates YYYY-MM-DD date format.
        """
        catalog_map: Dict[str, Optional[str]] = {}

        if not isinstance(raw_json, dict):
            raise ValueError("CISA KEV payload is not a valid JSON dictionary")

        vulnerabilities = raw_json.get("vulnerabilities")
        if not isinstance(vulnerabilities, list):
            raise ValueError("CISA KEV payload missing 'vulnerabilities' array")

        for item in vulnerabilities:
            if not isinstance(item, dict):
                continue

            cve_raw = item.get("cveID") or item.get("cve_id")
            if not cve_raw or not isinstance(cve_raw, str):
                continue

            cve_key = cve_raw.strip()

            date_raw = item.get("dateAdded")
            valid_date: Optional[str] = None
            if date_raw and isinstance(date_raw, str):
                date_clean = date_raw.strip()
                if DATE_PATTERN.match(date_clean):
                    valid_date = date_clean

            catalog_map[cve_key] = valid_date

        return catalog_map

    def fetch_catalog(self, force_refresh: bool = False) -> Optional[Dict[str, Optional[str]]]:
        """
        Download and parse the CISA KEV catalog.

        Returns:
            Dict[str, Optional[str]] on success, or None on network/parsing failure.
        """
        if self._catalog_map is not None and not force_refresh:
            return self._catalog_map

        headers = self._get_headers()

        try:
            with httpx.Client(timeout=self.timeout) as client:
                response = client.get(self.catalog_url, headers=headers)

                if response.status_code != 200:
                    logger.warning(
                        "CISA KEV catalog request failed with HTTP status %d",
                        response.status_code,
                    )
                    return None

                data = response.json()
                parsed = self.parse_catalog(data)
                self._catalog_map = parsed
                return self._catalog_map

        except httpx.TimeoutException as ex:
            logger.warning("CISA KEV catalog request timed out: %s", ex)
            return None
        except httpx.RequestError as ex:
            logger.warning("CISA KEV catalog network error: %s", ex)
            return None
        except Exception as ex:
            logger.error("Failed to parse CISA KEV catalog: %s", ex)
            return None

    def check_cve(
        self,
        cve_id: Optional[str],
        catalog_data: Optional[Dict[str, Optional[str]]] = None,
    ) -> Dict[str, Optional[Any]]:
        """
        Check if a CVE is listed in CISA KEV.

        Returns:
            {"kev_listed": True,  "kev_date_added": "YYYY-MM-DD"} -> Found in KEV
            {"kev_listed": False, "kev_date_added": None}         -> Successfully checked, NOT in KEV
            {"kev_listed": None,  "kev_date_added": None}         -> Catalog unreachable or invalid input
        """
        source_unavailable: Dict[str, Optional[Any]] = {
            "kev_listed": None,
            "kev_date_added": None,
        }

        if not self.validate_cve_id(cve_id):
            logger.info("KEV check skipped: invalid or missing CVE ID '%s'", cve_id)
            return source_unavailable

        assert cve_id is not None
        cve_clean = cve_id.strip()

        # Use provided catalog or fetch
        active_catalog = catalog_data if catalog_data is not None else self.fetch_catalog()

        # If catalog could not be retrieved / parsed -> Source Failure (None)
        if active_catalog is None:
            return source_unavailable

        # If present in KEV
        if cve_clean in active_catalog:
            return {
                "kev_listed": True,
                "kev_date_added": active_catalog[cve_clean],
            }

        # If not present in KEV -> Verified False
        return {
            "kev_listed": False,
            "kev_date_added": None,
        }


# Convenience singleton function
_default_kev_service = KEVService()


def get_kev_status(cve_id: Optional[str]) -> Dict[str, Optional[Any]]:
    """Retrieve normalized KEV status and date added for a given CVE ID using default service."""
    return _default_kev_service.check_cve(cve_id)


if __name__ == "__main__":
    import sys
    test_cves = sys.argv[1:] if len(sys.argv) > 1 else ["CVE-2021-44228", "CVE-2020-11023", "CVE-2099-0001"]
    print("Querying live CISA KEV Catalog...")
    service = KEVService()
    catalog = service.fetch_catalog()
    if catalog is not None:
        print(f"Catalog loaded successfully ({len(catalog)} vulnerabilities).")
        for cve in test_cves:
            result = service.check_cve(cve, catalog_data=catalog)
            print(f"  {cve}: {result}")
    else:
        print("Failed to download CISA KEV catalog.")
