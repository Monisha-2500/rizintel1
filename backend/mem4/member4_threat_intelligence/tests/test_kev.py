"""
tests/test_kev.py
=================
Unit tests for Member 4 CISA KEV Threat Intelligence Service (services/kev_service.py).

All external network operations are mocked with unittest.mock for 100% offline, deterministic testing.

Test Scenarios:
1. CVE present in KEV with valid dateAdded -> {"kev_listed": True, "kev_date_added": "YYYY-MM-DD"}
2. CVE present in KEV without dateAdded / malformed date -> {"kev_listed": True, "kev_date_added": None}
3. CVE verified NOT present in KEV -> {"kev_listed": False, "kev_date_added": None}
4. Empty KEV catalog -> {"kev_listed": False, "kev_date_added": None}
5. Invalid / Null CVE inputs (None, empty, malformed) -> skips fetch or returns None
6. HTTP errors on catalog download (404, 500, 503) -> {"kev_listed": None, "kev_date_added": None}
7. Timeout handling on catalog download -> {"kev_listed": None, "kev_date_added": None}
8. Network failure (ConnectError) -> {"kev_listed": None, "kev_date_added": None}
9. Malformed catalog response (non-dict, missing 'vulnerabilities' key, bad JSON) -> None
10. Multiple entries with distinct dates parsed correctly
11. Explicit catalog dependency injection for efficient batch/cached lookups
12. Verification of strict 3-state distinction: True (hit) vs False (miss) vs None (source failure)
"""

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch
import httpx
import pytest

# Ensure member4_threat_intelligence is in PYTHONPATH
sys.path.insert(0, str(Path(__file__).parent.parent))

from services.kev_service import KEVService, get_kev_status


# ---------------------------------------------------------------------------
# Fixture payloads representing official CISA KEV JSON catalog
# ---------------------------------------------------------------------------

SAMPLE_KEV_CATALOG = {
    "title": "CISA Known Exploited Vulnerabilities Catalog",
    "catalogVersion": "2024.04.01",
    "dateReleased": "2024-04-01T00:00:00.000Z",
    "count": 3,
    "vulnerabilities": [
        {
            "cveID": "CVE-2021-44228",
            "vendorProject": "Apache",
            "product": "Log4j",
            "vulnerabilityName": "Apache Log4j RCE",
            "dateAdded": "2021-12-10",
            "shortDescription": "Log4j Remote Code Execution",
            "requiredAction": "Apply updates",
            "dueDate": "2021-12-24",
            "knownRansomwareCampaignUse": "Known",
        },
        {
            "cveID": "CVE-2018-7600",
            "vendorProject": "Drupal",
            "product": "Drupal Core",
            "vulnerabilityName": "Drupalgeddon2 RCE",
            "dateAdded": "2022-03-25",
            "shortDescription": "Drupal Remote Code Execution",
            "requiredAction": "Apply updates",
            "dueDate": "2022-04-15",
            "knownRansomwareCampaignUse": "Known",
        },
        {
            "cveID": "CVE-2024-3400",
            "vendorProject": "Palo Alto Networks",
            "product": "PAN-OS",
            "vulnerabilityName": "PAN-OS Command Injection",
            "dateAdded": "2024-04-12",
            "shortDescription": "PAN-OS Command Injection Vulnerability",
            "requiredAction": "Apply mitigations",
            "dueDate": "2024-04-19",
            "knownRansomwareCampaignUse": "Known",
        },
    ],
}

SAMPLE_KEV_EMPTY_CATALOG = {
    "title": "CISA Known Exploited Vulnerabilities Catalog",
    "catalogVersion": "2024.04.01",
    "count": 0,
    "vulnerabilities": [],
}


# ===========================================================================
# Unit Tests
# ===========================================================================

class TestKEVService:
    @pytest.fixture
    def service(self):
        return KEVService(timeout=5.0)

    def test_cve_present_in_kev(self, service):
        """CVE found in catalog must return kev_listed=True and valid dateAdded."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = SAMPLE_KEV_CATALOG

        with patch("httpx.Client.get", return_value=mock_resp) as mock_get:
            result = service.check_cve("CVE-2021-44228")

            mock_get.assert_called_once()
            assert result == {
                "kev_listed": True,
                "kev_date_added": "2021-12-10",
            }
            assert isinstance(result["kev_listed"], bool)
            assert isinstance(result["kev_date_added"], str)

    def test_cve_present_without_date_added(self, service):
        """CVE present in KEV with missing dateAdded returns True with null date."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "vulnerabilities": [
                {
                    "cveID": "CVE-2021-44228",
                    "dateAdded": None,
                }
            ]
        }

        with patch("httpx.Client.get", return_value=mock_resp):
            result = service.check_cve("CVE-2021-44228")
            assert result == {
                "kev_listed": True,
                "kev_date_added": None,
            }

    def test_cve_present_with_malformed_date_added(self, service):
        """CVE present in KEV with invalid date format returns None for date."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "vulnerabilities": [
                {
                    "cveID": "CVE-2021-44228",
                    "dateAdded": "InvalidDate123",
                }
            ]
        }

        with patch("httpx.Client.get", return_value=mock_resp):
            result = service.check_cve("CVE-2021-44228")
            assert result == {
                "kev_listed": True,
                "kev_date_added": None,
            }

    def test_cve_not_present_in_kev_returns_false(self, service):
        """When catalog is successfully retrieved but CVE is absent, return False."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = SAMPLE_KEV_CATALOG

        with patch("httpx.Client.get", return_value=mock_resp):
            result = service.check_cve("CVE-2020-11023")
            assert result == {
                "kev_listed": False,
                "kev_date_added": None,
            }
            assert result["kev_listed"] is False

    def test_empty_catalog_returns_false(self, service):
        """Empty vulnerabilities list successfully returns False for searched CVE."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = SAMPLE_KEV_EMPTY_CATALOG

        with patch("httpx.Client.get", return_value=mock_resp):
            result = service.check_cve("CVE-2021-44228")
            assert result == {
                "kev_listed": False,
                "kev_date_added": None,
            }

    @pytest.mark.parametrize("invalid_cve", [
        None,
        "",
        "   ",
        "INVALID-CVE",
        "CVE-20-1234",
        "cve-2021-44228",
        12345,
    ])
    def test_invalid_cve_skips_network_call(self, service, invalid_cve):
        """Invalid CVE IDs must immediately return null without making network requests."""
        with patch("httpx.Client.get") as mock_get:
            result = service.check_cve(invalid_cve)
            mock_get.assert_not_called()
            assert result == {"kev_listed": None, "kev_date_added": None}

    def test_http_404_catalog_returns_null(self, service):
        """Source failure (HTTP 404) returns None (unknown), NOT False."""
        mock_resp = MagicMock()
        mock_resp.status_code = 404

        with patch("httpx.Client.get", return_value=mock_resp):
            result = service.check_cve("CVE-2021-44228")
            assert result == {"kev_listed": None, "kev_date_added": None}

    def test_http_500_catalog_returns_null(self, service):
        """Source failure (HTTP 500) returns None (unknown), NOT False."""
        mock_resp = MagicMock()
        mock_resp.status_code = 500

        with patch("httpx.Client.get", return_value=mock_resp):
            result = service.check_cve("CVE-2021-44228")
            assert result == {"kev_listed": None, "kev_date_added": None}

    def test_http_timeout_returns_null(self, service):
        """Timeout on catalog download returns None."""
        with patch("httpx.Client.get", side_effect=httpx.TimeoutException("Timeout")):
            result = service.check_cve("CVE-2021-44228")
            assert result == {"kev_listed": None, "kev_date_added": None}

    def test_network_connection_error_returns_null(self, service):
        """ConnectError on catalog download returns None."""
        with patch("httpx.Client.get", side_effect=httpx.ConnectError("Network unreachable")):
            result = service.check_cve("CVE-2021-44228")
            assert result == {"kev_listed": None, "kev_date_added": None}

    def test_malformed_json_response_returns_null(self, service):
        """Malformed JSON from CISA feed returns None without crashing."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.side_effect = ValueError("Invalid JSON")

        with patch("httpx.Client.get", return_value=mock_resp):
            result = service.check_cve("CVE-2021-44228")
            assert result == {"kev_listed": None, "kev_date_added": None}

    def test_missing_vulnerabilities_array_returns_null(self, service):
        """JSON payload missing 'vulnerabilities' key returns None."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"title": "CISA KEV", "count": 0}

        with patch("httpx.Client.get", return_value=mock_resp):
            result = service.check_cve("CVE-2021-44228")
            assert result == {"kev_listed": None, "kev_date_added": None}

    def test_preloaded_catalog_lookup(self, service):
        """Testing lookup using pre-fetched catalog map without network requests."""
        preloaded_catalog = {
            "CVE-2021-44228": "2021-12-10",
            "CVE-2018-7600": "2022-03-25",
        }

        with patch("httpx.Client.get") as mock_get:
            hit = service.check_cve("CVE-2021-44228", catalog_data=preloaded_catalog)
            miss = service.check_cve("CVE-2020-11023", catalog_data=preloaded_catalog)

            mock_get.assert_not_called()
            assert hit == {"kev_listed": True, "kev_date_added": "2021-12-10"}
            assert miss == {"kev_listed": False, "kev_date_added": None}

    def test_convenience_function(self):
        """Test get_kev_status top-level helper."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = SAMPLE_KEV_CATALOG

        with patch("httpx.Client.get", return_value=mock_resp):
            result = get_kev_status("CVE-2024-3400")
            assert result == {
                "kev_listed": True,
                "kev_date_added": "2024-04-12",
            }
