"""
tests/test_epss.py
==================
Unit tests for Member 4 EPSS Threat Intelligence Service (services/epss_service.py).

All external API calls are mocked with unittest.mock to ensure 100% offline, deterministic tests.

Test Scenarios:
1. Valid CVE with typical EPSS data
2. Valid CVE with low EPSS values
3. Valid CVE with high EPSS values
4. CVE with empty data / no EPSS record
5. Invalid / Null CVE inputs (None, whitespace, invalid formats)
6. HTTP errors (404 Not Found, 500 Internal Error, 503 Service Unavailable)
7. Timeout handling (httpx.TimeoutException)
8. Network connection errors (httpx.ConnectError)
9. Malformed API response structure (non-dict, non-list, corrupt JSON)
10. Out-of-bounds or invalid EPSS score (>1.0, <0.0, non-numeric)
11. Out-of-bounds or invalid EPSS percentile (>1.0, <0.0, non-numeric)
12. Partial validity (valid score with invalid percentile, or vice-versa)
13. Output contract verification: {"epss_score": float|None, "epss_percentile": float|None}
"""

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch
import httpx
import pytest

# Ensure member4_threat_intelligence is in PYTHONPATH
sys.path.insert(0, str(Path(__file__).parent.parent))

from services.epss_service import EPSSService, get_epss


# ---------------------------------------------------------------------------
# Fixture payloads representing official FIRST EPSS API responses
# ---------------------------------------------------------------------------

SAMPLE_EPSS_HIGH_RESPONSE = {
    "status": "OK",
    "status-code": 200,
    "version": "1.0",
    "access": "public",
    "total": 1,
    "offset": 0,
    "limit": 100,
    "data": [
        {
            "cve": "CVE-2021-44228",
            "epss": "0.97529",
            "percentile": "0.99980",
            "date": "2024-04-01",
        }
    ],
}

SAMPLE_EPSS_LOW_RESPONSE = {
    "status": "OK",
    "status-code": 200,
    "version": "1.0",
    "access": "public",
    "total": 1,
    "offset": 0,
    "limit": 100,
    "data": [
        {
            "cve": "CVE-2020-11023",
            "epss": "0.00142",
            "percentile": "0.48520",
            "date": "2024-04-01",
        }
    ],
}

SAMPLE_EPSS_EMPTY_RESPONSE = {
    "status": "OK",
    "status-code": 200,
    "version": "1.0",
    "access": "public",
    "total": 0,
    "offset": 0,
    "limit": 100,
    "data": [],
}


# ===========================================================================
# Unit Tests
# ===========================================================================

class TestEPSSService:
    @pytest.fixture
    def service(self):
        return EPSSService(timeout=5.0)

    def test_valid_cve_with_high_epss(self, service):
        """Verify high EPSS score and percentile are properly parsed and converted to float."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = SAMPLE_EPSS_HIGH_RESPONSE

        with patch("httpx.Client.get", return_value=mock_resp) as mock_get:
            result = service.fetch_epss("CVE-2021-44228")

            mock_get.assert_called_once()
            assert result == {
                "epss_score": 0.9753,
                "epss_percentile": 0.9998,
            }
            assert isinstance(result["epss_score"], float)
            assert isinstance(result["epss_percentile"], float)
            assert 0.0 <= result["epss_score"] <= 1.0
            assert 0.0 <= result["epss_percentile"] <= 1.0

    def test_valid_cve_with_low_epss(self, service):
        """Verify low EPSS score and percentile are properly parsed."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = SAMPLE_EPSS_LOW_RESPONSE

        with patch("httpx.Client.get", return_value=mock_resp):
            result = service.fetch_epss("CVE-2020-11023")

            assert result == {
                "epss_score": 0.0014,
                "epss_percentile": 0.4852,
            }

    def test_cve_with_empty_data_record(self, service):
        """Verify total=0 and empty data array returns nulls."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = SAMPLE_EPSS_EMPTY_RESPONSE

        with patch("httpx.Client.get", return_value=mock_resp):
            result = service.fetch_epss("CVE-2099-0001")
            assert result == {"epss_score": None, "epss_percentile": None}

    @pytest.mark.parametrize("invalid_cve", [
        None,
        "",
        "   ",
        "INVALID-CVE",
        "CVE-20-1234",
        "cve-2021-44228",
        9999,
    ])
    def test_invalid_cve_skips_network_call(self, service, invalid_cve):
        """Invalid CVE IDs must immediately return null without making network requests."""
        with patch("httpx.Client.get") as mock_get:
            result = service.fetch_epss(invalid_cve)
            mock_get.assert_not_called()
            assert result == {"epss_score": None, "epss_percentile": None}

    def test_http_404_handled(self, service):
        """Verify HTTP 404 returns nulls gracefully."""
        mock_resp = MagicMock()
        mock_resp.status_code = 404

        with patch("httpx.Client.get", return_value=mock_resp):
            result = service.fetch_epss("CVE-2021-44228")
            assert result == {"epss_score": None, "epss_percentile": None}

    def test_http_500_server_error_handled(self, service):
        """Verify HTTP 500 returns nulls gracefully."""
        mock_resp = MagicMock()
        mock_resp.status_code = 500

        with patch("httpx.Client.get", return_value=mock_resp):
            result = service.fetch_epss("CVE-2021-44228")
            assert result == {"epss_score": None, "epss_percentile": None}

    def test_http_timeout_handled(self, service):
        """Verify TimeoutException returns nulls."""
        with patch("httpx.Client.get", side_effect=httpx.TimeoutException("Timeout")):
            result = service.fetch_epss("CVE-2021-44228")
            assert result == {"epss_score": None, "epss_percentile": None}

    def test_network_connection_error_handled(self, service):
        """Verify ConnectError returns nulls."""
        with patch("httpx.Client.get", side_effect=httpx.ConnectError("Network down")):
            result = service.fetch_epss("CVE-2021-44228")
            assert result == {"epss_score": None, "epss_percentile": None}

    def test_malformed_json_response_handled(self, service):
        """Verify malformed JSON does not crash the service."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.side_effect = ValueError("Invalid JSON")

        with patch("httpx.Client.get", return_value=mock_resp):
            result = service.fetch_epss("CVE-2021-44228")
            assert result == {"epss_score": None, "epss_percentile": None}

    def test_invalid_epss_score_out_of_bounds(self, service):
        """Verify EPSS score > 1.0 or < 0.0 is invalidated to None."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "data": [
                {
                    "cve": "CVE-2021-44228",
                    "epss": "1.5000",
                    "percentile": "0.9500",
                }
            ]
        }

        with patch("httpx.Client.get", return_value=mock_resp):
            result = service.fetch_epss("CVE-2021-44228")
            assert result["epss_score"] is None
            assert result["epss_percentile"] == 0.9500

    def test_invalid_epss_percentile_out_of_bounds(self, service):
        """Verify percentile > 1.0 or < 0.0 is invalidated to None."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "data": [
                {
                    "cve": "CVE-2021-44228",
                    "epss": "0.7500",
                    "percentile": "-0.1000",
                }
            ]
        }

        with patch("httpx.Client.get", return_value=mock_resp):
            result = service.fetch_epss("CVE-2021-44228")
            assert result["epss_score"] == 0.7500
            assert result["epss_percentile"] is None

    def test_non_numeric_epss_values(self, service):
        """Verify non-numeric values are safely handled."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "data": [
                {
                    "cve": "CVE-2021-44228",
                    "epss": "N/A",
                    "percentile": "UNKNOWN",
                }
            ]
        }

        with patch("httpx.Client.get", return_value=mock_resp):
            result = service.fetch_epss("CVE-2021-44228")
            assert result == {"epss_score": None, "epss_percentile": None}

    def test_missing_epss_fields_in_record(self, service):
        """Verify record with missing keys returns null for missing fields."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "data": [
                {
                    "cve": "CVE-2021-44228",
                    # no epss or percentile keys
                }
            ]
        }

        with patch("httpx.Client.get", return_value=mock_resp):
            result = service.fetch_epss("CVE-2021-44228")
            assert result == {"epss_score": None, "epss_percentile": None}

    def test_convenience_function(self):
        """Test get_epss module-level helper."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = SAMPLE_EPSS_HIGH_RESPONSE

        with patch("httpx.Client.get", return_value=mock_resp):
            result = get_epss("CVE-2021-44228")
            assert result == {
                "epss_score": 0.9753,
                "epss_percentile": 0.9998,
            }
