"""
tests/test_nvd.py
=================
Unit tests for Member 4 NVD Threat Intelligence Service (services/nvd_service.py).

All external API calls are mocked to ensure 100% fast, deterministic, offline execution.

Test Scenarios:
1. Valid CVE with CVSS v3.1 data (Primary and Secondary preference)
2. Valid CVE with CVSS v4.0 data
3. Valid CVE with CVSS v3.0 data
4. Valid CVE with CVSS v2.0 data
5. Valid CVE with empty/missing metrics
6. CVE not found in NVD (totalResults = 0 or 404 response)
7. Invalid / Null CVE inputs (None, empty, malformed format)
8. HTTP error responses (403 Forbidden, 500 Internal Error, 503 Unavailable)
9. Network timeout (httpx.TimeoutException) and connection error (httpx.ConnectError)
10. Malformed / Corrupted JSON responses
11. Returned dictionary structure & type verification
"""

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch
import httpx
import pytest

# Ensure member4_threat_intelligence is in PYTHONPATH
sys.path.insert(0, str(Path(__file__).parent.parent))

from services.nvd_service import NVDService, get_nvd_cvss


# ---------------------------------------------------------------------------
# Fixture payloads representing official NVD 2.0 API responses
# ---------------------------------------------------------------------------

SAMPLE_NVD_V31_RESPONSE = {
    "resultsPerPage": 1,
    "startIndex": 0,
    "totalResults": 1,
    "format": "NVD_CVE",
    "version": "2.0",
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2021-44228",
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "source": "nvd@nist.gov",
                            "type": "Primary",
                            "cvssData": {
                                "version": "3.1",
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                                "baseScore": 10.0,
                                "baseSeverity": "CRITICAL",
                            },
                        },
                        {
                            "source": "cve@mitre.org",
                            "type": "Secondary",
                            "cvssData": {
                                "version": "3.1",
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                "baseScore": 9.8,
                                "baseSeverity": "CRITICAL",
                            },
                        },
                    ]
                },
            }
        }
    ],
}

SAMPLE_NVD_V40_RESPONSE = {
    "totalResults": 1,
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2024-3400",
                "metrics": {
                    "cvssMetricV40": [
                        {
                            "source": "nvd@nist.gov",
                            "type": "Primary",
                            "cvssData": {
                                "version": "4.0",
                                "vectorString": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H",
                                "baseScore": 10.0,
                            },
                        }
                    ]
                },
            }
        }
    ],
}

SAMPLE_NVD_V30_RESPONSE = {
    "totalResults": 1,
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2018-7600",
                "metrics": {
                    "cvssMetricV30": [
                        {
                            "source": "nvd@nist.gov",
                            "type": "Primary",
                            "cvssData": {
                                "version": "3.0",
                                "vectorString": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                "baseScore": 9.8,
                            },
                        }
                    ]
                },
            }
        }
    ],
}

SAMPLE_NVD_V2_RESPONSE = {
    "totalResults": 1,
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2012-1823",
                "metrics": {
                    "cvssMetricV2": [
                        {
                            "source": "nvd@nist.gov",
                            "type": "Primary",
                            "cvssData": {
                                "version": "2.0",
                                "vectorString": "AV:N/AC:L/Au:N/C:P/I:P/A:P",
                                "baseScore": 7.5,
                            },
                        }
                    ]
                },
            }
        }
    ],
}


# ===========================================================================
# Unit Tests
# ===========================================================================

class TestNVDService:
    @pytest.fixture
    def service(self):
        return NVDService(timeout=5.0)

    def test_valid_cve_with_cvss_v31_primary_selected(self, service):
        """Verify CVSS v3.1 Primary entry is selected over Secondary."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = SAMPLE_NVD_V31_RESPONSE

        with patch("httpx.Client.get", return_value=mock_resp) as mock_get:
            result = service.fetch_cvss("CVE-2021-44228")

            mock_get.assert_called_once()
            assert result == {
                "cvss_score": 10.0,
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
            }
            assert isinstance(result["cvss_score"], float)
            assert isinstance(result["cvss_vector"], str)

    def test_valid_cve_with_cvss_v40(self, service):
        """Verify CVSS v4.0 is extracted properly."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = SAMPLE_NVD_V40_RESPONSE

        with patch("httpx.Client.get", return_value=mock_resp):
            result = service.fetch_cvss("CVE-2024-3400")
            assert result["cvss_score"] == 10.0
            assert "CVSS:4.0" in result["cvss_vector"]

    def test_valid_cve_with_cvss_v30(self, service):
        """Verify CVSS v3.0 is extracted properly when v3.1 is absent."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = SAMPLE_NVD_V30_RESPONSE

        with patch("httpx.Client.get", return_value=mock_resp):
            result = service.fetch_cvss("CVE-2018-7600")
            assert result["cvss_score"] == 9.8
            assert "CVSS:3.0" in result["cvss_vector"]

    def test_valid_cve_with_cvss_v2(self, service):
        """Verify legacy CVSS v2 is extracted when v3/v4 are absent."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = SAMPLE_NVD_V2_RESPONSE

        with patch("httpx.Client.get", return_value=mock_resp):
            result = service.fetch_cvss("CVE-2012-1823")
            assert result["cvss_score"] == 7.5
            assert result["cvss_vector"] == "AV:N/AC:L/Au:N/C:P/I:P/A:P"

    def test_valid_cve_without_cvss_metrics(self, service):
        """Verify empty metrics dictionary yields null values without error."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "totalResults": 1,
            "vulnerabilities": [{"cve": {"id": "CVE-2024-99999", "metrics": {}}}],
        }

        with patch("httpx.Client.get", return_value=mock_resp):
            result = service.fetch_cvss("CVE-2024-99999")
            assert result == {"cvss_score": None, "cvss_vector": None}

    def test_cve_not_found_empty_vulnerabilities(self, service):
        """Verify totalResults=0 returns null CVSS data."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "totalResults": 0,
            "vulnerabilities": [],
        }

        with patch("httpx.Client.get", return_value=mock_resp):
            result = service.fetch_cvss("CVE-2099-0001")
            assert result == {"cvss_score": None, "cvss_vector": None}

    def test_cve_not_found_404_status(self, service):
        """Verify HTTP 404 returns null values without throwing exceptions."""
        mock_resp = MagicMock()
        mock_resp.status_code = 404

        with patch("httpx.Client.get", return_value=mock_resp):
            result = service.fetch_cvss("CVE-2099-0001")
            assert result == {"cvss_score": None, "cvss_vector": None}

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
        """Invalid CVE IDs must immediately return null without network activity."""
        with patch("httpx.Client.get") as mock_get:
            result = service.fetch_cvss(invalid_cve)
            mock_get.assert_not_called()
            assert result == {"cvss_score": None, "cvss_vector": None}

    def test_http_403_rate_limit_handled(self, service):
        """Verify 403 Forbidden returns null and does not crash."""
        mock_resp = MagicMock()
        mock_resp.status_code = 403

        with patch("httpx.Client.get", return_value=mock_resp):
            result = service.fetch_cvss("CVE-2021-44228")
            assert result == {"cvss_score": None, "cvss_vector": None}

    def test_http_500_server_error_handled(self, service):
        """Verify HTTP 500 error returns null gracefully."""
        mock_resp = MagicMock()
        mock_resp.status_code = 500

        with patch("httpx.Client.get", return_value=mock_resp):
            result = service.fetch_cvss("CVE-2021-44228")
            assert result == {"cvss_score": None, "cvss_vector": None}

    def test_http_timeout_handled(self, service):
        """Verify TimeoutException is caught and returns null."""
        with patch("httpx.Client.get", side_effect=httpx.TimeoutException("Request timed out")):
            result = service.fetch_cvss("CVE-2021-44228")
            assert result == {"cvss_score": None, "cvss_vector": None}

    def test_network_connection_error_handled(self, service):
        """Verify ConnectError is caught and returns null."""
        with patch("httpx.Client.get", side_effect=httpx.ConnectError("Network unreachable")):
            result = service.fetch_cvss("CVE-2021-44228")
            assert result == {"cvss_score": None, "cvss_vector": None}

    def test_malformed_json_response_handled(self, service):
        """Verify malformed JSON does not crash the service."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.side_effect = ValueError("Invalid JSON string")

        with patch("httpx.Client.get", return_value=mock_resp):
            result = service.fetch_cvss("CVE-2021-44228")
            assert result == {"cvss_score": None, "cvss_vector": None}

    def test_malformed_cvss_score_value(self, service):
        """Non-numeric or out-of-range baseScore should be safely set to None."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "totalResults": 1,
            "vulnerabilities": [
                {
                    "cve": {
                        "metrics": {
                            "cvssMetricV31": [
                                {
                                    "type": "Primary",
                                    "cvssData": {
                                        "baseScore": "not-a-number",
                                        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                    },
                                }
                            ]
                        }
                    }
                }
            ],
        }

        with patch("httpx.Client.get", return_value=mock_resp):
            result = service.fetch_cvss("CVE-2021-44228")
            assert result["cvss_score"] is None
            assert result["cvss_vector"] == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"

    def test_custom_api_key_header(self):
        """Ensure NVD_API_KEY environment / parameter adds apiKey header."""
        custom_service = NVDService(api_key="test-api-key-12345")
        headers = custom_service._get_headers()
        assert headers.get("apiKey") == "test-api-key-12345"

    def test_convenience_function(self):
        """Test get_nvd_cvss top-level helper."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = SAMPLE_NVD_V31_RESPONSE

        with patch("httpx.Client.get", return_value=mock_resp):
            result = get_nvd_cvss("CVE-2021-44228")
            assert result["cvss_score"] == 10.0
            assert result["cvss_vector"] == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
