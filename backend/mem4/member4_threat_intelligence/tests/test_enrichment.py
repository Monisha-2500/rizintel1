"""
tests/test_enrichment.py
========================
Unit tests for Member 4 Threat Intelligence Enrichment Service (services/enrichment_service.py).

All external service interactions (NVD, EPSS, KEV) are mocked and an in-memory
SQLite database is used for fast, deterministic, 100% offline testing.
"""

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock
import pytest

# Ensure member4_threat_intelligence is in PYTHONPATH
sys.path.insert(0, str(Path(__file__).parent.parent))

from cache.database import ThreatIntelCache
from models.schemas import (
    ConfidenceClassification,
    ConfidenceEnrichedFinding,
    SeverityLevel,
    ThreatEnrichedFinding,
    VulnerabilityType,
)
from services.enrichment_service import ThreatIntelligenceEnrichmentService
from services.epss_service import EPSSService
from services.kev_service import KEVService
from services.nvd_service import NVDService


# ---------------------------------------------------------------------------
# Test Helpers & Fixtures
# ---------------------------------------------------------------------------

def make_sample_m3_finding(**overrides) -> dict:
    """Create a sample valid Member 3 ConfidenceEnrichedFinding dictionary."""
    base = {
        "schema_version": "1.0",
        "finding_id": "DEDUP-000001",
        "cve_id": "CVE-2021-44228",
        "vulnerability_name": "Log4Shell Remote Code Execution",
        "vulnerability_type": "REMOTE_CODE_EXECUTION",
        "severity": "CRITICAL",
        "asset": {
            "asset_id": "ASSET-SRV-042",
            "host": "srv-042.example.org",
            "endpoint": "/login",
            "port": 8080,
            "parameter": "username",
        },
        "scanner_consensus": {
            "scanner_names": ["ZAP", "NUCLEI", "OPENVAS"],
            "detected_by_count": 3,
            "total_scanners": 4,
            "score": 0.75,
        },
        "finding_confidence": {
            "score": 0.9520,
            "classification": "CONFIRMED",
            "signals": {
                "scanner_consensus": 0.75,
                "evidence_quality": 0.95,
                "cve_mapping": 1.0,
                "repeatability": 0.90,
            },
            "review_required": False,
        },
        "noise_assessment": {
            "likely_noise": False,
            "reason": "Reproduced across multiple automated engines",
        },
        "source_findings": ["ZAP-101", "NUCLEI-202", "OPENVAS-303"],
    }
    base.update(overrides)
    return base


@pytest.fixture
def mock_nvd():
    nvd = MagicMock(spec=NVDService)
    nvd.fetch_cvss.return_value = {
        "cvss_score": 10.0,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    }
    return nvd


@pytest.fixture
def mock_epss():
    epss = MagicMock(spec=EPSSService)
    epss.fetch_epss.return_value = {
        "epss_score": 0.9753,
        "epss_percentile": 0.9998,
    }
    return epss


@pytest.fixture
def mock_kev():
    kev = MagicMock(spec=KEVService)
    kev.check_cve.return_value = {
        "kev_listed": True,
        "kev_date_added": "2021-12-10",
    }
    return kev


@pytest.fixture
def memory_cache():
    return ThreatIntelCache(db_path=":memory:", ttl_hours=24.0)


@pytest.fixture
def service(mock_nvd, mock_epss, mock_kev, memory_cache):
    return ThreatIntelligenceEnrichmentService(
        nvd_service=mock_nvd,
        epss_service=mock_epss,
        kev_service=mock_kev,
        cache=memory_cache,
    )


# ===========================================================================
# Unit Tests
# ===========================================================================

class TestEnrichmentService:
    def test_complete_enrichment(self, service, mock_nvd, mock_epss, mock_kev):
        """Test full enrichment when NVD, EPSS, and KEV are all available."""
        finding_input = make_sample_m3_finding()
        result = service.enrich_finding(finding_input)

        assert isinstance(result, ThreatEnrichedFinding)
        assert result.finding_id == "DEDUP-000001"
        assert result.cve_id == "CVE-2021-44228"
        assert result.asset_id == "ASSET-SRV-042"
        assert result.scanner_sources == ["ZAP", "NUCLEI", "OPENVAS"]
        assert result.scanner_consensus_score == 0.75
        assert result.finding_confidence_score == 0.9520
        assert result.finding_confidence_classification == ConfidenceClassification.CONFIRMED

        ti = result.threat_intelligence
        assert ti.cvss_score == 10.0
        assert ti.cvss_vector == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
        assert ti.epss_score == 0.9753
        assert ti.epss_percentile == 0.9998
        assert ti.kev_listed is True
        assert ti.kev_date_added == "2021-12-10"
        assert ti.exploit_available is None
        assert ti.exploit_sources == []
        assert ti.last_updated is not None

        # Verify all mocks were called once
        mock_nvd.fetch_cvss.assert_called_once_with("CVE-2021-44228")
        mock_epss.fetch_epss.assert_called_once_with("CVE-2021-44228")
        mock_kev.check_cve.assert_called_once_with("CVE-2021-44228")

        # Verify cached in database
        cached = service.cache.get_cached("CVE-2021-44228")
        assert cached is not None
        assert cached["cvss_score"] == 10.0

    def test_missing_cve_id_handling(self, service, mock_nvd, mock_epss, mock_kev):
        """When cve_id is None, no external services must be called, and all-null TI returned."""
        finding_input = make_sample_m3_finding(cve_id=None)
        result = service.enrich_finding(finding_input)

        assert isinstance(result, ThreatEnrichedFinding)
        assert result.cve_id is None
        assert result.finding_id == "DEDUP-000001"
        assert result.asset_id == "ASSET-SRV-042"

        ti = result.threat_intelligence
        assert ti.cvss_score is None
        assert ti.cvss_vector is None
        assert ti.epss_score is None
        assert ti.epss_percentile is None
        assert ti.kev_listed is None
        assert ti.kev_date_added is None
        assert ti.exploit_available is None
        assert ti.exploit_sources == []
        assert ti.last_updated is None

        # Ensure NO external calls occurred
        mock_nvd.fetch_cvss.assert_not_called()
        mock_epss.fetch_epss.assert_not_called()
        mock_kev.check_cve.assert_not_called()

    def test_cache_hit_prevents_api_calls(self, service, mock_nvd, mock_epss, mock_kev):
        """On 2nd lookup of same CVE, cache hit occurs and external APIs are NOT called."""
        finding_input = make_sample_m3_finding(cve_id="CVE-2021-44228")

        # 1st enrichment -> Cache MISS -> API lookup
        res1 = service.enrich_finding(finding_input)
        assert mock_nvd.fetch_cvss.call_count == 1
        assert mock_epss.fetch_epss.call_count == 1
        assert mock_kev.check_cve.call_count == 1

        original_last_updated = res1.threat_intelligence.last_updated

        # 2nd enrichment -> Cache HIT -> No API lookup
        res2 = service.enrich_finding(finding_input)
        assert mock_nvd.fetch_cvss.call_count == 1
        assert mock_epss.fetch_epss.call_count == 1
        assert mock_kev.check_cve.call_count == 1

        # Values & timestamp preserved
        assert res2.threat_intelligence.cvss_score == 10.0
        assert res2.threat_intelligence.last_updated == original_last_updated

        # Verify stats
        stats = service.get_stats()
        assert stats["total_findings"] == 2
        assert stats["unique_cves"] == 1
        assert stats["cache_misses"] == 1
        assert stats["cache_hits"] == 1

    def test_cache_stale_triggers_refresh(self, service, mock_nvd, mock_epss, mock_kev):
        """Stale cache entry must trigger external refresh and update the cache."""
        stale_ts = (datetime.now(timezone.utc) - timedelta(hours=48)).isoformat().replace("+00:00", "Z")
        service.cache.set_cached(
            "CVE-2021-44228",
            {
                "cvss_score": 7.5,
                "cvss_vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                "epss_score": 0.5000,
                "epss_percentile": 0.8000,
                "kev_listed": False,
                "kev_date_added": None,
                "exploit_available": None,
                "exploit_sources": [],
                "last_updated": stale_ts,
            },
        )

        finding_input = make_sample_m3_finding(cve_id="CVE-2021-44228")
        res = service.enrich_finding(finding_input)

        # External services were called to refresh stale data
        mock_nvd.fetch_cvss.assert_called_once()
        mock_epss.fetch_epss.assert_called_once()
        mock_kev.check_cve.assert_called_once()

        assert res.threat_intelligence.cvss_score == 10.0
        assert res.threat_intelligence.last_updated != stale_ts

        stats = service.get_stats()
        assert stats["cache_stale"] == 1

    def test_partial_enrichment_nvd_failure(self, service, mock_nvd, mock_epss, mock_kev):
        """When NVD fails, EPSS and KEV values are still preserved in output."""
        mock_nvd.fetch_cvss.return_value = {"cvss_score": None, "cvss_vector": None}

        finding_input = make_sample_m3_finding()
        result = service.enrich_finding(finding_input)

        ti = result.threat_intelligence
        assert ti.cvss_score is None
        assert ti.cvss_vector is None
        assert ti.epss_score == 0.9753
        assert ti.kev_listed is True

        stats = service.get_stats()
        assert stats["nvd_failure"] == 1
        assert stats["epss_success"] == 1
        assert stats["kev_success"] == 1
        assert stats["partially_enriched"] == 1

    def test_partial_enrichment_epss_failure(self, service, mock_nvd, mock_epss, mock_kev):
        """When EPSS fails, CVSS and KEV values are preserved."""
        mock_epss.fetch_epss.return_value = {"epss_score": None, "epss_percentile": None}

        finding_input = make_sample_m3_finding()
        result = service.enrich_finding(finding_input)

        ti = result.threat_intelligence
        assert ti.cvss_score == 10.0
        assert ti.epss_score is None
        assert ti.epss_percentile is None
        assert ti.kev_listed is True

        stats = service.get_stats()
        assert stats["nvd_success"] == 1
        assert stats["epss_failure"] == 1
        assert stats["partially_enriched"] == 1

    def test_partial_enrichment_kev_failure(self, service, mock_nvd, mock_epss, mock_kev):
        """When KEV fails, CVSS and EPSS values are preserved."""
        mock_kev.check_cve.return_value = {"kev_listed": None, "kev_date_added": None}

        finding_input = make_sample_m3_finding()
        result = service.enrich_finding(finding_input)

        ti = result.threat_intelligence
        assert ti.cvss_score == 10.0
        assert ti.epss_score == 0.9753
        assert ti.kev_listed is None

        stats = service.get_stats()
        assert stats["kev_failure"] == 1
        assert stats["partially_enriched"] == 1

    def test_all_external_sources_unavailable(self, service, mock_nvd, mock_epss, mock_kev):
        """When all external sources fail, returns all-null threat intelligence without crashing."""
        mock_nvd.fetch_cvss.return_value = {"cvss_score": None, "cvss_vector": None}
        mock_epss.fetch_epss.return_value = {"epss_score": None, "epss_percentile": None}
        mock_kev.check_cve.return_value = {"kev_listed": None, "kev_date_added": None}

        finding_input = make_sample_m3_finding()
        result = service.enrich_finding(finding_input)

        assert isinstance(result, ThreatEnrichedFinding)
        ti = result.threat_intelligence
        assert ti.cvss_score is None
        assert ti.epss_score is None
        assert ti.kev_listed is None

        stats = service.get_stats()
        assert stats["failed"] == 1

    def test_batch_enrichment(self, service):
        """Test enrichment of multiple findings in batch."""
        findings = [
            make_sample_m3_finding(finding_id="DEDUP-001", cve_id="CVE-2021-44228"),
            make_sample_m3_finding(finding_id="DEDUP-002", cve_id="CVE-2021-44228"), # Same CVE (cache hit)
            make_sample_m3_finding(finding_id="DEDUP-003", cve_id=None),             # Null CVE
        ]

        results = service.enrich_findings(findings)
        assert len(results) == 3
        assert results[0].finding_id == "DEDUP-001"
        assert results[1].finding_id == "DEDUP-002"
        assert results[2].finding_id == "DEDUP-003"
        assert results[2].threat_intelligence.cvss_score is None

        stats = service.get_stats()
        assert stats["total_findings"] == 3
        assert stats["cache_misses"] == 1
        assert stats["cache_hits"] == 1
        assert stats["missing_cve"] == 1
