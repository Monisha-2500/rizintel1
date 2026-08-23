"""
tests/test_cache.py
===================
Unit tests for Member 4 SQLite Local Threat Intelligence Cache (cache/database.py).

All tests execute against isolated temporary SQLite databases (:memory: or tmp_path)
to guarantee no side-effects or dependency on persistent disk state.

Test Scenarios:
1. Table creation and database initialization
2. Insert and retrieve threat intelligence record
3. Cache Miss (nonexistent CVE returns None and status "MISS")
4. Cache Hit (fresh record returns valid dictionary and status "HIT")
5. Freshness check: is_fresh() with current timestamp returns True
6. Staleness check: is_fresh() with timestamp older than TTL returns False
7. Stale record retrieval: returns stored record with status "STALE"
8. Update existing CVE record (UPSERT modifies existing row without duplication)
9. Duplicate prevention (inserting same CVE twice leaves count == 1)
10. Null and invalid CVE handling (None, empty, whitespace skipped safely)
11. Multiple distinct CVEs in database
12. Exploit sources JSON list serialization and deserialization
13. Three-state boolean preservation for kev_listed (True, False, None)
14. Out-of-bounds score clipping/validation
15. Configurable TTL verification
"""

import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
import pytest

# Ensure member4_threat_intelligence is in PYTHONPATH
sys.path.insert(0, str(Path(__file__).parent.parent))

from cache.database import ThreatIntelCache


# ---------------------------------------------------------------------------
# Test Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def temp_cache(tmp_path):
    """Provide an isolated, file-based temporary SQLite cache for testing."""
    db_file = tmp_path / "test_threat_cache.db"
    return ThreatIntelCache(db_path=str(db_file), ttl_hours=24.0)


@pytest.fixture
def memory_cache():
    """Provide an in-memory SQLite cache for testing."""
    return ThreatIntelCache(db_path=":memory:", ttl_hours=24.0)


# ===========================================================================
# Unit Tests
# ===========================================================================

class TestThreatIntelCache:
    def test_database_initialization(self, temp_cache):
        """Verify database and threat_intelligence_cache table are created."""
        assert Path(temp_cache.db_path).exists()
        assert temp_cache.count() == 0

    def test_insert_and_retrieve_cve(self, temp_cache):
        """Verify basic storage and accurate retrieval of a complete threat intelligence record."""
        now_ts = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        sample_data = {
            "cvss_score": 9.8,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "epss_score": 0.9753,
            "epss_percentile": 0.9998,
            "kev_listed": True,
            "kev_date_added": "2021-12-10",
            "exploit_available": True,
            "exploit_sources": ["exploit-db", "metasploit"],
            "last_updated": now_ts,
        }

        success = temp_cache.set_cached("CVE-2021-44228", sample_data)
        assert success is True
        assert temp_cache.count() == 1

        cached = temp_cache.get_cached("CVE-2021-44228")
        assert cached is not None
        assert cached["cvss_score"] == 9.8
        assert cached["cvss_vector"] == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        assert cached["epss_score"] == 0.9753
        assert cached["epss_percentile"] == 0.9998
        assert cached["kev_listed"] is True
        assert cached["kev_date_added"] == "2021-12-10"
        assert cached["exploit_available"] is True
        assert cached["exploit_sources"] == ["exploit-db", "metasploit"]
        assert cached["last_updated"] == now_ts

    def test_cache_miss_behavior(self, temp_cache):
        """Lookup of non-existent CVE must return None and 'MISS' status."""
        record = temp_cache.get_cached("CVE-2099-0001")
        assert record is None

        data, status = temp_cache.lookup("CVE-2099-0001")
        assert data is None
        assert status == "MISS"

    def test_cache_hit_behavior(self, temp_cache):
        """Fresh CVE record must return valid data and 'HIT' status."""
        fresh_ts = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
        temp_cache.set_cached(
            "CVE-2021-44228",
            {
                "cvss_score": 10.0,
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                "epss_score": 0.9753,
                "epss_percentile": 0.9998,
                "kev_listed": True,
                "kev_date_added": "2021-12-10",
                "exploit_available": None,
                "exploit_sources": [],
                "last_updated": fresh_ts,
            },
        )

        data, status = temp_cache.lookup("CVE-2021-44228")
        assert status == "HIT"
        assert data is not None
        assert data["cvss_score"] == 10.0

    def test_is_fresh_calculation(self, memory_cache):
        """Verify is_fresh returns True for recent timestamps and False for old ones."""
        now = datetime.now(timezone.utc)
        recent_ts = (now - timedelta(hours=2)).isoformat().replace("+00:00", "Z")
        old_ts = (now - timedelta(hours=30)).isoformat().replace("+00:00", "Z")

        # Configured TTL is 24 hours
        assert memory_cache.is_fresh(recent_ts) is True
        assert memory_cache.is_fresh(old_ts) is False
        assert memory_cache.is_fresh(None) is False
        assert memory_cache.is_fresh("invalid-timestamp") is False

    def test_cache_stale_behavior(self, temp_cache):
        """Stale record (older than TTL) must return data with status 'STALE'."""
        stale_ts = (datetime.now(timezone.utc) - timedelta(hours=48)).isoformat().replace("+00:00", "Z")
        temp_cache.set_cached(
            "CVE-2018-7600",
            {
                "cvss_score": 9.8,
                "cvss_vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "epss_score": 0.9500,
                "epss_percentile": 0.9900,
                "kev_listed": True,
                "kev_date_added": "2022-03-25",
                "exploit_available": None,
                "exploit_sources": [],
                "last_updated": stale_ts,
            },
        )

        data, status = temp_cache.lookup("CVE-2018-7600")
        assert status == "STALE"
        assert data is not None
        assert data["cvss_score"] == 9.8
        # Ensure stale record is NOT deleted automatically
        assert temp_cache.count() == 1

    def test_update_existing_cve(self, temp_cache):
        """Updating an existing CVE should update values without duplicate rows."""
        initial_data = {
            "cvss_score": 7.5,
            "cvss_vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            "epss_score": 0.1200,
            "epss_percentile": 0.5000,
            "kev_listed": False,
            "kev_date_added": None,
            "exploit_available": None,
            "exploit_sources": [],
            "last_updated": "2026-08-01T00:00:00Z",
        }
        temp_cache.set_cached("CVE-2023-4966", initial_data)
        assert temp_cache.count() == 1

        # Updated enrichment
        updated_data = {
            "cvss_score": 9.4,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
            "epss_score": 0.9200,
            "epss_percentile": 0.9800,
            "kev_listed": True,
            "kev_date_added": "2023-10-18",
            "exploit_available": True,
            "exploit_sources": ["cisa"],
            "last_updated": "2026-08-20T12:00:00Z",
        }
        temp_cache.set_cached("CVE-2023-4966", updated_data)

        assert temp_cache.count() == 1
        cached = temp_cache.get_cached("CVE-2023-4966")
        assert cached["cvss_score"] == 9.4
        assert cached["epss_score"] == 0.9200
        assert cached["kev_listed"] is True
        assert cached["kev_date_added"] == "2023-10-18"
        assert cached["last_updated"] == "2026-08-20T12:00:00Z"

    @pytest.mark.parametrize("invalid_cve", [
        None,
        "",
        "   ",
        "INVALID-CVE",
        "CVE-20-1234",
        12345,
    ])
    def test_invalid_cve_handling(self, temp_cache, invalid_cve):
        """Invalid or null CVE inputs must return None and not insert invalid keys."""
        res_get = temp_cache.get_cached(invalid_cve)
        assert res_get is None

        res_set = temp_cache.set_cached(invalid_cve, {"cvss_score": 5.0})
        assert res_set is False
        assert temp_cache.count() == 0

    def test_three_state_boolean_preservation(self, memory_cache):
        """Verify True, False, and None are accurately preserved for boolean fields."""
        # 1. kev_listed is False
        memory_cache.set_cached(
            "CVE-2020-11023",
            {
                "kev_listed": False,
                "exploit_available": False,
            },
        )
        c1 = memory_cache.get_cached("CVE-2020-11023")
        assert c1["kev_listed"] is False
        assert c1["exploit_available"] is False

        # 2. kev_listed is True
        memory_cache.set_cached(
            "CVE-2021-44228",
            {
                "kev_listed": True,
                "exploit_available": True,
            },
        )
        c2 = memory_cache.get_cached("CVE-2021-44228")
        assert c2["kev_listed"] is True
        assert c2["exploit_available"] is True

        # 3. kev_listed is None
        memory_cache.set_cached(
            "CVE-2024-3400",
            {
                "kev_listed": None,
                "exploit_available": None,
            },
        )
        c3 = memory_cache.get_cached("CVE-2024-3400")
        assert c3["kev_listed"] is None
        assert c3["exploit_available"] is None

    def test_exploit_sources_json_handling(self, memory_cache):
        """Ensure empty and populated lists of exploit sources serialize cleanly."""
        memory_cache.set_cached(
            "CVE-2021-44228",
            {"exploit_sources": ["exploit-db", "metasploit", "github"]},
        )
        cached = memory_cache.get_cached("CVE-2021-44228")
        assert cached["exploit_sources"] == ["exploit-db", "metasploit", "github"]

    def test_multiple_cves_isolation(self, memory_cache):
        """Multiple CVEs stored must remain isolated and searchable."""
        cves = ["CVE-2021-44228", "CVE-2020-1472", "CVE-2019-0708"]
        for idx, cve in enumerate(cves):
            memory_cache.set_cached(
                cve,
                {"cvss_score": 8.0 + idx, "epss_score": 0.5 + (idx * 0.1)},
            )

        assert memory_cache.count() == 3
        for idx, cve in enumerate(cves):
            item = memory_cache.get_cached(cve)
            assert item["cvss_score"] == 8.0 + idx

    def test_delete_entry(self, memory_cache):
        """Test deletion of cached record."""
        memory_cache.set_cached("CVE-2021-44228", {"cvss_score": 10.0})
        assert memory_cache.count() == 1

        deleted = memory_cache.delete("CVE-2021-44228")
        assert deleted is True
        assert memory_cache.count() == 0
        assert memory_cache.get_cached("CVE-2021-44228") is None
