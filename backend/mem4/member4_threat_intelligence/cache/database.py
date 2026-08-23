"""
cache/database.py
=================
SQLite Local Cache for Member 4 Threat Intelligence Enrichment Engine.

Provides persistent caching of threat intelligence metrics (CVSS, EPSS, KEV,
Exploits) keyed by canonical `cve_id` with configurable TTL freshness checks.

Database Schema:
----------------
CREATE TABLE IF NOT EXISTS threat_intelligence_cache (
    cve_id TEXT PRIMARY KEY,
    cvss_score REAL,
    cvss_vector TEXT,
    epss_score REAL,
    epss_percentile REAL,
    kev_listed INTEGER,        -- 1 (True), 0 (False), NULL (Unknown/Unavailable)
    kev_date_added TEXT,
    exploit_available INTEGER, -- 1 (True), 0 (False), NULL (Unknown/Unavailable)
    exploit_sources TEXT,      -- JSON serialized array of strings, e.g. '["exploit-db"]'
    last_updated TEXT NOT NULL -- ISO 8601 UTC timestamp (e.g. '2026-08-20T12:00:00Z')
);
"""

from __future__ import annotations

import json
import logging
import os
import re
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger(__name__)

# Default Database and TTL settings
DEFAULT_CACHE_DIR = Path(__file__).parent
DEFAULT_DB_PATH = str(DEFAULT_CACHE_DIR / "threat_cache.db")
DEFAULT_TTL_HOURS = 24.0

CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$")


class ThreatIntelCache:
    """SQLite-backed local cache for CVE threat intelligence."""

    def __init__(
        self,
        db_path: Optional[str] = None,
        ttl_hours: Optional[float] = None,
    ):
        if db_path:
            self.db_path = db_path
        else:
            self.db_path = os.getenv("CACHE_DB_PATH", DEFAULT_DB_PATH)

        ttl_env = os.getenv("CACHE_TTL_HOURS")
        if ttl_hours is not None:
            self.ttl_hours = float(ttl_hours)
        elif ttl_env:
            try:
                self.ttl_hours = float(ttl_env)
            except ValueError:
                self.ttl_hours = DEFAULT_TTL_HOURS
        else:
            self.ttl_hours = DEFAULT_TTL_HOURS

        self._memory_conn: Optional[sqlite3.Connection] = None
        if self.db_path == ":memory:":
            self._memory_conn = sqlite3.connect(":memory:", check_same_thread=False)
            self._memory_conn.row_factory = sqlite3.Row

        self.init_db()

    def _get_connection(self) -> sqlite3.Connection:
        """Create and return a configured SQLite connection with row factory."""
        if self._memory_conn is not None:
            return self._memory_conn

        db_dir = Path(self.db_path).parent
        db_dir.mkdir(parents=True, exist_ok=True)

        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def init_db(self) -> None:
        """Initialize the SQLite database and create tables/indexes if not present."""
        create_table_sql = """
        CREATE TABLE IF NOT EXISTS threat_intelligence_cache (
            cve_id TEXT PRIMARY KEY,
            cvss_score REAL,
            cvss_vector TEXT,
            epss_score REAL,
            epss_percentile REAL,
            kev_listed INTEGER,
            kev_date_added TEXT,
            exploit_available INTEGER,
            exploit_sources TEXT,
            last_updated TEXT NOT NULL
        );
        """
        try:
            with self._get_connection() as conn:
                conn.execute(create_table_sql)
                conn.commit()
        except sqlite3.Error as ex:
            logger.error("Failed to initialize SQLite cache database at '%s': %s", self.db_path, ex)
            raise

    def validate_cve_id(self, cve_id: Optional[str]) -> bool:
        """Check if CVE ID is well-formed according to standard CVE naming rules."""
        if not cve_id or not isinstance(cve_id, str):
            return False
        return bool(CVE_PATTERN.match(cve_id.strip()))

    def is_fresh(
        self,
        last_updated: Optional[str],
        ttl_hours: Optional[float] = None,
        reference_time: Optional[datetime] = None,
    ) -> bool:
        """
        Check if a given ISO 8601 UTC timestamp is within the configured TTL.

        Returns:
            True if fresh, False if stale or unparseable.
        """
        if not last_updated or not isinstance(last_updated, str):
            return False

        active_ttl = ttl_hours if ttl_hours is not None else self.ttl_hours
        now = reference_time or datetime.now(timezone.utc)

        try:
            # Parse ISO 8601 format (supports Z or offset)
            clean_ts = last_updated.strip().replace("Z", "+00:00")
            parsed_dt = datetime.fromisoformat(clean_ts)

            if parsed_dt.tzinfo is None:
                parsed_dt = parsed_dt.replace(tzinfo=timezone.utc)

            age = now - parsed_dt
            max_age = timedelta(hours=active_ttl)

            return timedelta(0) <= age <= max_age
        except (ValueError, TypeError) as ex:
            logger.warning("Failed to parse last_updated timestamp '%s': %s", last_updated, ex)
            return False

    def get_cached(self, cve_id: Optional[str]) -> Optional[Dict[str, Any]]:
        """
        Retrieve cached threat intelligence for a CVE ID.

        Returns:
            Dictionary matching the ThreatIntelligence structure, or None on cache miss.
        """
        if not self.validate_cve_id(cve_id):
            return None

        assert cve_id is not None
        cve_clean = cve_id.strip()

        query_sql = "SELECT * FROM threat_intelligence_cache WHERE cve_id = ?;"

        try:
            with self._get_connection() as conn:
                cursor = conn.execute(query_sql, (cve_clean,))
                row = cursor.fetchone()

                if not row:
                    return None

                # Deserialize exploit_sources JSON list
                raw_sources = row["exploit_sources"]
                sources: List[str] = []
                if raw_sources:
                    try:
                        parsed_sources = json.loads(raw_sources)
                        if isinstance(parsed_sources, list):
                            sources = [str(s) for s in parsed_sources]
                    except (json.JSONDecodeError, TypeError):
                        sources = []

                # Convert integer flags to Optional[bool] (1 -> True, 0 -> False, NULL -> None)
                kev_flag = None
                if row["kev_listed"] is not None:
                    kev_flag = bool(row["kev_listed"])

                exploit_flag = None
                if row["exploit_available"] is not None:
                    exploit_flag = bool(row["exploit_available"])

                return {
                    "cvss_score": row["cvss_score"],
                    "cvss_vector": row["cvss_vector"],
                    "epss_score": row["epss_score"],
                    "epss_percentile": row["epss_percentile"],
                    "kev_listed": kev_flag,
                    "kev_date_added": row["kev_date_added"],
                    "exploit_available": exploit_flag,
                    "exploit_sources": sources,
                    "last_updated": row["last_updated"],
                }

        except sqlite3.Error as ex:
            logger.error("SQLite error while fetching cached CVE '%s': %s", cve_clean, ex)
            return None

    def lookup(self, cve_id: Optional[str]) -> Tuple[Optional[Dict[str, Any]], str]:
        """
        Lookup a CVE in the cache and determine its status.

        Returns:
            Tuple of (cached_data_or_None, status)
            status is one of: "HIT", "STALE", "MISS"
        """
        if not self.validate_cve_id(cve_id):
            return None, "MISS"

        data = self.get_cached(cve_id)
        if data is None:
            return None, "MISS"

        if self.is_fresh(data.get("last_updated")):
            return data, "HIT"

        return data, "STALE"

    def set_cached(
        self,
        cve_id: Optional[str],
        threat_intelligence: Dict[str, Any],
    ) -> bool:
        """
        Store or update threat intelligence for a CVE ID (UPSERT).

        Args:
            cve_id: Canonical CVE ID (e.g. 'CVE-2021-44228')
            threat_intelligence: Dictionary containing threat intelligence fields.

        Returns:
            True on successful write, False otherwise.
        """
        if not self.validate_cve_id(cve_id):
            logger.warning("Cache write skipped: invalid CVE ID '%s'", cve_id)
            return False

        if not isinstance(threat_intelligence, dict):
            logger.warning("Cache write skipped: threat_intelligence must be a dict")
            return False

        assert cve_id is not None
        cve_clean = cve_id.strip()

        # Extract & validate fields
        cvss_score = threat_intelligence.get("cvss_score")
        if cvss_score is not None:
            try:
                cvss_score = round(float(cvss_score), 1)
                if not (0.0 <= cvss_score <= 10.0):
                    cvss_score = None
            except (ValueError, TypeError):
                cvss_score = None

        cvss_vector = threat_intelligence.get("cvss_vector")
        if cvss_vector is not None and not isinstance(cvss_vector, str):
            cvss_vector = str(cvss_vector)

        epss_score = threat_intelligence.get("epss_score")
        if epss_score is not None:
            try:
                epss_score = round(float(epss_score), 4)
                if not (0.0 <= epss_score <= 1.0):
                    epss_score = None
            except (ValueError, TypeError):
                epss_score = None

        epss_percentile = threat_intelligence.get("epss_percentile")
        if epss_percentile is not None:
            try:
                epss_percentile = round(float(epss_percentile), 4)
                if not (0.0 <= epss_percentile <= 1.0):
                    epss_percentile = None
            except (ValueError, TypeError):
                epss_percentile = None

        # Boolean to integer mapping (preserve 3-state: 1, 0, or NULL)
        kev_listed = threat_intelligence.get("kev_listed")
        kev_int: Optional[int] = None
        if kev_listed is not None:
            kev_int = 1 if bool(kev_listed) else 0

        kev_date_added = threat_intelligence.get("kev_date_added")

        exploit_available = threat_intelligence.get("exploit_available")
        exploit_int: Optional[int] = None
        if exploit_available is not None:
            exploit_int = 1 if bool(exploit_available) else 0

        # Exploit sources list -> JSON text
        exploit_sources_raw = threat_intelligence.get("exploit_sources", [])
        if not isinstance(exploit_sources_raw, list):
            exploit_sources_raw = []
        exploit_sources_json = json.dumps(exploit_sources_raw)

        # Last updated timestamp (defaults to current UTC time if not provided)
        last_updated = threat_intelligence.get("last_updated")
        if not last_updated or not isinstance(last_updated, str):
            last_updated = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

        upsert_sql = """
        INSERT INTO threat_intelligence_cache (
            cve_id,
            cvss_score,
            cvss_vector,
            epss_score,
            epss_percentile,
            kev_listed,
            kev_date_added,
            exploit_available,
            exploit_sources,
            last_updated
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(cve_id) DO UPDATE SET
            cvss_score = excluded.cvss_score,
            cvss_vector = excluded.cvss_vector,
            epss_score = excluded.epss_score,
            epss_percentile = excluded.epss_percentile,
            kev_listed = excluded.kev_listed,
            kev_date_added = excluded.kev_date_added,
            exploit_available = excluded.exploit_available,
            exploit_sources = excluded.exploit_sources,
            last_updated = excluded.last_updated;
        """

        try:
            with self._get_connection() as conn:
                conn.execute(
                    upsert_sql,
                    (
                        cve_clean,
                        cvss_score,
                        cvss_vector,
                        epss_score,
                        epss_percentile,
                        kev_int,
                        kev_date_added,
                        exploit_int,
                        exploit_sources_json,
                        last_updated,
                    ),
                )
                conn.commit()
                return True
        except sqlite3.Error as ex:
            logger.error("SQLite error while inserting cached CVE '%s': %s", cve_clean, ex)
            return False

    def delete(self, cve_id: str) -> bool:
        """Remove a cached CVE entry."""
        if not cve_id:
            return False
        try:
            with self._get_connection() as conn:
                conn.execute("DELETE FROM threat_intelligence_cache WHERE cve_id = ?;", (cve_id.strip(),))
                conn.commit()
                return True
        except sqlite3.Error as ex:
            logger.error("SQLite error during deletion of CVE '%s': %s", cve_id, ex)
            return False

    def count(self) -> int:
        """Count total cached CVE records."""
        try:
            with self._get_connection() as conn:
                cursor = conn.execute("SELECT COUNT(*) FROM threat_intelligence_cache;")
                return cursor.fetchone()[0]
        except sqlite3.Error:
            return 0


# Convenience singleton
_default_cache = ThreatIntelCache()


def get_cached_threat_intel(cve_id: Optional[str]) -> Optional[Dict[str, Any]]:
    return _default_cache.get_cached(cve_id)


def set_cached_threat_intel(cve_id: Optional[str], data: Dict[str, Any]) -> bool:
    return _default_cache.set_cached(cve_id, data)


if __name__ == "__main__":
    print("--- SQLite Threat Intel Cache Demonstration ---")
    demo_cache = ThreatIntelCache(db_path=":memory:", ttl_hours=24.0)

    test_cve = "CVE-2021-44228"
    print(f"1. Initial lookup for {test_cve} (Expecting Cache MISS):")
    record, status = demo_cache.lookup(test_cve)
    print(f"   Status: {status}, Record: {record}")

    print(f"\n2. Storing threat intelligence for {test_cve}...")
    sample_data = {
        "cvss_score": 10.0,
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "epss_score": 0.9753,
        "epss_percentile": 0.9998,
        "kev_listed": True,
        "kev_date_added": "2021-12-10",
        "exploit_available": None,
        "exploit_sources": [],
        "last_updated": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    }
    demo_cache.set_cached(test_cve, sample_data)
    print("   Stored successfully.")

    print(f"\n3. Second lookup for {test_cve} (Expecting Cache HIT):")
    record, status = demo_cache.lookup(test_cve)
    print(f"   Status: {status}")
    print(f"   CVSS: {record['cvss_score']}, EPSS: {record['epss_score']}, KEV: {record['kev_listed']}")

    print(f"\n4. Storing stale record for CVE-2018-7600 (last_updated 48 hours ago)...")
    stale_cve = "CVE-2018-7600"
    stale_time = (datetime.now(timezone.utc) - timedelta(hours=48)).isoformat().replace("+00:00", "Z")
    demo_cache.set_cached(
        stale_cve,
        {
            "cvss_score": 9.8,
            "cvss_vector": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "epss_score": 0.9654,
            "epss_percentile": 0.9950,
            "kev_listed": True,
            "kev_date_added": "2022-03-25",
            "exploit_available": None,
            "exploit_sources": [],
            "last_updated": stale_time,
        },
    )

    record, status = demo_cache.lookup(stale_cve)
    print(f"   Lookup Status: {status} (Record exists but is older than 24h TTL)")
    print(f"   Total records in cache: {demo_cache.count()}")
