"""
services/enrichment_service.py
==============================
Threat Intelligence Enrichment Service (Member 4 Core Orchestrator).

Accepts a ConfidenceEnrichedFinding (from Member 3) and produces a
ThreatEnrichedFinding (for Member 5), adhering strictly to the
RizIntel Interface Contract v1.0.

Pipeline Flow:
--------------
1. Validates input finding against ConfidenceEnrichedFinding schema.
2. Extracts canonical `cve_id`.
3. If `cve_id` is None:
   - Returns all-null ThreatIntelligence object immediately (0 API calls).
4. If `cve_id` is present:
   - Checks local SQLite cache (cache/database.py).
   - If Cache HIT (fresh): returns cached ThreatIntelligence immediately.
   - If Cache MISS or STALE:
     - Queries NVDService, EPSSService, and KEVService.
     - Combines metrics into normalized ThreatIntelligence structure.
     - Stores/updates record in SQLite cache with UTC timestamp.
5. Preserves upstream identifiers (finding_id, cve_id, asset_id).
6. Maps scanner_consensus → scanner_sources and confidence → confidence fields.

Usage (from Member 3 → Member 4):
-----------------------------------
    from services.enrichment_service import ThreatIntelligenceEnrichmentService

    service = ThreatIntelligenceEnrichmentService()
    result = service.enrich_finding(finding)   # Returns ThreatEnrichedFinding
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Union

from cache.database import ThreatIntelCache, _default_cache
from models.schemas import (
    ConfidenceEnrichedFinding,
    ThreatEnrichedFinding,
    ThreatIntelligence,
)
from services.epss_service import EPSSService, _default_epss_service
from services.kev_service import KEVService, _default_kev_service
from services.nvd_service import NVDService, _default_nvd_service

logger = logging.getLogger(__name__)


class ThreatIntelligenceEnrichmentService:
    """
    Orchestrates single-finding threat intelligence enrichment for Member 4.

    Accepts a ConfidenceEnrichedFinding (Member 3 output), consults the SQLite
    cache, queries NVD / EPSS / CISA KEV on a cache MISS or STALE, updates
    the cache, and returns a ThreatEnrichedFinding (Member 5 input).

    All three intelligence services are injected via constructor to allow
    easy mocking in tests.
    """

    def __init__(
        self,
        nvd_service: Optional[NVDService] = None,
        epss_service: Optional[EPSSService] = None,
        kev_service: Optional[KEVService] = None,
        cache: Optional[ThreatIntelCache] = None,
    ):
        self.nvd_service = nvd_service or _default_nvd_service
        self.epss_service = epss_service or _default_epss_service
        self.kev_service = kev_service or _default_kev_service
        self.cache = cache or _default_cache

        # Per-CVE deduplication tracking
        self._seen_cves: Set[str] = set()

        # Enrichment counters — preserved for test compatibility and diagnostics.
        # cache_hits / cache_misses / cache_stale reflect cache behaviour.
        # nvd/epss/kev success/failure track individual source reliability.
        # fully_enriched / partially_enriched / failed describe outcome quality.
        self._stats: Dict[str, int] = {
            "total_findings": 0,
            "unique_cves": 0,
            "cache_hits": 0,
            "cache_misses": 0,
            "cache_stale": 0,
            "nvd_success": 0,
            "nvd_failure": 0,
            "epss_success": 0,
            "epss_failure": 0,
            "kev_success": 0,
            "kev_failure": 0,
            "missing_cve": 0,
            "fully_enriched": 0,
            "partially_enriched": 0,
            "failed": 0,
        }

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get_stats(self) -> Dict[str, int]:
        """Return a copy of the current enrichment counters."""
        return dict(self._stats)

    def reset_stats(self) -> None:
        """Reset all enrichment counters and the CVE deduplication set."""
        self._seen_cves.clear()
        for k in self._stats:
            self._stats[k] = 0

    def enrich_finding(
        self,
        finding_input: Union[ConfidenceEnrichedFinding, Dict[str, Any]],
    ) -> ThreatEnrichedFinding:
        """
        Enrich a single Member 3 finding with threat intelligence.

        Args:
            finding_input: ConfidenceEnrichedFinding instance or a dict
                           conforming to the M3→M4 contract.

        Returns:
            ThreatEnrichedFinding conforming to the RizIntel Interface Contract v1.0.
        """
        # Validate / normalise input
        if isinstance(finding_input, dict):
            finding = ConfidenceEnrichedFinding.model_validate(finding_input)
        elif isinstance(finding_input, ConfidenceEnrichedFinding):
            finding = finding_input
        else:
            raise ValueError(f"Invalid finding input type: {type(finding_input)}")

        self._stats["total_findings"] += 1

        cve_id = finding.cve_id

        # --- No CVE ID: return all-null threat intelligence immediately ---
        if not cve_id or not cve_id.strip():
            self._stats["missing_cve"] += 1
            threat_intel = self._build_empty_threat_intel()

        else:
            cve_clean = cve_id.strip()

            # Track unique CVEs across enrichment calls
            if cve_clean not in self._seen_cves:
                self._seen_cves.add(cve_clean)
                self._stats["unique_cves"] += 1

            # --- SQLite cache lookup ---
            cached_data, status = self.cache.lookup(cve_clean)

            if status == "HIT" and cached_data is not None:
                # Cache HIT → return immediately, no external API calls
                self._stats["cache_hits"] += 1
                threat_intel = ThreatIntelligence.model_validate(cached_data)
                self._assess_enrichment_completeness(cached_data)

            else:
                # Cache MISS or STALE → fetch from NVD + EPSS + CISA KEV
                if status == "STALE":
                    self._stats["cache_stale"] += 1
                else:
                    self._stats["cache_misses"] += 1

                fresh_intel = self._fetch_external_intel(cve_clean)

                # Persist to SQLite cache (UPSERT)
                self.cache.set_cached(cve_clean, fresh_intel)

                threat_intel = ThreatIntelligence.model_validate(fresh_intel)
                self._assess_enrichment_completeness(fresh_intel)

        # --- Assemble and return ThreatEnrichedFinding ---
        output_payload = {
            "schema_version": finding.schema_version,
            "finding_id": finding.finding_id,
            "cve_id": finding.cve_id,
            "asset_id": finding.asset.asset_id,
            "vulnerability_name": finding.vulnerability_name,
            "vulnerability_type": finding.vulnerability_type,
            "scanner_sources": list(finding.scanner_consensus.scanner_names),
            "scanner_consensus_score": finding.scanner_consensus.score,
            "finding_confidence_score": finding.finding_confidence.score,
            "finding_confidence_classification": finding.finding_confidence.classification,
            "threat_intelligence": threat_intel,
        }
        return ThreatEnrichedFinding.model_validate(output_payload)

    def enrich_findings(
        self,
        findings_list: List[Union[ConfidenceEnrichedFinding, Dict[str, Any]]],
    ) -> List[ThreatEnrichedFinding]:
        """
        Enrich a list of Member 3 findings.

        Delegates to enrich_finding() for each item, sharing the same
        cache and counters across the whole list.
        """
        return [self.enrich_finding(item) for item in findings_list]

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _build_empty_threat_intel(self) -> ThreatIntelligence:
        """Return an all-null ThreatIntelligence for findings without a CVE ID."""
        return ThreatIntelligence(
            cvss_score=None,
            cvss_vector=None,
            epss_score=None,
            epss_percentile=None,
            kev_listed=None,
            kev_date_added=None,
            exploit_available=None,
            exploit_sources=[],
            last_updated=None,
        )

    def _fetch_external_intel(self, cve_id: str) -> Dict[str, Any]:
        """
        Query NVD, EPSS, and CISA KEV for a CVE ID and return a combined dict.

        Exploit availability is intentionally omitted — that responsibility
        falls outside Member 4's current scope.
        """
        # 1. NVD → cvss_score, cvss_vector
        nvd_res = self.nvd_service.fetch_cvss(cve_id)
        cvss_score = nvd_res.get("cvss_score")
        cvss_vector = nvd_res.get("cvss_vector")
        if cvss_score is not None or cvss_vector is not None:
            self._stats["nvd_success"] += 1
        else:
            self._stats["nvd_failure"] += 1

        # 2. EPSS → epss_score, epss_percentile
        epss_res = self.epss_service.fetch_epss(cve_id)
        epss_score = epss_res.get("epss_score")
        epss_percentile = epss_res.get("epss_percentile")
        if epss_score is not None or epss_percentile is not None:
            self._stats["epss_success"] += 1
        else:
            self._stats["epss_failure"] += 1

        # 3. CISA KEV → kev_listed, kev_date_added
        kev_res = self.kev_service.check_cve(cve_id)
        kev_listed = kev_res.get("kev_listed")
        kev_date_added = kev_res.get("kev_date_added")
        if kev_listed is not None:
            self._stats["kev_success"] += 1
        else:
            self._stats["kev_failure"] += 1

        now_utc = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

        return {
            "cvss_score": cvss_score,
            "cvss_vector": cvss_vector,
            "epss_score": epss_score,
            "epss_percentile": epss_percentile,
            "kev_listed": kev_listed,
            "kev_date_added": kev_date_added,
            "exploit_available": None,   # Not implemented in Member 4 scope
            "exploit_sources": [],       # Not implemented in Member 4 scope
            "last_updated": now_utc,
        }

    def _assess_enrichment_completeness(self, ti_dict: Dict[str, Any]) -> None:
        """
        Categorise enrichment outcome as fully_enriched, partially_enriched, or failed.

        fully_enriched   = all three sources (CVSS, EPSS, KEV) returned data
        partially_enriched = at least one source returned data
        failed           = no source returned any data
        """
        has_cvss = ti_dict.get("cvss_score") is not None
        has_epss = ti_dict.get("epss_score") is not None
        has_kev = ti_dict.get("kev_listed") is not None

        successes = sum([has_cvss, has_epss, has_kev])
        if successes == 3:
            self._stats["fully_enriched"] += 1
        elif successes >= 1:
            self._stats["partially_enriched"] += 1
        else:
            self._stats["failed"] += 1


# ---------------------------------------------------------------------------
# Module-level convenience helpers
# ---------------------------------------------------------------------------

# Default singleton — suitable for direct import in small scripts / prototypes.
_default_enrichment_service = ThreatIntelligenceEnrichmentService()


def enrich_finding(
    finding: Union[ConfidenceEnrichedFinding, Dict[str, Any]],
) -> ThreatEnrichedFinding:
    """Enrich a single finding using the default singleton service."""
    return _default_enrichment_service.enrich_finding(finding)
