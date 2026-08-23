"""
demo.py
=======
Demonstration and integration script for Member 4 Threat Intelligence.

Flow:
    Member 3 (ConfidenceEnrichedFinding)
             |
    Member 4 (ThreatIntelligenceEnrichmentService)
             |
    SQLite Cache (cache/database.py)
             |-- HIT  -> Returns cached threat intelligence immediately
             `-- MISS -> Queries NVD + EPSS + CISA KEV -> Stores in SQLite cache
             |
    Member 5 (ThreatEnrichedFinding)
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

# Ensure project root is on the import path
sys.path.insert(0, str(Path(__file__).parent))

from models.schemas import (
    Asset,
    ConfidenceClassification,
    ConfidenceEnrichedFinding,
    ConfidenceSignals,
    FindingConfidence,
    NoiseAssessment,
    ScannerConsensus,
    SchemaVersion,
    SeverityLevel,
    VulnerabilityType,
)
from services.enrichment_service import ThreatIntelligenceEnrichmentService


def create_sample_member3_finding() -> ConfidenceEnrichedFinding:
    """Build a realistic sample ConfidenceEnrichedFinding (Member 3 output)."""
    return ConfidenceEnrichedFinding(
        schema_version=SchemaVersion.V1_0,
        finding_id="DEDUP-000001",
        cve_id="CVE-2021-44228",
        vulnerability_name="Log4Shell Remote Code Execution",
        vulnerability_type=VulnerabilityType.REMOTE_CODE_EXECUTION,
        severity=SeverityLevel.CRITICAL,
        asset=Asset(
            asset_id="ASSET-SRV-042",
            host="srv-042.example.org",
            endpoint="/login",
            port=8080,
            parameter="username",
        ),
        scanner_consensus=ScannerConsensus(
            scanner_names=["ZAP", "NUCLEI", "OPENVAS"],
            detected_by_count=3,
            total_scanners=4,
            score=0.75,
        ),
        finding_confidence=FindingConfidence(
            score=0.9520,
            classification=ConfidenceClassification.CONFIRMED,
            signals=ConfidenceSignals(
                scanner_consensus=0.75,
                evidence_quality=0.95,
                cve_mapping=1.0,
                repeatability=0.90,
            ),
            review_required=False,
        ),
        noise_assessment=NoiseAssessment(
            likely_noise=False,
            reason="Reproduced across multiple automated engines",
        ),
        source_findings=["ZAP-101", "NUCLEI-202", "OPENVAS-303"],
    )


def main() -> None:
    print("=" * 70)
    print("  RIZINTEL - MEMBER 4 THREAT INTELLIGENCE DEMONSTRATION")
    print("=" * 70)
    print("\nArchitecture Pipeline:")
    print("  Member 3  --[ConfidenceEnrichedFinding]--> Member 4")
    print("  Member 4  --[ThreatEnrichedFinding]------> Member 5")
    print("=" * 70)

    # Instantiate the Member 4 Enrichment Service
    service = ThreatIntelligenceEnrichmentService()

    sample_finding = create_sample_member3_finding()
    target_cve = sample_finding.cve_id
    assert target_cve is not None

    print(f"\n[1] Incoming Finding from Member 3:")
    print(f"    Finding ID   : {sample_finding.finding_id}")
    print(f"    CVE ID       : {target_cve}")
    print(f"    Vulnerability: {sample_finding.vulnerability_name}")
    print(f"    Asset ID     : {sample_finding.asset.asset_id} ({sample_finding.asset.host})")
    print(f"    Confidence   : {sample_finding.finding_confidence.score} ({sample_finding.finding_confidence.classification.value})")

    # Ensure demo CVE is not present in cache before demonstration starts
    service.cache.delete(target_cve)
    pre_data, pre_status = service.cache.lookup(target_cve)
    print(f"\n[2] Pre-condition Check for SQLite Cache:")
    print(f"    Initial lookup for {target_cve} -> Cache status: {pre_status}")

    # =========================================================================
    # FIRST REQUEST: Cache MISS -> Query NVD + EPSS + KEV -> Store in SQLite
    # =========================================================================
    print("\n" + "=" * 70)
    print("FIRST REQUEST")
    print("=" * 70)
    
    # Check cache status right before enrichment
    _, status_1 = service.cache.lookup(target_cve)
    print(f"Cache status: {status_1}")
    print("Threat intelligence fetched")
    
    start_1 = time.perf_counter()
    result_1 = service.enrich_finding(sample_finding)
    elapsed_1 = time.perf_counter() - start_1
    
    print("Result stored in cache")
    print(f"[OK] Completed in {elapsed_1:.3f}s")
    print("\nThreatEnrichedFinding (JSON for Member 5):")
    print(result_1.model_dump_json(indent=2))

    # =========================================================================
    # SECOND REQUEST: Same CVE -> Cache HIT -> Immediate Return from SQLite
    # =========================================================================
    print("\n" + "=" * 70)
    print("SECOND REQUEST")
    print("=" * 70)

    # Check cache status right before enrichment
    _, status_2 = service.cache.lookup(target_cve)
    print(f"Cache status: {status_2}")
    print("Result retrieved from cache")
    print("No external API lookup required")

    start_2 = time.perf_counter()
    result_2 = service.enrich_finding(sample_finding)
    elapsed_2 = time.perf_counter() - start_2

    print(f"[OK] Completed in {elapsed_2:.5f}s")
    print(f"    CVSS Score     : {result_2.threat_intelligence.cvss_score}")
    print(f"    CVSS Vector    : {result_2.threat_intelligence.cvss_vector}")
    print(f"    EPSS Score     : {result_2.threat_intelligence.epss_score}")
    print(f"    EPSS Percentile: {result_2.threat_intelligence.epss_percentile}")
    print(f"    CISA KEV Listed: {result_2.threat_intelligence.kev_listed}")
    print(f"    KEV Date Added : {result_2.threat_intelligence.kev_date_added}")
    print(f"    Last Updated   : {result_2.threat_intelligence.last_updated}")

    # =========================================================================
    # FINAL STATISTICS
    # =========================================================================
    print("\n" + "=" * 70)
    print("FINAL STATISTICS")
    print("=" * 70)
    stats = service.get_stats()
    print(f"  total findings           : {stats['total_findings']}")
    print(f"  unique CVEs              : {stats['unique_cves']}")
    print(f"  cache hits               : {stats['cache_hits']}")
    print(f"  cache misses             : {stats['cache_misses']}")
    print(f"  fully enriched outcomes  : {stats['fully_enriched']}")
    print("=" * 70)
    print("[OK] Demonstration complete.\n")


if __name__ == "__main__":
    main()
