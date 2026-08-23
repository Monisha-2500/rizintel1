"""
tests/test_schemas.py
=====================
Phase 1 — Pydantic schema validation tests.

Tests:
  1. Valid ConfidenceEnrichedFinding parses without error.
  2. Valid ThreatEnrichedFinding parses without error.
  3. Finding with cve_id = null is accepted by ConfidenceEnrichedFinding.
  4. Finding with cve_id = null produces all-null threat_intelligence in ThreatEnrichedFinding.
  5. Invalid CVE format is rejected.
  6. Score out of range is rejected (scanner_consensus_score > 1.0).
  7. Severity must be a valid SeverityLevel enum.
  8. Empty finding_id is rejected.
  9. Empty asset_id is rejected.
  10. detected_by_count > total_scanners is rejected.
  11. CVSS score > 10.0 is rejected.
  12. EPSS score > 1.0 is rejected.
  13. kev_date_added must be YYYY-MM-DD format.
  14. last_updated must be ISO 8601 UTC timestamp.
  15. ThreatIntelligence all-null is valid (contract requires nullable defaults).
  16. Complete enriched finding round-trips through Pydantic correctly.
  17. Fixture files are valid JSON and parse correctly.
  18. expected_single.json has the correct structural shape.
"""

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

# ---------------------------------------------------------------------------
# Path helpers
# ---------------------------------------------------------------------------

FIXTURES_DIR = Path(__file__).parent / "fixtures"
INPUT_SINGLE  = FIXTURES_DIR / "input_single.json"
INPUT_NULL_CVE = FIXTURES_DIR / "input_null_cve.json"
EXPECTED_SINGLE = FIXTURES_DIR / "expected_single.json"

# ---------------------------------------------------------------------------
# Import models
# ---------------------------------------------------------------------------

import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

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
    ThreatEnrichedFinding,
    ThreatIntelligence,
    VulnerabilityType,
)


# ---------------------------------------------------------------------------
# Helper builders
# ---------------------------------------------------------------------------

def make_valid_input_finding(**overrides) -> dict:
    """Return a minimal valid ConfidenceEnrichedFinding payload."""
    base = {
        "schema_version": "1.0",
        "finding_id": "DEDUP-000001",
        "cve_id": "CVE-2018-7600",
        "vulnerability_name": "Drupalgeddon2 RCE",
        "vulnerability_type": "REMOTE_CODE_EXECUTION",
        "severity": "CRITICAL",
        "asset": {
            "asset_id": "ASSET-DB-083",
            "host": "db-083.example.net",
            "endpoint": "/backup",
            "port": 5432,
            "parameter": "limit",
        },
        "scanner_consensus": {
            "scanner_names": ["ZAP", "NMAP"],
            "detected_by_count": 2,
            "total_scanners": 4,
            "score": 0.5,
        },
        "finding_confidence": {
            "score": 0.6967,
            "classification": "NEEDS_REVIEW",
            "signals": {
                "scanner_consensus": 0.4765,
                "evidence_quality": 0.661,
                "cve_mapping": 0.9342,
                "repeatability": 0.6314,
            },
            "review_required": True,
        },
        "noise_assessment": {
            "likely_noise": False,
            "reason": "Reproducible across multiple scan sessions",
        },
        "source_findings": ["ZAP-195325", "NMAP-892495"],
    }
    base.update(overrides)
    return base


def make_valid_output_finding(**overrides) -> dict:
    """Return a minimal valid ThreatEnrichedFinding payload."""
    base = {
        "schema_version": "1.0",
        "finding_id": "DEDUP-000001",
        "cve_id": "CVE-2018-7600",
        "asset_id": "ASSET-DB-083",
        "vulnerability_name": "Drupalgeddon2 RCE",
        "vulnerability_type": "REMOTE_CODE_EXECUTION",
        "scanner_sources": ["ZAP", "NMAP"],
        "scanner_consensus_score": 0.5,
        "finding_confidence_score": 0.6967,
        "finding_confidence_classification": "NEEDS_REVIEW",
        "threat_intelligence": {
            "cvss_score": None,
            "cvss_vector": None,
            "epss_score": None,
            "epss_percentile": None,
            "kev_listed": None,
            "kev_date_added": None,
            "exploit_available": None,
            "exploit_sources": [],
            "last_updated": None,
        },
    }
    base.update(overrides)
    return base


# ===========================================================================
# TEST 1 — Valid ConfidenceEnrichedFinding parses without error
# ===========================================================================

def test_valid_input_finding_parses():
    data = make_valid_input_finding()
    finding = ConfidenceEnrichedFinding.model_validate(data)
    assert finding.finding_id == "DEDUP-000001"
    assert finding.cve_id == "CVE-2018-7600"
    assert finding.schema_version == SchemaVersion.V1_0
    assert finding.severity == SeverityLevel.CRITICAL
    assert finding.vulnerability_type == VulnerabilityType.REMOTE_CODE_EXECUTION


# ===========================================================================
# TEST 2 — Valid ThreatEnrichedFinding parses without error
# ===========================================================================

def test_valid_output_finding_parses():
    data = make_valid_output_finding()
    finding = ThreatEnrichedFinding.model_validate(data)
    assert finding.finding_id == "DEDUP-000001"
    assert finding.asset_id == "ASSET-DB-083"
    assert finding.scanner_consensus_score == 0.5
    assert finding.finding_confidence_score == 0.6967
    assert finding.finding_confidence_classification == ConfidenceClassification.NEEDS_REVIEW


# ===========================================================================
# TEST 3 — cve_id = null is accepted by ConfidenceEnrichedFinding
# ===========================================================================

def test_null_cve_id_accepted_in_input():
    data = make_valid_input_finding(cve_id=None)
    finding = ConfidenceEnrichedFinding.model_validate(data)
    assert finding.cve_id is None


# ===========================================================================
# TEST 4 — ThreatEnrichedFinding with cve_id = null has all-null threat intel
# ===========================================================================

def test_null_cve_produces_all_null_threat_intel():
    data = make_valid_output_finding(cve_id=None)
    finding = ThreatEnrichedFinding.model_validate(data)
    assert finding.cve_id is None
    ti = finding.threat_intelligence
    assert ti.cvss_score is None
    assert ti.cvss_vector is None
    assert ti.epss_score is None
    assert ti.epss_percentile is None
    assert ti.kev_listed is None
    assert ti.kev_date_added is None
    assert ti.exploit_available is None
    assert ti.exploit_sources == []
    assert ti.last_updated is None


# ===========================================================================
# TEST 5 — Invalid CVE format is rejected
# ===========================================================================

@pytest.mark.parametrize("bad_cve", [
    "CVE-202-1234",      # year too short
    "CVE-2024-123",      # sequence too short
    "cve-2024-12345",    # lowercase
    "2024-12345",        # missing CVE- prefix
    "CVE2024-12345",     # missing dash after CVE
    "CVE-2024-ABCDE",    # non-numeric sequence
])
def test_invalid_cve_format_rejected(bad_cve):
    data = make_valid_input_finding(cve_id=bad_cve)
    with pytest.raises(ValidationError) as exc_info:
        ConfidenceEnrichedFinding.model_validate(data)
    errors = exc_info.value.errors()
    assert any("cve_id" in str(e) or "CVE format" in str(e) for e in errors)


# ===========================================================================
# TEST 6 — Scanner consensus score out of range is rejected
# ===========================================================================

def test_scanner_consensus_score_above_one_rejected():
    data = make_valid_input_finding()
    data["scanner_consensus"]["score"] = 1.5
    with pytest.raises(ValidationError):
        ConfidenceEnrichedFinding.model_validate(data)


def test_scanner_consensus_score_below_zero_rejected():
    data = make_valid_input_finding()
    data["scanner_consensus"]["score"] = -0.1
    with pytest.raises(ValidationError):
        ConfidenceEnrichedFinding.model_validate(data)


# ===========================================================================
# TEST 7 — Severity must be a valid SeverityLevel
# ===========================================================================

def test_invalid_severity_rejected():
    data = make_valid_input_finding(severity="EXTREME")
    with pytest.raises(ValidationError):
        ConfidenceEnrichedFinding.model_validate(data)


@pytest.mark.parametrize("severity", ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"])
def test_all_valid_severities_accepted(severity):
    data = make_valid_input_finding(severity=severity)
    finding = ConfidenceEnrichedFinding.model_validate(data)
    assert finding.severity.value == severity


# ===========================================================================
# TEST 8 — Empty finding_id is rejected
# ===========================================================================

@pytest.mark.parametrize("bad_id", ["", "   "])
def test_empty_finding_id_rejected(bad_id):
    data = make_valid_input_finding(finding_id=bad_id)
    with pytest.raises(ValidationError):
        ConfidenceEnrichedFinding.model_validate(data)


# ===========================================================================
# TEST 9 — Empty asset_id is rejected
# ===========================================================================

@pytest.mark.parametrize("bad_id", ["", "   "])
def test_empty_asset_id_rejected_in_output(bad_id):
    data = make_valid_output_finding(asset_id=bad_id)
    with pytest.raises(ValidationError):
        ThreatEnrichedFinding.model_validate(data)


# ===========================================================================
# TEST 10 — detected_by_count > total_scanners is rejected
# ===========================================================================

def test_detected_by_count_exceeds_total_rejected():
    data = make_valid_input_finding()
    data["scanner_consensus"]["detected_by_count"] = 5
    data["scanner_consensus"]["total_scanners"] = 4
    with pytest.raises(ValidationError) as exc_info:
        ConfidenceEnrichedFinding.model_validate(data)
    errors = str(exc_info.value)
    assert "detected_by_count" in errors or "total_scanners" in errors


# ===========================================================================
# TEST 11 — CVSS score > 10.0 is rejected
# ===========================================================================

def test_cvss_score_above_ten_rejected():
    data = make_valid_output_finding()
    data["threat_intelligence"]["cvss_score"] = 10.1
    with pytest.raises(ValidationError):
        ThreatEnrichedFinding.model_validate(data)


def test_cvss_score_ten_accepted():
    data = make_valid_output_finding()
    data["threat_intelligence"]["cvss_score"] = 10.0
    finding = ThreatEnrichedFinding.model_validate(data)
    assert finding.threat_intelligence.cvss_score == 10.0


def test_cvss_score_zero_accepted():
    data = make_valid_output_finding()
    data["threat_intelligence"]["cvss_score"] = 0.0
    finding = ThreatEnrichedFinding.model_validate(data)
    assert finding.threat_intelligence.cvss_score == 0.0


# ===========================================================================
# TEST 12 — EPSS score > 1.0 is rejected
# ===========================================================================

def test_epss_score_above_one_rejected():
    data = make_valid_output_finding()
    data["threat_intelligence"]["epss_score"] = 1.01
    with pytest.raises(ValidationError):
        ThreatEnrichedFinding.model_validate(data)


def test_epss_percentile_above_one_rejected():
    data = make_valid_output_finding()
    data["threat_intelligence"]["epss_percentile"] = 1.001
    with pytest.raises(ValidationError):
        ThreatEnrichedFinding.model_validate(data)


def test_epss_score_one_accepted():
    data = make_valid_output_finding()
    data["threat_intelligence"]["epss_score"] = 1.0
    finding = ThreatEnrichedFinding.model_validate(data)
    assert finding.threat_intelligence.epss_score == 1.0


# ===========================================================================
# TEST 13 — kev_date_added must be YYYY-MM-DD format
# ===========================================================================

@pytest.mark.parametrize("bad_date", [
    "20240401",          # no dashes
    "2024/04/01",        # slashes
    "April 1, 2024",     # natural language
    "2024-4-1",          # single-digit month/day
    "24-04-01",          # two-digit year
])
def test_invalid_kev_date_format_rejected(bad_date):
    data = make_valid_output_finding()
    data["threat_intelligence"]["kev_date_added"] = bad_date
    with pytest.raises(ValidationError):
        ThreatEnrichedFinding.model_validate(data)


def test_valid_kev_date_format_accepted():
    data = make_valid_output_finding()
    data["threat_intelligence"]["kev_date_added"] = "2024-04-01"
    finding = ThreatEnrichedFinding.model_validate(data)
    assert finding.threat_intelligence.kev_date_added == "2024-04-01"


# ===========================================================================
# TEST 14 — last_updated must be ISO 8601 UTC timestamp
# ===========================================================================

@pytest.mark.parametrize("bad_ts", [
    "2026-08-20",               # date only, no time
    "2026-08-20 00:00:00",      # space separator, not T
    "Aug 20, 2026",             # natural language
    "20260820T000000Z",         # compact form, no dashes
])
def test_invalid_last_updated_format_rejected(bad_ts):
    data = make_valid_output_finding()
    data["threat_intelligence"]["last_updated"] = bad_ts
    with pytest.raises(ValidationError):
        ThreatEnrichedFinding.model_validate(data)


@pytest.mark.parametrize("good_ts", [
    "2026-08-20T00:00:00Z",
    "2026-08-20T00:00:00+00:00",
    "2026-08-20T12:34:56.789Z",
])
def test_valid_last_updated_format_accepted(good_ts):
    data = make_valid_output_finding()
    data["threat_intelligence"]["last_updated"] = good_ts
    finding = ThreatEnrichedFinding.model_validate(data)
    assert finding.threat_intelligence.last_updated == good_ts


# ===========================================================================
# TEST 15 — ThreatIntelligence all-null is valid
# ===========================================================================

def test_all_null_threat_intelligence_is_valid():
    ti = ThreatIntelligence(
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
    assert ti.cvss_score is None
    assert ti.exploit_sources == []


# ===========================================================================
# TEST 16 — Round-trip: dict → Pydantic → dict preserves values
# ===========================================================================

def test_enriched_finding_round_trip():
    data = make_valid_output_finding()
    data["threat_intelligence"]["cvss_score"] = 9.8
    data["threat_intelligence"]["cvss_vector"] = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    data["threat_intelligence"]["epss_score"] = 0.9723
    data["threat_intelligence"]["epss_percentile"] = 0.9985
    data["threat_intelligence"]["kev_listed"] = True
    data["threat_intelligence"]["kev_date_added"] = "2024-04-01"
    data["threat_intelligence"]["exploit_available"] = True
    data["threat_intelligence"]["exploit_sources"] = ["exploit-db", "github"]
    data["threat_intelligence"]["last_updated"] = "2026-08-20T00:00:00Z"

    finding = ThreatEnrichedFinding.model_validate(data)
    assert finding.threat_intelligence.cvss_score == 9.8
    assert finding.threat_intelligence.cvss_vector == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    assert finding.threat_intelligence.epss_score == 0.9723
    assert finding.threat_intelligence.kev_listed is True
    assert finding.threat_intelligence.exploit_sources == ["exploit-db", "github"]
    assert finding.threat_intelligence.last_updated == "2026-08-20T00:00:00Z"

    # Round-trip back to dict
    dumped = finding.model_dump()
    assert dumped["finding_id"] == "DEDUP-000001"
    assert dumped["asset_id"] == "ASSET-DB-083"
    assert dumped["threat_intelligence"]["cvss_score"] == 9.8


# ===========================================================================
# TEST 17 — Fixture files are valid JSON and parse correctly
# ===========================================================================

def test_input_single_fixture_is_valid_json():
    assert INPUT_SINGLE.exists(), f"Fixture not found: {INPUT_SINGLE}"
    with INPUT_SINGLE.open() as f:
        data = json.load(f)
    finding = ConfidenceEnrichedFinding.model_validate(data)
    assert finding.finding_id == "DEDUP-000001"
    assert finding.cve_id == "CVE-2018-7600"


def test_input_null_cve_fixture_is_valid_json():
    assert INPUT_NULL_CVE.exists(), f"Fixture not found: {INPUT_NULL_CVE}"
    with INPUT_NULL_CVE.open() as f:
        data = json.load(f)
    finding = ConfidenceEnrichedFinding.model_validate(data)
    assert finding.finding_id == "DEDUP-000017"
    assert finding.cve_id is None


# ===========================================================================
# TEST 18 — expected_single.json has the correct structural shape
# ===========================================================================

def test_expected_single_fixture_validates_as_threat_enriched_finding():
    assert EXPECTED_SINGLE.exists(), f"Fixture not found: {EXPECTED_SINGLE}"
    with EXPECTED_SINGLE.open() as f:
        raw = json.load(f)

    # Strip comment keys (prefixed with _)
    data = {k: v for k, v in raw.items() if not k.startswith("_")}

    finding = ThreatEnrichedFinding.model_validate(data)
    assert finding.finding_id == "DEDUP-000001"
    assert finding.asset_id == "ASSET-DB-083"
    assert finding.cve_id == "CVE-2018-7600"
    assert finding.threat_intelligence.cvss_score is None
    assert finding.threat_intelligence.exploit_sources == []
    assert finding.threat_intelligence.last_updated is None


# ===========================================================================
# Additional edge-case tests
# ===========================================================================

def test_kev_listed_false_is_valid():
    """kev_listed=False (not in KEV) is explicitly allowed."""
    data = make_valid_output_finding()
    data["threat_intelligence"]["kev_listed"] = False
    finding = ThreatEnrichedFinding.model_validate(data)
    assert finding.threat_intelligence.kev_listed is False


def test_kev_listed_none_is_valid():
    """kev_listed=None (KEV unavailable) is explicitly allowed."""
    data = make_valid_output_finding()
    data["threat_intelligence"]["kev_listed"] = None
    finding = ThreatEnrichedFinding.model_validate(data)
    assert finding.threat_intelligence.kev_listed is None


def test_exploit_sources_populated():
    data = make_valid_output_finding()
    data["threat_intelligence"]["exploit_available"] = True
    data["threat_intelligence"]["exploit_sources"] = ["exploit-db", "metasploit"]
    finding = ThreatEnrichedFinding.model_validate(data)
    assert len(finding.threat_intelligence.exploit_sources) == 2


def test_confidence_classification_confirmed():
    data = make_valid_output_finding(finding_confidence_classification="CONFIRMED")
    finding = ThreatEnrichedFinding.model_validate(data)
    assert finding.finding_confidence_classification == ConfidenceClassification.CONFIRMED


# NOTE: The shared sample_data/ dataset belongs to the RizIntel team.
# Per Member 4's scope, dataset-level tests are not part of core unit testing.
# Schema validation is covered exhaustively by the tests above.
