"""
test_m2_match_confidence.py
===========================
Focused test suite for RizIntel Issue #3: M2 Match Confidence vs Scanner Consensus.

Validates:
1. Exact CVE match produces high match_score (1.0) and EXACT_CVE method.
2. Exact Fingerprint match produces 0.95 match_score and EXACT_FINGERPRINT method.
3. Fuzzy/Hybrid match produces calculated score based on actual similarity.
4. Scanner consensus changes (e.g. 1/3 -> 2/3 -> 3/3) without altering match_score.
5. Match score changes without altering scanner consensus.
6. Match features reflect real calculated values (not hardcoded 1.0s).
7. Deterministic group aggregation for multi-member groups (>2 findings).
8. Singletons receive SINGLETON method with 1.0 match_score while consensus is 0.33.
9. M3 receives independent consensus and match_confidence signals (no double counting).
10. E2E pipeline verification proving consensus and match_score are genuinely distinct.
"""

from pathlib import Path
import pytest

from mem2.src.models import NormalizedFinding
from mem2.src.deduplicator import Deduplicator
from mem2.src.matcher import VulnerabilityMatcher, compute_endpoint_similarity, compute_parameter_similarity
from services.pipeline_service import UnifiedPipelineRunner, DEFAULT_ASSET_CATALOG

_BACKEND_DIR = Path(__file__).resolve().parent.parent


# =============================================================================
# 1. Real Match Score & Method Tests
# =============================================================================

def test_exact_cve_match_score_and_method():
    """Exact CVE match on the same asset must yield match_score 1.0 and EXACT_CVE method."""
    f1 = NormalizedFinding(
        finding_id="ZAP-01",
        scanner="ZAP",
        cve_id="CVE-2024-1234",
        vulnerability_name="SQL Injection",
        vulnerability_type="SQL_INJECTION",
        severity="HIGH",
        asset_id="ASSET-WEB-001",
        host="payments.internal.corp",
        url="https://payments.internal.corp/login",
        endpoint="/login",
        port=443,
        parameter="username",
        description="SQL injection detected",
        timestamp="2026-08-20T10:00:00Z"
    )
    f2 = NormalizedFinding(
        finding_id="NUCLEI-01",
        scanner="NUCLEI",
        cve_id="CVE-2024-1234",
        vulnerability_name="SQL Injection Vulnerability",
        vulnerability_type="SQL_INJECTION",
        severity="HIGH",
        asset_id="ASSET-WEB-001",
        host="payments.internal.corp",
        url="https://payments.internal.corp/login",
        endpoint="/login",
        port=443,
        parameter="username",
        description="SQL injection confirmed",
        timestamp="2026-08-20T10:05:00Z"
    )

    deduplicator = Deduplicator()
    result = deduplicator.deduplicate([f1, f2])
    assert len(result["findings"]) == 1
    deduped = result["findings"][0]

    assert deduped["deduplication"]["match_method"] == "EXACT_CVE"
    assert deduped["deduplication"]["match_score"] == 1.0
    # Scanner consensus must be 2/3 (0.67), strictly different from match_score (1.0)
    assert deduped["scanner_consensus"]["score"] == 0.67
    assert deduped["deduplication"]["match_score"] != deduped["scanner_consensus"]["score"]


def test_exact_fingerprint_match_score_and_method():
    """Exact fingerprint match (no CVE) must yield match_score 0.95 and EXACT_FINGERPRINT method."""
    f1 = NormalizedFinding(
        finding_id="ZAP-02",
        scanner="ZAP",
        cve_id=None,
        vulnerability_name="Cross-Site Scripting",
        vulnerability_type="CROSS_SITE_SCRIPTING",
        severity="MEDIUM",
        asset_id="ASSET-DEV-003",
        host="staging.internal.corp",
        url="https://staging.internal.corp/search",
        endpoint="/search",
        port=443,
        parameter="q",
        description="Reflected XSS",
        timestamp="2026-08-20T10:00:00Z"
    )
    f2 = NormalizedFinding(
        finding_id="WAPITI-02",
        scanner="WAPITI",
        cve_id=None,
        vulnerability_name="Cross-Site Scripting",
        vulnerability_type="CROSS_SITE_SCRIPTING",
        severity="MEDIUM",
        asset_id="ASSET-DEV-003",
        host="staging.internal.corp",
        url="https://staging.internal.corp/search",
        endpoint="/search",
        port=443,
        parameter="q",
        description="Reflected XSS found",
        timestamp="2026-08-20T10:02:00Z"
    )

    deduplicator = Deduplicator()
    result = deduplicator.deduplicate([f1, f2])
    assert len(result["findings"]) == 1
    deduped = result["findings"][0]

    assert deduped["deduplication"]["match_method"] == "EXACT_FINGERPRINT"
    assert deduped["deduplication"]["match_score"] == 0.95
    assert deduped["scanner_consensus"]["score"] == 0.67


def test_fuzzy_hybrid_match_reflects_actual_similarity():
    """Fuzzy/Hybrid match must produce calculated score reflecting keyword and endpoint overlap."""
    f1 = NormalizedFinding(
        finding_id="ZAP-03",
        scanner="ZAP",
        cve_id=None,
        vulnerability_name="Server Header Information Disclosure",
        vulnerability_type="SECURITY_HEADER",
        severity="LOW",
        asset_id="ASSET-WEB-001",
        host="payments.internal.corp",
        url="https://payments.internal.corp/api/v1",
        endpoint="/api/v1",
        port=443,
        parameter=None,
        description="Server leaks banner",
        timestamp="2026-08-20T10:00:00Z"
    )
    f2 = NormalizedFinding(
        finding_id="NUCLEI-03",
        scanner="NUCLEI",
        cve_id=None,
        vulnerability_name="Information Disclosure via Server Header",
        vulnerability_type="SECURITY_HEADER",
        severity="LOW",
        asset_id="ASSET-WEB-001",
        host="payments.internal.corp",
        url="https://payments.internal.corp/",
        endpoint="/",
        port=443,
        parameter=None,
        description="Server banner exposure",
        timestamp="2026-08-20T10:05:00Z"
    )

    matcher = VulnerabilityMatcher(similarity_threshold=0.60)
    is_match, score, features = matcher.hybrid_match(f1, f2)
    assert is_match is True
    assert features["match_method"] == "HYBRID"
    assert 0.60 <= score <= 1.0

    deduplicator = Deduplicator()
    result = deduplicator.deduplicate([f1, f2])
    assert len(result["findings"]) == 1
    deduped = result["findings"][0]
    assert deduped["deduplication"]["match_method"] == "HYBRID"
    assert deduped["deduplication"]["match_score"] == score


# =============================================================================
# 2. Independence: Consensus Changes vs Match Score Changes
# =============================================================================

def test_consensus_changes_without_altering_match_score():
    """
    1 scanner -> consensus = 0.33, match_score = 1.0 (singleton)
    2 scanners -> consensus = 0.67, match_score = 1.0 (exact CVE)
    3 scanners -> consensus = 1.00, match_score = 1.0 (exact CVE)
    Match score stays 1.0 while consensus scales with scanner agreement.
    """
    def make_finding(fid, scanner):
        return NormalizedFinding(
            finding_id=fid,
            scanner=scanner,
            cve_id="CVE-2021-44228",
            vulnerability_name="Log4j RCE",
            vulnerability_type="REMOTE_CODE_EXECUTION",
            severity="CRITICAL",
            asset_id="ASSET-WEB-001",
            host="payments.internal.corp",
            url="https://payments.internal.corp/app",
            endpoint="/app",
            port=443,
            parameter="user",
            description="Log4Shell",
            timestamp="2026-08-20T10:00:00Z"
        )

    deduplicator = Deduplicator()

    # 1 scanner
    r1 = deduplicator.deduplicate([make_finding("F1", "ZAP")])
    assert r1["findings"][0]["scanner_consensus"]["score"] == 0.33
    assert r1["findings"][0]["deduplication"]["match_score"] == 1.0
    assert r1["findings"][0]["deduplication"]["match_method"] == "SINGLETON"

    # 2 scanners
    r2 = deduplicator.deduplicate([make_finding("F1", "ZAP"), make_finding("F2", "NUCLEI")])
    assert r2["findings"][0]["scanner_consensus"]["score"] == 0.67
    assert r2["findings"][0]["deduplication"]["match_score"] == 1.0
    assert r2["findings"][0]["deduplication"]["match_method"] == "EXACT_CVE"

    # 3 scanners
    r3 = deduplicator.deduplicate([make_finding("F1", "ZAP"), make_finding("F2", "NUCLEI"), make_finding("F3", "OPENVAS")])
    assert r3["findings"][0]["scanner_consensus"]["score"] == 1.00
    assert r3["findings"][0]["deduplication"]["match_score"] == 1.0
    assert r3["findings"][0]["deduplication"]["match_method"] == "EXACT_CVE"


def test_match_score_changes_without_altering_consensus():
    """
    Two pairs of 2-scanner findings (both have consensus = 0.67):
    Pair A: Exact CVE match => match_score = 1.0
    Pair B: Fuzzy title similarity => match_score ~ 0.7-0.85
    Consensus is 0.67 for both, while match_score varies according to evidence strength.
    """
    # Pair A: Exact CVE
    f_cve1 = NormalizedFinding(
        finding_id="A1", scanner="ZAP", cve_id="CVE-2024-9999", vulnerability_name="Auth Bypass",
        vulnerability_type="AUTHENTICATION_BYPASS", severity="HIGH", asset_id="ASSET-WEB-001",
        host="payments.internal.corp", url="https://payments.internal.corp/admin", endpoint="/admin",
        port=443, parameter=None, description="Auth bypass", timestamp="2026-08-20T10:00:00Z"
    )
    f_cve2 = NormalizedFinding(
        finding_id="A2", scanner="NUCLEI", cve_id="CVE-2024-9999", vulnerability_name="Auth Bypass",
        vulnerability_type="AUTHENTICATION_BYPASS", severity="HIGH", asset_id="ASSET-WEB-001",
        host="payments.internal.corp", url="https://payments.internal.corp/admin", endpoint="/admin",
        port=443, parameter=None, description="Auth bypass", timestamp="2026-08-20T10:05:00Z"
    )

    # Pair B: Fuzzy match (no CVE)
    f_fuzz1 = NormalizedFinding(
        finding_id="B1", scanner="ZAP", cve_id=None, vulnerability_name="Directory Traversal Attack",
        vulnerability_type="PATH_TRAVERSAL", severity="MEDIUM", asset_id="ASSET-WEB-001",
        host="payments.internal.corp", url="https://payments.internal.corp/files/get", endpoint="/files/get",
        port=443, parameter="doc", description="Path traversal", timestamp="2026-08-20T10:00:00Z"
    )
    f_fuzz2 = NormalizedFinding(
        finding_id="B2", scanner="NUCLEI", cve_id=None, vulnerability_name="Path Traversal In Files",
        vulnerability_type="PATH_TRAVERSAL", severity="MEDIUM", asset_id="ASSET-WEB-001",
        host="payments.internal.corp", url="https://payments.internal.corp/files", endpoint="/files",
        port=443, parameter=None, description="Path traversal", timestamp="2026-08-20T10:05:00Z"
    )

    deduplicator = Deduplicator()
    res_a = deduplicator.deduplicate([f_cve1, f_cve2])
    res_b = deduplicator.deduplicate([f_fuzz1, f_fuzz2])

    dedup_a = res_a["findings"][0]
    dedup_b = res_b["findings"][0]

    # Both have exactly 2 scanners -> consensus = 0.67
    assert dedup_a["scanner_consensus"]["score"] == 0.67
    assert dedup_b["scanner_consensus"]["score"] == 0.67

    # Match scores differ according to evidence
    assert dedup_a["deduplication"]["match_score"] == 1.0
    assert dedup_b["deduplication"]["match_score"] < 1.0
    assert dedup_a["deduplication"]["match_score"] != dedup_b["deduplication"]["match_score"]


# =============================================================================
# 3. Real Match Features (No Hardcoded 1.0s)
# =============================================================================

def test_match_features_reflect_real_calculated_values():
    """Features like endpoint_similarity, parameter_match, and vulnerability_similarity must be real numbers."""
    f1 = NormalizedFinding(
        finding_id="F1", scanner="ZAP", cve_id=None, vulnerability_name="SQL Injection in Login Form",
        vulnerability_type="SQL_INJECTION", severity="HIGH", asset_id="ASSET-WEB-001",
        host="payments.internal.corp", url="https://payments.internal.corp/api/v1/auth/login",
        endpoint="/api/v1/auth/login", port=443, parameter="user", description="SQLi", timestamp="2026-08-20T10:00:00Z"
    )
    f2 = NormalizedFinding(
        finding_id="F2", scanner="NUCLEI", cve_id=None, vulnerability_name="SQLi Vulnerability",
        vulnerability_type="SQL_INJECTION", severity="HIGH", asset_id="ASSET-WEB-001",
        host="payments.internal.corp", url="https://payments.internal.corp/api/v1/auth",
        endpoint="/api/v1/auth", port=443, parameter=None, description="SQLi", timestamp="2026-08-20T10:05:00Z"
    )

    deduplicator = Deduplicator()
    result = deduplicator.deduplicate([f1, f2])
    assert len(result["findings"]) == 1
    features = result["findings"][0]["deduplication"]["match_features"]

    # Must contain all expected keys with real float values
    assert "cve_match" in features
    assert "host_match" in features
    assert "endpoint_similarity" in features
    assert "parameter_match" in features
    assert "vulnerability_similarity" in features

    assert features["cve_match"] == 0.0  # No CVE
    assert features["host_match"] == 1.0
    assert 0.70 <= features["endpoint_similarity"] <= 1.0  # Path prefix similarity
    assert features["parameter_match"] == 0.90  # One parameter is None
    assert 0.60 <= features["vulnerability_similarity"] <= 1.0


# =============================================================================
# 4. Deterministic Multi-Member Group Aggregation
# =============================================================================

def test_deterministic_multi_member_group_aggregation():
    """Group of 3 findings with mixed similarity matches must aggregate match_score deterministically."""
    f1 = NormalizedFinding(
        finding_id="M1", scanner="ZAP", cve_id="CVE-2024-1111", vulnerability_name="Remote Code Execution",
        vulnerability_type="REMOTE_CODE_EXECUTION", severity="CRITICAL", asset_id="ASSET-WEB-001",
        host="payments.internal.corp", url="https://payments.internal.corp/api/exec", endpoint="/api/exec",
        port=443, parameter="cmd", description="RCE", timestamp="2026-08-20T10:00:00Z"
    )
    f2 = NormalizedFinding(
        finding_id="M2", scanner="NUCLEI", cve_id="CVE-2024-1111", vulnerability_name="RCE in API Exec",
        vulnerability_type="REMOTE_CODE_EXECUTION", severity="CRITICAL", asset_id="ASSET-WEB-001",
        host="payments.internal.corp", url="https://payments.internal.corp/api/exec", endpoint="/api/exec",
        port=443, parameter="cmd", description="RCE", timestamp="2026-08-20T10:05:00Z"
    )
    f3 = NormalizedFinding(
        finding_id="M3", scanner="OPENVAS", cve_id="CVE-2024-1111", vulnerability_name="Command Execution",
        vulnerability_type="REMOTE_CODE_EXECUTION", severity="CRITICAL", asset_id="ASSET-WEB-001",
        host="payments.internal.corp", url="https://payments.internal.corp/api", endpoint="/api",
        port=443, parameter=None, description="RCE", timestamp="2026-08-20T10:10:00Z"
    )

    deduplicator = Deduplicator()
    res1 = deduplicator.deduplicate([f1, f2, f3])
    res2 = deduplicator.deduplicate([f1, f2, f3])

    # Must be 100% deterministic across multiple runs
    assert res1["findings"][0]["deduplication"]["match_score"] == res2["findings"][0]["deduplication"]["match_score"]
    assert res1["findings"][0]["deduplication"]["match_method"] == res2["findings"][0]["deduplication"]["match_method"]
    assert res1["findings"][0]["deduplication"]["match_features"] == res2["findings"][0]["deduplication"]["match_features"]


# =============================================================================
# 5. M3 Confidence Signal Independence
# =============================================================================

def test_m3_receives_independent_consensus_and_match_confidence():
    """
    End-to-End M1 -> M3 check: verify that M3 receives consensus and match_confidence
    as two distinct, non-aliased numeric signals in confidence_signals.
    """
    # A single scanner finding (ZAP only)
    f_single = NormalizedFinding(
        finding_id="SINGLE-01", scanner="ZAP", cve_id=None, vulnerability_name="Missing Security Header",
        vulnerability_type="SECURITY_HEADER", severity="LOW", asset_id="ASSET-DEV-003",
        host="staging.internal.corp", url="https://staging.internal.corp/", endpoint="/",
        port=443, parameter=None, description="X-Frame-Options missing", evidence="Header missing",
        timestamp="2026-08-20T10:00:00Z"
    )

    runner = UnifiedPipelineRunner()
    deduped, _ = runner.run_m2([f_single.model_dump()])
    assert len(deduped) == 1

    d = deduped[0]
    # M2 output check:
    assert d["scanner_consensus"]["score"] == 0.33
    assert d["deduplication"]["match_score"] == 1.0
    assert d["deduplication"]["match_method"] == "SINGLETON"

    # M3 enrichment check:
    confidence_findings = runner.run_m3(deduped)
    assert len(confidence_findings) == 1
    c = confidence_findings[0]

    signals = c["finding_confidence"]["signals"]
    # Signal 1 (scanner_consensus) and Signal 2 (match_confidence) must be independent
    assert signals["scanner_consensus"] == 0.33
    assert signals["match_confidence"] == 1.0
    assert signals["scanner_consensus"] != signals["match_confidence"]
