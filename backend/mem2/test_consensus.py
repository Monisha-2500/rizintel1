from src.models import NormalizedFinding
from src.consensus import calculate_scanner_consensus

# Simulate findings from 3 scanners
findings = [
    NormalizedFinding(
        finding_id="ZAP-001",
        scanner="ZAP",
        cve_id="CVE-2024-1234",
        vulnerability_name="SQL Injection",
        vulnerability_type="SQL_INJECTION",
        severity="HIGH",
        asset_id="ASSET-001",
        host="example.com",
        url="https://example.com/login",
        endpoint="/login",
        port=443,
        parameter="username",
        description="SQL injection",
        evidence=None,
        timestamp="2026-08-14T05:39:23Z"
    ),
    NormalizedFinding(
        finding_id="NUCLEI-001",
        scanner="NUCLEI",
        cve_id="CVE-2024-1234",
        vulnerability_name="SQLi vulnerability",
        vulnerability_type="SQL_INJECTION",
        severity="HIGH",
        asset_id="ASSET-001",
        host="example.com",
        url="https://example.com/login",
        endpoint="/login",
        port=443,
        parameter="username",
        description="SQL injection found",
        evidence=None,
        timestamp="2026-08-14T05:40:00Z"
    ),
    NormalizedFinding(
        finding_id="OPENVAS-001",
        scanner="OPENVAS",
        cve_id="CVE-2024-1234",
        vulnerability_name="SQL Injection Vulnerability",
        vulnerability_type="SQL_INJECTION",
        severity="HIGH",
        asset_id="ASSET-001",
        host="example.com",
        url="https://example.com/login",
        endpoint="/login",
        port=443,
        parameter="username",
        description="SQL injection detected",
        evidence=None,
        timestamp="2026-08-14T05:41:00Z"
    )
]

consensus = calculate_scanner_consensus(findings)

print("=== SCANNER CONSENSUS ===")
print(f"Scanner Names: {consensus['scanner_names']}")
print(f"Detected by: {consensus['detected_by_count']} / {consensus['total_scanners']} scanners")
print(f"Consensus Score: {consensus['score']}")