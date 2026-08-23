from src.models import NormalizedFinding
from src.fingerprint import generate_fingerprint, generate_cve_fingerprint

# Test finding 1 - SQL Injection from ZAP
f1 = NormalizedFinding(
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
)

# Test finding 2 - Same vulnerability from Nuclei (should match)
f2 = NormalizedFinding(
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
)

# Test finding 3 - Different host (should NOT match)
f3 = NormalizedFinding(
    finding_id="OPENVAS-001",
    scanner="OPENVAS",
    cve_id="CVE-2024-1234",
    vulnerability_name="SQL Injection",
    vulnerability_type="SQL_INJECTION",
    severity="HIGH",
    asset_id="ASSET-002",
    host="test.example.com",
    url="https://test.example.com/login",
    endpoint="/login",
    port=443,
    parameter="username",
    description="SQL injection",
    evidence=None,
    timestamp="2026-08-14T05:41:00Z"
)

# Generate fingerprints
fp1 = generate_fingerprint(f1)
fp2 = generate_fingerprint(f2)
fp3 = generate_fingerprint(f3)

cve1 = generate_cve_fingerprint(f1)
cve2 = generate_cve_fingerprint(f2)
cve3 = generate_cve_fingerprint(f3)

print("=== FINGERPRINT TESTS ===")
print(f"Finding 1 (ZAP): {fp1}")
print(f"Finding 2 (Nuclei): {fp2}")
print(f"Finding 3 (OpenVAS): {fp3}")
print()
print(f"F1 and F2 match? {fp1 == fp2} (Expected: True)")
print(f"F1 and F3 match? {fp1 == fp3} (Expected: False)")
print()
print("=== CVE FINGERPRINT TESTS ===")
print(f"F1 CVE: {cve1}")
print(f"F2 CVE: {cve2}")
print(f"F3 CVE: {cve3}")
print()
print(f"F1 and F2 CVE match? {cve1 == cve2} (Expected: True)")
print(f"F1 and F3 CVE match? {cve1 == cve3} (Expected: False)")