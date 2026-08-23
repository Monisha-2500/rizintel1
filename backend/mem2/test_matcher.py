from src.models import NormalizedFinding
from src.matcher import VulnerabilityMatcher

# Create matcher with 85% threshold
matcher = VulnerabilityMatcher(similarity_threshold=0.85)

# Test 1: Same vulnerability, slightly different names
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

# Test 2: Different vulnerabilities
f3 = NormalizedFinding(
    finding_id="ZAP-002",
    scanner="ZAP",
    cve_id=None,
    vulnerability_name="Cross-Site Scripting",
    vulnerability_type="XSS",
    severity="MEDIUM",
    asset_id="ASSET-001",
    host="example.com",
    url="https://example.com/search",
    endpoint="/search",
    port=443,
    parameter="q",
    description="XSS vulnerability",
    evidence=None,
    timestamp="2026-08-14T05:42:00Z"
)

f4 = NormalizedFinding(
    finding_id="NUCLEI-002",
    scanner="NUCLEI",
    cve_id=None,
    vulnerability_name="XSS vulnerability",
    vulnerability_type="XSS",
    severity="MEDIUM",
    asset_id="ASSET-001",
    host="example.com",
    url="https://example.com/search",
    endpoint="/search",
    port=443,
    parameter="q",
    description="XSS found",
    evidence=None,
    timestamp="2026-08-14T05:43:00Z"
)

print("=== EXACT MATCH TEST ===")
is_match, score = matcher.exact_match(f1, f2)
print(f"F1 vs F2 (same CVE): {is_match} (Score: {score})")
print()

print("=== FUZZY MATCH TEST - Similar Names ===")
is_match, score, features = matcher.fuzzy_match(f1, f2)
print(f"F1 vs F2 ('SQL Injection' vs 'SQLi vulnerability'):")
print(f"  Match: {is_match}")
print(f"  Score: {score:.2f}")
print(f"  Features: {features}")
print()

print("=== FUZZY MATCH TEST - Different Vulnerabilities ===")
is_match, score, features = matcher.fuzzy_match(f3, f4)
print(f"F3 vs F4 ('XSS' vs 'XSS vulnerability'):")
print(f"  Match: {is_match}")
print(f"  Score: {score:.2f}")
print(f"  Features: {features}")
print()

print("=== HYBRID MATCH TEST ===")
is_match, score, features = matcher.hybrid_match(f1, f2)
print(f"F1 vs F2 (should match): {is_match} (Score: {score:.2f})")
print(f"Features: {features}")
print()

is_match, score, features = matcher.hybrid_match(f1, f3)
print(f"F1 vs F3 (different vulnerabilities): {is_match} (Score: {score:.2f})")