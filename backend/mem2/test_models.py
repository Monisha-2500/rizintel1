from src.models import NormalizedFinding

# Sample finding
sample = {
    "finding_id": "TEST-001",
    "scanner": "ZAP",
    "cve_id": None,
    "vulnerability_name": "SQL Injection",
    "vulnerability_type": "SQL_INJECTION",
    "severity": "HIGH",
    "asset_id": "ASSET-001",
    "host": "example.com",
    "url": "https://example.com/login",
    "endpoint": "/login",
    "port": 443,
    "parameter": "username",
    "description": "SQL injection vulnerability",
    "evidence": None,
    "timestamp": "2026-08-14T05:39:23Z"
}

try:
    finding = NormalizedFinding(**sample)
    print("✅ Model works!")
    print(f"   Finding ID: {finding.finding_id}")
    print(f"   Scanner: {finding.scanner}")
    print(f"   Host: {finding.host}")
    print(f"   Vulnerability: {finding.vulnerability_name}")
except Exception as e:
    print(f"❌ Error: {e}")