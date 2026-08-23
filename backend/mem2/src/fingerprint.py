"""
Fingerprint Generation for Vulnerability Matching

Creates unique identifiers for findings so we can quickly group duplicates.
"""
import hashlib
from typing import Optional
from src.models import NormalizedFinding


def generate_fingerprint(finding: NormalizedFinding) -> str:
    """
    Create a fingerprint key for exact matching.
    
    Uses: host + endpoint + port + parameter + vulnerability_type
    
    Example: "example.com_/login_443_username_SQL_INJECTION"
    
    This is the PRIMARY key for deduplication.
    If two findings have the same fingerprint, they're very likely duplicates.
    """
    # Extract components, handle None values
    host = finding.host.lower().strip()
    endpoint = finding.endpoint.lower().strip() if finding.endpoint else "/"
    port = str(finding.port) if finding.port else "0"
    parameter = finding.parameter.lower().strip() if finding.parameter else "none"
    vuln_type = finding.vulnerability_type.upper().strip()
    
    # Create composite key
    key = f"{host}_{endpoint}_{port}_{parameter}_{vuln_type}"
    
    # Hash for consistent length
    return hashlib.md5(key.encode()).hexdigest()[:16]


def generate_cve_fingerprint(finding: NormalizedFinding) -> Optional[str]:
    """
    Alternative fingerprint using CVE + host + port.
    
    This is a STRONGER match signal when CVE is available.
    If both findings have the same CVE, they're the same vulnerability.
    """
    if not finding.cve_id:
        return None
    
    host = finding.host.lower().strip()
    port = str(finding.port) if finding.port else "0"
    cve = finding.cve_id.strip()
    
    key = f"{host}_{port}_{cve}"
    return hashlib.md5(key.encode()).hexdigest()[:16]
