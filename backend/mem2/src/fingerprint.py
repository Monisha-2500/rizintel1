"""
Fingerprint Generation for Vulnerability Matching

Creates unique identifiers for findings so we can quickly group duplicates.

Asset Boundary Guarantee:
- asset_id is ALWAYS the outermost key component.
- Two findings with different asset_ids will never share a fingerprint.
- UNMAPPED findings use normalized host:port as instance boundary so
  two unrelated unknown hosts cannot merge.
"""
import hashlib
from typing import Optional
try:
    from .models import NormalizedFinding
except (ImportError, ValueError):
    from src.models import NormalizedFinding


def _asset_boundary_key(finding: NormalizedFinding) -> str:
    """
    Return the canonical asset boundary string for a finding.

    For a resolved asset (asset_id != 'UNMAPPED'):
        Use asset_id directly — it is the authoritative, catalog-verified identity.

    For UNMAPPED findings:
        Use normalized host:port as the instance boundary so two different
        unknown hosts cannot be treated as the same asset.
        This is deliberately conservative: unknown host A != unknown host B.
    """
    asset_id = (finding.asset_id or "UNMAPPED").strip().upper()
    if asset_id == "UNMAPPED":
        host = finding.host.lower().strip()
        port = str(finding.port) if finding.port else "0"
        return f"UNMAPPED:{host}:{port}"
    return asset_id


def generate_fingerprint(finding: NormalizedFinding) -> str:
    """
    Create a fingerprint key for exact matching.

    Key hierarchy:
      asset_boundary | host | endpoint | port | parameter | vulnerability_type

    The asset_boundary is ALWAYS the outermost component.
    Two findings with different asset_ids cannot share this fingerprint.

    Example (resolved asset):
        "ASSET-LAB-WEBGOAT_127.0.0.1_/WebGoat/SqlInjection_8001_none_SQL_INJECTION"
    Example (UNMAPPED):
        "UNMAPPED:foreign-host.net:9999_foreign-host.net_/path_9999_none_SQL_INJECTION"
    """
    asset_key = _asset_boundary_key(finding)
    host = finding.host.lower().strip()
    endpoint = finding.endpoint.lower().strip() if finding.endpoint else "/"
    port = str(finding.port) if finding.port else "0"
    parameter = finding.parameter.lower().strip() if finding.parameter else "none"
    vuln_type = finding.vulnerability_type.upper().strip()

    key = f"{asset_key}_{host}_{endpoint}_{port}_{parameter}_{vuln_type}"
    return hashlib.md5(key.encode()).hexdigest()[:16]


def generate_cve_fingerprint(finding: NormalizedFinding) -> Optional[str]:
    """
    Alternative fingerprint using CVE + asset_boundary + port.

    STRONGER match signal when CVE is available — but ONLY within the same asset.
    asset_boundary is the outermost component to enforce the cross-asset hard wall.

    Two findings with the same CVE on DIFFERENT assets will have DIFFERENT
    CVE fingerprints and cannot be grouped as duplicates.
    """
    if not finding.cve_id:
        return None

    asset_key = _asset_boundary_key(finding)
    port = str(finding.port) if finding.port else "0"
    cve = finding.cve_id.strip()

    key = f"{asset_key}_{port}_{cve}"
    return hashlib.md5(key.encode()).hexdigest()[:16]
