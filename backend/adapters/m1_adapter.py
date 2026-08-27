"""
m1_adapter.py
=============
M1NormalizedFindingAdapter: Bridges Member 1 raw scanner normalization
to Schema v1.0 Section 3 (NormalizedFinding) consumed by Member 2.

Rules:
- Maps `cve` -> `cve_id`.
- Uppercases `severity` ("High" -> "HIGH").
- Populates `schema_version = "1.0"`.
- Extracts or derives host, url, endpoint, port, asset_id, and vulnerability_type.
- Does NOT fabricate any security evidence.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse


def _derive_vulnerability_type(vuln_name: str, cwe: Optional[str] = None) -> str:
    """Map CWE or vulnerability title to standardized uppercase vulnerability type."""
    name_upper = (vuln_name or "").upper()
    cwe_upper = (cwe or "").upper()

    if "CWE-89" in cwe_upper or "SQL" in name_upper:
        return "SQL_INJECTION"
    if "CWE-79" in cwe_upper or "XSS" in name_upper or "CROSS SITE SCRIPTING" in name_upper:
        return "CROSS_SITE_SCRIPTING"
    if "CWE-78" in cwe_upper or "CWE-94" in cwe_upper or "RCE" in name_upper or "COMMAND INJECTION" in name_upper or "REMOTE CODE" in name_upper:
        return "REMOTE_CODE_EXECUTION"
    if "CWE-918" in cwe_upper or "SSRF" in name_upper:
        return "SSRF"
    if "CWE-22" in cwe_upper or "PATH TRAVERSAL" in name_upper or "DIRECTORY TRAVERSAL" in name_upper:
        return "PATH_TRAVERSAL"
    if "CWE-287" in cwe_upper or "CWE-306" in cwe_upper or "AUTHENTICATION" in name_upper or "AUTH BYPASS" in name_upper:
        return "AUTHENTICATION_BYPASS"
    if "CWE-200" in cwe_upper or "DISCLOSURE" in name_upper or "INFORMATION" in name_upper:
        return "INFORMATION_DISCLOSURE"
    if "CWE-1004" in cwe_upper or "CWE-16" in cwe_upper or "HEADER" in name_upper or "COOKIE" in name_upper or "CSP" in name_upper:
        return "SECURITY_HEADER"
    if "CWE-502" in cwe_upper or "DESERIALIZATION" in name_upper:
        return "DESERIALIZATION"
    if "CWE-284" in cwe_upper or "ACCESS CONTROL" in name_upper or "IDOR" in name_upper:
        return "ACCESS_CONTROL"
    if "CWE-1104" in cwe_upper or "COMPONENT" in name_upper or "OUTDATED" in name_upper or "DEPENDENCY" in name_upper:
        return "VULNERABLE_COMPONENT"

    return "OTHER"


def _normalize_severity(severity_val: Any) -> str:
    """Normalize severity strings/enums into contract standard UPPERCASE."""
    if not severity_val:
        return "INFO"
    s = str(severity_val).upper().strip()
    if "SEVERITY." in s:
        s = s.split("SEVERITY.")[-1]
    if s in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}:
        return s
    # Map common aliases
    if s == "WARN" or s == "WARNING":
        return "MEDIUM"
    if s == "ERROR":
        return "HIGH"
    return "INFO"


def _parse_host_and_port(raw_host: str, endpoint: Optional[str] = None) -> tuple[str, str, str, int]:
    """
    Given a host string (e.g. 'http://localhost:3000' or 'example.com'),
    returns (clean_host, url, clean_endpoint, port).
    """
    clean_endpoint = (endpoint or "").strip()
    if not clean_endpoint.startswith("/") and clean_endpoint:
        clean_endpoint = "/" + clean_endpoint
    elif not clean_endpoint:
        clean_endpoint = "/"

    if "://" in raw_host:
        parsed = urlparse(raw_host)
        clean_host = parsed.hostname or "localhost"
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        url = f"{parsed.scheme}://{parsed.netloc}{clean_endpoint}"
    else:
        # Check for host:port
        if ":" in raw_host:
            parts = raw_host.split(":")
            clean_host = parts[0]
            try:
                port = int(parts[1])
            except ValueError:
                port = 80
            url = f"http://{clean_host}:{port}{clean_endpoint}"
        else:
            clean_host = raw_host or "localhost"
            port = 80
            url = f"http://{clean_host}{clean_endpoint}"

    return clean_host, url, clean_endpoint, port


class M1NormalizedFindingAdapter:
    """
    Converts raw M1 findings or dictionaries into Schema v1.0 Section 3 NormalizedFinding.
    """

    @staticmethod
    def adapt_single(
        raw_item: Any,
        default_asset_id: Optional[str] = None,
        asset_resolver: Optional[Any] = None
    ) -> Dict[str, Any]:
        """Convert a single M1 StandardFinding or dictionary into Section 3 shape."""
        # Extract dictionary if pydantic model
        if hasattr(raw_item, "model_dump"):
            data = raw_item.model_dump()
        elif hasattr(raw_item, "dict"):
            data = raw_item.dict()
        elif isinstance(raw_item, dict):
            data = dict(raw_item)
        else:
            raise ValueError(f"Unsupported finding input type: {type(raw_item)}")

        finding_id = str(data.get("finding_id") or "FIND-00000000")
        scanner = str(data.get("scanner") or "GENERIC_SCANNER").upper()
        
        # CVE normalization
        cve_id = data.get("cve_id") or data.get("cve") or None
        if cve_id:
            cve_id = str(cve_id).strip().upper()
            if not cve_id.startswith("CVE-"):
                cve_id = f"CVE-{cve_id}"

        vuln_name = str(data.get("vulnerability_name") or "Unknown Vulnerability")
        cwe = data.get("cwe")
        vuln_type = data.get("vulnerability_type") or _derive_vulnerability_type(vuln_name, cwe)
        severity = _normalize_severity(data.get("severity"))

        raw_host = str(data.get("host") or "localhost")
        raw_endpoint = data.get("endpoint")
        clean_host, full_url, clean_endpoint, port = _parse_host_and_port(raw_host, raw_endpoint)

        # Asset ID resolution
        raw_aid = data.get("asset_id")
        if raw_aid and str(raw_aid).upper() != "UNMAPPED":
            asset_id = str(raw_aid)
        elif asset_resolver:
            resolved_aid, _ = asset_resolver.resolve({
                "host": clean_host,
                "port": port,
                "url": data.get("url") or full_url
            })
            asset_id = resolved_aid
        elif default_asset_id:
            asset_id = default_asset_id
        else:
            asset_id = "UNMAPPED"

        # Timestamp normalization
        raw_ts = data.get("timestamp")
        if isinstance(raw_ts, datetime):
            ts_str = raw_ts.isoformat().replace("+00:00", "Z")
        elif isinstance(raw_ts, str) and raw_ts.strip():
            ts_str = raw_ts.strip()
        else:
            ts_str = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

        return {
            "schema_version": "1.0",
            "finding_id": finding_id,
            "scanner": scanner,
            "cve_id": cve_id,
            "vulnerability_name": vuln_name,
            "vulnerability_type": vuln_type,
            "severity": severity,
            "asset_id": asset_id,
            "host": clean_host,
            "url": data.get("url") or full_url,
            "endpoint": clean_endpoint,
            "port": data.get("port") or port,
            "parameter": data.get("parameter"),
            "description": str(data.get("description") or ""),
            "evidence": data.get("evidence"),
            "timestamp": ts_str,
        }

    @classmethod
    def adapt_batch(
        cls,
        raw_items: List[Any],
        default_asset_id: Optional[str] = None,
        asset_resolver: Optional[Any] = None
    ) -> List[Dict[str, Any]]:
        """Convert a list of raw M1 findings into Section 3 list."""
        return [cls.adapt_single(item, default_asset_id=default_asset_id, asset_resolver=asset_resolver) for item in raw_items]
