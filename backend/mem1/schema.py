"""
schema.py
---------
The single 'universal' shape every scanner output gets converted into.

Why pydantic:
- Free validation (wrong types / missing required fields fail loudly at parse time,
  not silently later in the pipeline)
- Free .dict() / .json() serialization for handing off to Member 2/3 (dedup + enrichment)
- Easy to demo: "here's the schema, here's it validating bad data"
"""

from pydantic import BaseModel, Field, field_validator
from typing import Optional
from datetime import datetime
from enum import Enum
import hashlib


class Severity(str, Enum):
    """Normalized severity levels. Every scanner's own scale gets mapped into this."""
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"


class StandardFinding(BaseModel):
    finding_id: str = Field(..., description="Deterministic unique ID (see generate_finding_id)")
    scanner: str = Field(..., description="Origin scanner, e.g. 'ZAP', 'Nuclei', 'OpenVAS'")
    cve: Optional[str] = Field(None, description="CVE identifier if known, e.g. 'CVE-2023-1234'")
    cwe: Optional[str] = Field(None, description="CWE identifier if known, e.g. 'CWE-89'. DAST tools populate this far more reliably than CVE.")
    vulnerability_name: str
    severity: Severity
    host: str = Field(..., description="URL or IP the finding applies to")
    endpoint: Optional[str] = Field(None, description="Path/route, e.g. '/login'")
    parameter: Optional[str] = Field(None, description="Vulnerable parameter, e.g. 'username'")
    description: str = ""
    evidence: Optional[str] = None
    timestamp: datetime

    # Raw scanner-native severity, kept for traceability/debugging even after normalization
    raw_severity: Optional[str] = None

    # Escape hatch: tool-specific fields that don't fit the universal schema
    # (e.g. Trivy's 'fixed_version'/'package_name', Nmap's 'port_state') live here
    # instead of forcing a schema change every time a new scanner category appears.
    # Core consumers (dedup, scoring) never need to read this — it's for
    # traceability/debugging and future-proofing only.
    extra_fields: dict = Field(default_factory=dict)

    @field_validator("cve")
    @classmethod
    def validate_cve_format(cls, v):
        if v and not v.upper().startswith("CVE-"):
            raise ValueError(f"Malformed CVE id: {v}")
        return v.upper() if v else v

    @field_validator("cwe")
    @classmethod
    def normalize_cwe_format(cls, v):
        if not v:
            return v
        v = str(v).strip().upper()
        if v.isdigit():
            return f"CWE-{v}"
        return v


def _normalize_host(host: str) -> str:
    """
    Canonicalize a host/URL for stable hashing.
    Strips scheme, lowercases, removes trailing slashes.
    e.g. 'http://127.0.0.1:8001/WebGoat/login' -> '127.0.0.1:8001/webgoat/login'
    """
    from urllib.parse import urlparse
    host = (host or "").strip()
    if "://" in host:
        parsed = urlparse(host)
        netloc = parsed.netloc.lower()
        path = parsed.path.rstrip("/") or "/"
        return f"{netloc}{path}"
    return host.lower().rstrip("/")


def _normalize_endpoint(endpoint: str) -> str:
    """Lowercase and strip endpoint path, ensuring leading slash, no trailing slash."""
    ep = (endpoint or "").strip().lower()
    if not ep.startswith("/"):
        ep = "/" + ep if ep else "/"
    return ep.rstrip("/") or "/"


def generate_source_id(
    scanner: str,
    host: str,
    vuln_name: str,
    endpoint: str = "",
    port: str = "",
    discriminator: str = "",
) -> str:
    """
    Deterministic, unique, reproducible source finding ID.

    Canonical key (all lowercased, in fixed order):
      SCANNER | normalized_host | port | normalized_endpoint | vuln_name | discriminator

    ``discriminator`` is a scanner-specific sub-identifier that distinguishes
    multiple firings of the same template/alert on the same URL:
      - Nuclei:  ``matcher-name`` (e.g. 'content-security-policy', 'bootstrap')
      - ZAP:     ZAP instance ``id`` field when all other fields are identical
      - Wapiti:  ``parameter`` or empty

    Returns "SCANNER-<sha1[:12]>" (human-readable, scanner-namespaced).
    """
    scanner_ns = (scanner or "GENERIC").upper()
    norm_host = _normalize_host(host)
    norm_ep = _normalize_endpoint(endpoint)
    port_s = str(port).strip() if port else ""
    vuln_s = (vuln_name or "").strip().lower()
    disc_s = (discriminator or "").strip().lower()

    canonical = f"{scanner_ns}|{norm_host}|{port_s}|{norm_ep}|{vuln_s}|{disc_s}"
    digest = hashlib.sha1(canonical.encode("utf-8")).hexdigest()[:12]
    return f"{scanner_ns}-{digest}"


def generate_finding_id(scanner: str, host: str, vuln_name: str, endpoint: str = "", parameter: str = "") -> str:
    """
    Backward-compatible wrapper kept for any callers that still use the old signature.
    New code should call generate_source_id() directly.
    """
    return generate_source_id(scanner, host, vuln_name, endpoint, port="", discriminator=parameter)
