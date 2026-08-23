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


def generate_finding_id(scanner: str, host: str, vuln_name: str, endpoint: str = "", parameter: str = "") -> str:
    """
    Deterministic ID so the SAME underlying issue always hashes to the SAME id,
    even across separate pipeline runs. This is what makes Member 2's deduplication
    step possible later (two scanners flagging the same bug on the same endpoint
    should be recognizable as 'the same finding').
    """
    raw = f"{scanner}|{host}|{vuln_name}|{endpoint}|{parameter}".lower().strip()
    return "FIND-" + hashlib.sha1(raw.encode()).hexdigest()[:12]
