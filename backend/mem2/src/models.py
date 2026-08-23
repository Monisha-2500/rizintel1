"""
Data Models for Member 2 - Deduplication Engine
Based on PS4_Standardized_Module_Interface_Contract_v1.docx
"""
from pydantic import BaseModel
from typing import Optional, List, Dict


class NormalizedFinding(BaseModel):
    """
    INPUT from Member 1
    Section 3 of the Interface Contract
    
    This represents a single scanner finding normalized into a common format.
    """
    schema_version: str = "1.0"
    finding_id: str
    scanner: str
    cve_id: Optional[str] = None
    vulnerability_name: str
    vulnerability_type: str
    severity: str
    asset_id: str
    host: str
    url: str
    endpoint: str
    port: int
    parameter: Optional[str] = None
    description: str
    evidence: Optional[str] = None
    timestamp: str


class DeduplicatedFinding(BaseModel):
    """
    OUTPUT to Member 3
    Section 4 of the Interface Contract
    """
    schema_version: str = "1.0"
    finding_id: str
    member_source: str = "M2"
    cve_id: Optional[str] = None
    vulnerability_name: str
    vulnerability_type: str
    severity: str
    asset: Dict
    deduplication: Dict
    scanner_consensus: Dict
    source_findings: List[Dict]
    first_seen: str
    last_seen: str


class DeduplicationMetrics(BaseModel):
    """
    Metrics for Member 8 Dashboard
    """
    total_raw_findings: int
    unique_findings: int
    duplicates_removed: int
    duplicate_reduction_rate: float
    scanner_breakdown: Dict[str, int]
