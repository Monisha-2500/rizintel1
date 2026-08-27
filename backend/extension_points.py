"""
extension_points.py
===================
Architectural Extension Points & Structural Schemas for RizIntel Real-Time Scanner Integration.

Provides non-breaking extension boundaries and abstract interfaces for future:
  - Multi-tenant Organization & Workspace isolation
  - Asset Registry management
  - Remote Scanner Connector / Agent orchestration
  - Explicit Scan Run lifecycle execution
  - Real-time Raw Finding ingestion into M1 input boundary
  - Pipeline Stage Event streaming (SSE / WebSocket)

NOTE: M1->M8 engine behavior remains strictly frozen and reusable via M1 input adapter.
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


# ── Enums ────────────────────────────────────────────────────────────────────

class MemberRole(str, Enum):
    VIEWER = "VIEWER"
    ANALYST = "ANALYST"
    SECURITY_LEAD = "SECURITY_LEAD"
    ADMIN = "ADMIN"


class ScanRunStatus(str, Enum):
    QUEUED = "QUEUED"
    PROVISIONING = "PROVISIONING"
    RUNNING = "RUNNING"
    NORMALIZING = "NORMALIZING"
    ANALYZING = "ANALYZING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class ScannerAgentStatus(str, Enum):
    ONLINE = "ONLINE"
    OFFLINE = "OFFLINE"
    BUSY = "BUSY"
    DEGRADED = "DEGRADED"


# ── Operational Entities Schemas ──────────────────────────────────────────────

class Organization(BaseModel):
    """Multi-tenant Organization root boundary."""
    organization_id: str = Field(..., description="Unique organization identifier, e.g. org_acme_sec")
    display_name: str = Field(..., description="Human-readable organization name")
    created_at: str = Field(..., description="ISO 8601 creation timestamp")
    is_active: bool = True
    metadata: Dict[str, Any] = Field(default_factory=dict)


class OrganizationMembership(BaseModel):
    """Workspace membership tying user account to organization and role."""
    membership_id: str
    organization_id: str
    user_id: str
    user_email: str
    role: MemberRole
    granted_at: str


class RegisteredAsset(BaseModel):
    """Central Asset Registry model representing an authorized scanning target."""
    asset_id: str = Field(..., description="Canonical asset identifier, e.g. AST-PROD-API-01")
    organization_id: str = Field(..., description="Owning organization ID")
    display_name: str
    environment: str = Field("production", description="production, staging, development")
    criticality: str = Field("HIGH", description="CRITICAL, HIGH, MEDIUM, LOW")
    internet_facing: Optional[bool] = None  # None = UNMAPPED / Unknown
    data_sensitivity: str = "CONFIDENTIAL"
    host_hints: List[str] = Field(default_factory=list, description="IPs, FQDNs, URLs")
    mac_address: Optional[str] = None
    tags: Dict[str, str] = Field(default_factory=dict)
    created_at: str
    updated_at: str


class ScannerConnection(BaseModel):
    """Configuration for an authorized scanner integration or connector."""
    connection_id: str
    organization_id: str
    scanner_name: str = Field(..., description="ZAP, NUCLEI, TRIVY, DEPENDABOT, BURP, QUALYS, etc.")
    connector_type: str = Field("AGENT_PULL", description="AGENT_PULL, WEBHOOK_PUSH, DIRECT_API")
    is_enabled: bool = True
    config_parameters: Dict[str, Any] = Field(default_factory=dict)
    last_synced_at: Optional[str] = None


class ScannerAgent(BaseModel):
    """On-premise / VPC Scanner Agent heartbeat and status registration."""
    agent_id: str
    organization_id: str
    agent_name: str
    network_zone: str = Field(..., description="e.g. internal_vpc_us_east_1, lab_subnet_2")
    supported_scanners: List[str]
    status: ScannerAgentStatus = ScannerAgentStatus.ONLINE
    last_heartbeat_at: str
    version: str


class ScanRun(BaseModel):
    """
    Explicit Scan Run lifecycle record connecting tenant, target asset, agent,
    scanner selections, execution counters, and data origin.
    """
    scan_run_id: str = Field(..., description="Unique scan execution ID, e.g. RUN-20260824-001")
    organization_id: str
    asset_id: str
    created_by: str = Field(..., description="User ID or Agent ID that initiated scan")
    scanner_selections: List[str] = Field(..., description="List of scanners selected for this run")
    status: ScanRunStatus = ScanRunStatus.QUEUED
    started_at: str
    completed_at: Optional[str] = None
    
    # Progress & Finding Counts
    raw_count: int = 0
    normalized_count: int = 0
    canonical_count: int = 0
    confirmed_count: int = 0
    pending_review_count: int = 0
    suppressed_count: int = 0
    
    data_origin: str = Field("LIVE_SCAN", description="LIVE_SCAN, MOCK_SCAN, FALLBACK")
    error_message: Optional[str] = None


class RawScannerFinding(BaseModel):
    """
    Raw, un-normalized finding event submitted by a Scanner Agent or Webhook
    before passing into the M1 normalization engine.
    """
    raw_finding_id: str
    scan_run_id: str
    organization_id: str
    scanner_source_id: str = Field(..., description="Deterministic scanner identifier, e.g. ZAP, NUCLEI")
    raw_payload: Dict[str, Any]
    ingested_at: str


class ScanStageEvent(BaseModel):
    """
    Pipeline stage transition event for real-time progress streaming (SSE / WebSockets).
    """
    event_id: str
    scan_run_id: str
    organization_id: str
    stage: str = Field(..., description="M1_NORMALIZATION, M2_DEDUPLICATION, M3_NOISE_ROUTING, M4_MATCH, M5_RISK, M6_EXPLANATION, M7_PROVENANCE")
    status: str = Field(..., description="STARTED, PROGRESS, COMPLETED, FAILED")
    progress_percentage: float = Field(0.0, ge=0.0, le=100.0)
    stage_summary: Dict[str, Any] = Field(default_factory=dict)
    timestamp: str


# ── M1 Ingestion Boundary Extension Interface ─────────────────────────────────

class M1IngestionBoundaryInterface:
    """
    Abstract extension interface for passing raw scanner payloads from a ScanRun
    into the frozen M1 normalization engine.
    """
    def ingest_raw_scanner_events(
        self,
        scan_run: ScanRun,
        raw_events: List[RawScannerFinding]
    ) -> List[Dict[str, Any]]:
        """
        Converts raw scanner findings into standardized M1 Section 3 normalized finding objects
        suitable for UnifiedPipelineRunner.run_m2() through run_m7().
        """
        raise NotImplementedError("M1 Ingestion Boundary must be implemented by active scanner connector.")
