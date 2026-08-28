"""
database.py — SQLite Persistent Store for RizIntel
  - Tamper-Evident Analyst Audit Trail (SHA-256 chained)
  - Operational Pipeline Execution Log
  - Phase 1: Organizations, Memberships, Registered Assets, Scan Runs

Schema:
  audit_trail(
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    finding_id     TEXT NOT NULL,
    m5_risk_score  INTEGER NOT NULL,   -- original machine assessment (never mutated)
    analyst_action TEXT NOT NULL,      -- e.g. ACCEPT_PRIORITY, ESCALATE, DOWNGRADE, etc.
    rationale      TEXT DEFAULT '',
    role           TEXT NOT NULL DEFAULT 'security_analyst',
    timestamp      TEXT NOT NULL,       -- ISO-8601
    previous_hash  TEXT NOT NULL,       -- SHA-256 of previous event or "GENESIS"
    event_hash     TEXT NOT NULL UNIQUE -- SHA-256 of this event payload
  )

Tamper-evidence:
  event_hash = SHA-256( finding_id | m5_risk_score | analyst_action |
                        rationale | role | timestamp | previous_hash )
  Any modification breaks the cryptographic chain.
"""

import sqlite3
import hashlib
import json
import logging
import os
import re
from datetime import datetime, timezone
from threading import Lock
from typing import List, Dict, Optional, Any

logger = logging.getLogger("rizintel.database")

DB_PATH = os.getenv("RIZINTEL_DB_PATH", os.path.join(os.path.dirname(__file__), "data", "audit_trail.db"))

# Ensure data directory exists
os.makedirs(os.path.dirname(os.path.abspath(DB_PATH)), exist_ok=True)

_lock = Lock()


def _get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Create audit tables if they do not already exist, and migrate columns if needed."""
    with _lock:
        conn = _get_conn()
        try:
            # Enable foreign key enforcement
            conn.execute("PRAGMA foreign_keys = ON")

            # 1. Analyst finding decision audit trail (SHA-256 chained)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS audit_trail (
                    id                    INTEGER PRIMARY KEY AUTOINCREMENT,
                    finding_id            TEXT    NOT NULL,
                    m5_risk_score         INTEGER NOT NULL,
                    analyst_action        TEXT    NOT NULL,
                    rationale             TEXT    DEFAULT '',
                    role                  TEXT    NOT NULL DEFAULT 'security_analyst',
                    timestamp             TEXT    NOT NULL,
                    data_source           TEXT    NOT NULL DEFAULT 'LIVE',
                    finding_snapshot_hash TEXT    NOT NULL DEFAULT '',
                    previous_hash         TEXT    NOT NULL,
                    event_hash            TEXT    NOT NULL UNIQUE
                )
            """)
            cursor = conn.execute("PRAGMA table_info(audit_trail)")
            cols = {row["name"] for row in cursor.fetchall()}
            if "data_source" not in cols:
                conn.execute("ALTER TABLE audit_trail ADD COLUMN data_source TEXT NOT NULL DEFAULT 'LIVE'")
            if "finding_snapshot_hash" not in cols:
                conn.execute("ALTER TABLE audit_trail ADD COLUMN finding_snapshot_hash TEXT NOT NULL DEFAULT ''")

            # 2. Operational pipeline execution audit ledger
            conn.execute("""
                CREATE TABLE IF NOT EXISTS pipeline_execution_log (
                    id                      INTEGER PRIMARY KEY AUTOINCREMENT,
                    pipeline_run_id         TEXT    NOT NULL UNIQUE,
                    request_id              TEXT    NOT NULL,
                    triggered_by_user_id    TEXT    NOT NULL,
                    triggered_by_email      TEXT    NOT NULL,
                    triggered_by_role       TEXT    NOT NULL,
                    data_origin             TEXT    NOT NULL DEFAULT 'LIVE_SCAN',
                    raw_finding_count       INTEGER NOT NULL DEFAULT 0,
                    canonical_finding_count INTEGER NOT NULL DEFAULT 0,
                    status                  TEXT    NOT NULL DEFAULT 'SUCCESS',
                    timestamp               TEXT    NOT NULL,
                    error_message           TEXT    DEFAULT ''
                )
            """)

            # 3. Phase 1: Multi-tenant Organizations
            conn.execute("""
                CREATE TABLE IF NOT EXISTS organizations (
                    organization_id  TEXT    PRIMARY KEY,
                    display_name     TEXT    NOT NULL,
                    created_at       TEXT    NOT NULL,
                    is_active        INTEGER NOT NULL DEFAULT 1
                )
            """)

            # 4. Phase 1: Organization Memberships
            conn.execute("""
                CREATE TABLE IF NOT EXISTS organization_memberships (
                    membership_id    TEXT    PRIMARY KEY,
                    organization_id  TEXT    NOT NULL REFERENCES organizations(organization_id) ON DELETE CASCADE,
                    user_id          TEXT    NOT NULL,
                    role             TEXT    NOT NULL DEFAULT 'VIEWER',
                    created_at       TEXT    NOT NULL,
                    is_active        INTEGER NOT NULL DEFAULT 1,
                    UNIQUE(organization_id, user_id)
                )
            """)

            # 4b. Phase 1 / M7: Organization-Scoped Verified Teams
            conn.execute("""
                CREATE TABLE IF NOT EXISTS organization_teams (
                    organization_id  TEXT    NOT NULL REFERENCES organizations(organization_id) ON DELETE CASCADE,
                    team_id          TEXT    NOT NULL,
                    display_name     TEXT    NOT NULL,
                    is_active        INTEGER NOT NULL DEFAULT 1,
                    created_at       TEXT    NOT NULL,
                    PRIMARY KEY(organization_id, team_id)
                )
            """)

            # Seed default teams for demo org
            conn.execute("""
                INSERT OR IGNORE INTO organizations (organization_id, display_name, created_at, is_active)
                VALUES ('ORG-RIZZOLVE-DEMO', 'Rizzolve Demo Organization', '2026-08-20T00:00:00Z', 1)
            """)
            conn.execute("""
                INSERT OR IGNORE INTO organization_teams (organization_id, team_id, display_name, is_active, created_at)
                VALUES 
                  ('ORG-RIZZOLVE-DEMO', 'secops', 'SOC Operations Team', 1, '2026-08-20T00:00:00Z'),
                  ('ORG-RIZZOLVE-DEMO', 'appsec-team', 'Application Security Team', 1, '2026-08-20T00:00:00Z'),
                  ('ORG-RIZZOLVE-DEMO', 'payments-infra', 'Payments Infrastructure Team', 1, '2026-08-20T00:00:00Z'),
                  ('ORG-RIZZOLVE-DEMO', 'dev-lead', 'Development Lead', 1, '2026-08-20T00:00:00Z'),
                  ('ORG-RIZZOLVE-DEMO', 'cloud-eng', 'Cloud Engineering Team', 1, '2026-08-20T00:00:00Z')
            """)

            # 5. Phase 1: Registered Assets
            # Uniqueness policy: (organization_id, normalized_host, port) must be unique for ACTIVE assets.
            # The same host:port is allowed in different organizations (no cross-org leakage).
            conn.execute("""
                CREATE TABLE IF NOT EXISTS registered_assets (
                    asset_id              TEXT    PRIMARY KEY,
                    organization_id       TEXT    NOT NULL REFERENCES organizations(organization_id) ON DELETE CASCADE,
                    display_name          TEXT    NOT NULL,
                    host                  TEXT    NOT NULL,
                    normalized_host       TEXT    NOT NULL,
                    port                  INTEGER,
                    environment           TEXT    NOT NULL DEFAULT 'production',
                    criticality           TEXT    NOT NULL DEFAULT 'HIGH',
                    internet_facing       INTEGER,
                    data_sensitivity      TEXT    NOT NULL DEFAULT 'CONFIDENTIAL',
                    authorization_status  TEXT    NOT NULL DEFAULT 'PENDING',
                    created_by            TEXT    NOT NULL,
                    created_at            TEXT    NOT NULL,
                    updated_at            TEXT    NOT NULL
                )
            """)
            cursor = conn.execute("PRAGMA table_info(registered_assets)")
            asset_cols = {row["name"] for row in cursor.fetchall()}
            if asset_cols and "normalized_host" not in asset_cols:
                # If an old registered_assets table existed without Phase 1 columns, recreate it safely
                conn.execute("DROP TABLE IF EXISTS registered_assets")
                conn.execute("""
                    CREATE TABLE registered_assets (
                        asset_id              TEXT    PRIMARY KEY,
                        organization_id       TEXT    NOT NULL REFERENCES organizations(organization_id) ON DELETE CASCADE,
                        display_name          TEXT    NOT NULL,
                        host                  TEXT    NOT NULL,
                        normalized_host       TEXT    NOT NULL,
                        port                  INTEGER,
                        environment           TEXT    NOT NULL DEFAULT 'production',
                        criticality           TEXT    NOT NULL DEFAULT 'HIGH',
                        internet_facing       INTEGER,
                        data_sensitivity      TEXT    NOT NULL DEFAULT 'CONFIDENTIAL',
                        authorization_status  TEXT    NOT NULL DEFAULT 'PENDING',
                        created_by            TEXT    NOT NULL,
                        created_at            TEXT    NOT NULL,
                        updated_at            TEXT    NOT NULL
                    )
                """)

            # Enforce host uniqueness within an org for non-DISABLED assets via a unique partial index
            conn.execute("""
                CREATE UNIQUE INDEX IF NOT EXISTS uidx_asset_host_port_org
                ON registered_assets(organization_id, normalized_host, COALESCE(port, -1))
                WHERE authorization_status != 'DISABLED'
            """)

            # 6. Phase 1 & 2: Scan Runs
            conn.execute("""
                CREATE TABLE IF NOT EXISTS scan_runs (
                    scan_run_id          TEXT    PRIMARY KEY,
                    organization_id      TEXT    NOT NULL REFERENCES organizations(organization_id) ON DELETE CASCADE,
                    asset_id             TEXT    NOT NULL REFERENCES registered_assets(asset_id),
                    created_by_user_id   TEXT    NOT NULL,
                    status               TEXT    NOT NULL DEFAULT 'CREATED',
                    scanner_selections   TEXT    NOT NULL DEFAULT '[]',
                    data_origin          TEXT    NOT NULL DEFAULT 'LIVE_SCAN',
                    created_at           TEXT    NOT NULL,
                    started_at           TEXT,
                    completed_at         TEXT,
                    updated_at           TEXT    NOT NULL,
                    raw_count            INTEGER NOT NULL DEFAULT 0,
                    normalized_count     INTEGER NOT NULL DEFAULT 0,
                    canonical_count      INTEGER NOT NULL DEFAULT 0,
                    confirmed_count      INTEGER NOT NULL DEFAULT 0,
                    pending_review_count INTEGER NOT NULL DEFAULT 0,
                    suppressed_count     INTEGER NOT NULL DEFAULT 0,
                    error_message        TEXT    DEFAULT '',
                    received_scanners    TEXT    NOT NULL DEFAULT '[]',
                    pending_scanners     TEXT    NOT NULL DEFAULT '[]',
                    failed_scanners      TEXT    NOT NULL DEFAULT '[]',
                    last_ingested_at     TEXT,
                    processing_started_at TEXT
                )
            """)
            cursor = conn.execute("PRAGMA table_info(scan_runs)")
            sr_cols = {row["name"] for row in cursor.fetchall()}
            if "received_scanners" not in sr_cols:
                conn.execute("ALTER TABLE scan_runs ADD COLUMN received_scanners TEXT NOT NULL DEFAULT '[]'")
            if "pending_scanners" not in sr_cols:
                conn.execute("ALTER TABLE scan_runs ADD COLUMN pending_scanners TEXT NOT NULL DEFAULT '[]'")
            if "failed_scanners" not in sr_cols:
                conn.execute("ALTER TABLE scan_runs ADD COLUMN failed_scanners TEXT NOT NULL DEFAULT '[]'")
            if "last_ingested_at" not in sr_cols:
                conn.execute("ALTER TABLE scan_runs ADD COLUMN last_ingested_at TEXT")
            if "processing_started_at" not in sr_cols:
                conn.execute("ALTER TABLE scan_runs ADD COLUMN processing_started_at TEXT")

            # 7. Phase 2: Raw Scanner Submissions
            conn.execute("""
                CREATE TABLE IF NOT EXISTS scanner_submissions (
                    submission_id        TEXT    PRIMARY KEY,
                    scan_run_id          TEXT    NOT NULL REFERENCES scan_runs(scan_run_id) ON DELETE CASCADE,
                    organization_id      TEXT    NOT NULL REFERENCES organizations(organization_id) ON DELETE CASCADE,
                    asset_id             TEXT    NOT NULL REFERENCES registered_assets(asset_id),
                    scanner              TEXT    NOT NULL,
                    submission_type      TEXT    NOT NULL DEFAULT 'FILE_UPLOAD',
                    received_by_user_id  TEXT    NOT NULL,
                    received_at          TEXT    NOT NULL,
                    original_filename    TEXT,
                    content_type         TEXT,
                    file_size_bytes      INTEGER NOT NULL DEFAULT 0,
                    storage_path         TEXT    NOT NULL,
                    raw_finding_count    INTEGER NOT NULL DEFAULT 0,
                    processing_status    TEXT    NOT NULL DEFAULT 'RECEIVED',
                    error_code           TEXT    DEFAULT '',
                    error_message        TEXT    DEFAULT '',
                    payload_hash         TEXT    NOT NULL,
                    idempotency_key      TEXT    DEFAULT ''
                )
            """)

            # 8. Phase 2: Real Stage Event Ledger
            conn.execute("""
                CREATE TABLE IF NOT EXISTS scan_run_events (
                    event_id             TEXT    PRIMARY KEY,
                    organization_id      TEXT    NOT NULL REFERENCES organizations(organization_id) ON DELETE CASCADE,
                    scan_run_id          TEXT    NOT NULL REFERENCES scan_runs(scan_run_id) ON DELETE CASCADE,
                    event_type           TEXT    NOT NULL,
                    stage                TEXT    NOT NULL,
                    status               TEXT    NOT NULL DEFAULT 'INFO',
                    message              TEXT    NOT NULL,
                    metadata_json        TEXT    DEFAULT '{}',
                    created_at           TEXT    NOT NULL
                )
            """)

            # 9. Phase 2: Scan Run Results (Pipeline Outputs Scoped to Scan Run)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS scan_run_results (
                    result_id            TEXT    PRIMARY KEY,
                    organization_id      TEXT    NOT NULL REFERENCES organizations(organization_id) ON DELETE CASCADE,
                    scan_run_id          TEXT    NOT NULL UNIQUE REFERENCES scan_runs(scan_run_id) ON DELETE CASCADE,
                    asset_id             TEXT    NOT NULL REFERENCES registered_assets(asset_id),
                    raw_finding_count    INTEGER NOT NULL DEFAULT 0,
                    canonical_finding_count INTEGER NOT NULL DEFAULT 0,
                    findings_json        TEXT    NOT NULL,
                    summary_json         TEXT    NOT NULL,
                    completed_at         TEXT    NOT NULL
                )
            """)

            # 10. Phase 3: Short-lived SSE stream tokens (never the long-lived JWT)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS sse_stream_tokens (
                    token_hash           TEXT    PRIMARY KEY,
                    user_id              TEXT    NOT NULL,
                    organization_id      TEXT    NOT NULL,
                    scan_run_id          TEXT    NOT NULL,
                    expires_at           TEXT    NOT NULL,
                    created_at           TEXT    NOT NULL,
                    used_at              TEXT    DEFAULT NULL
                )
            """)

            cols = [r["name"] for r in conn.execute("PRAGMA table_info(sse_stream_tokens);").fetchall()]
            if "used_at" not in cols:
                conn.execute("ALTER TABLE sse_stream_tokens ADD COLUMN used_at TEXT DEFAULT NULL;")

            # 11. Phase 4: Persistent Scanner Agents & Machine Authentication
            conn.execute("""
                CREATE TABLE IF NOT EXISTS scanner_agents (
                    agent_id             TEXT    PRIMARY KEY,
                    organization_id      TEXT    NOT NULL REFERENCES organizations(organization_id) ON DELETE CASCADE,
                    display_name         TEXT    NOT NULL,
                    token_hash           TEXT    NOT NULL UNIQUE,
                    status               TEXT    NOT NULL DEFAULT 'ACTIVE',
                    capabilities_json    TEXT    NOT NULL DEFAULT '{}',
                    created_at           TEXT    NOT NULL,
                    last_seen_at         TEXT    DEFAULT NULL,
                    revoked_at           TEXT    DEFAULT NULL,
                    created_by_user_id   TEXT    NOT NULL
                )
            """)

            # 12. Phase 4: Persistent Scanner Jobs Queue & Execution Lifecycle
            conn.execute("""
                CREATE TABLE IF NOT EXISTS scanner_jobs (
                    scanner_job_id       TEXT    PRIMARY KEY,
                    organization_id      TEXT    NOT NULL REFERENCES organizations(organization_id) ON DELETE CASCADE,
                    scan_run_id          TEXT    NOT NULL REFERENCES scan_runs(scan_run_id) ON DELETE CASCADE,
                    asset_id             TEXT    NOT NULL REFERENCES registered_assets(asset_id),
                    scanner              TEXT    NOT NULL,
                    agent_id             TEXT    REFERENCES scanner_agents(agent_id),
                    status               TEXT    NOT NULL DEFAULT 'QUEUED',
                    attempt              INTEGER NOT NULL DEFAULT 1,
                    max_attempts         INTEGER NOT NULL DEFAULT 3,
                    created_at           TEXT    NOT NULL,
                    claimed_at           TEXT    DEFAULT NULL,
                    started_at           TEXT    DEFAULT NULL,
                    completed_at         TEXT    DEFAULT NULL,
                    failed_at            TEXT    DEFAULT NULL,
                    error_code           TEXT    DEFAULT NULL,
                    error_message        TEXT    DEFAULT NULL
                )
            """)

            # 13. Phase 7: Persistent Remediation Tickets & Tasks
            conn.execute("""
                CREATE TABLE IF NOT EXISTS tickets (
                    ticket_id          TEXT PRIMARY KEY,
                    organization_id    TEXT NOT NULL REFERENCES organizations(organization_id) ON DELETE CASCADE,
                    finding_id         TEXT NOT NULL,
                    cve_id             TEXT,
                    asset_id           TEXT NOT NULL,
                    asset_name         TEXT,
                    vulnerability_name TEXT,
                    risk_score         INTEGER NOT NULL,
                    priority           TEXT NOT NULL,
                    sla_hours          INTEGER NOT NULL,
                    discovered_at      TEXT NOT NULL,
                    due_at             TEXT NOT NULL,
                    status             TEXT NOT NULL DEFAULT 'OPEN',
                    assigned_to        TEXT,
                    created_at         TEXT NOT NULL,
                    updated_at         TEXT NOT NULL,
                    resolved_at        TEXT,
                    external_refs      TEXT DEFAULT '{}',
                    checklist_json     TEXT DEFAULT '[]',
                    assignee_type      TEXT DEFAULT 'TEAM',
                    assignee_display_name TEXT DEFAULT '',
                    UNIQUE(organization_id, finding_id)
                )
            """)

            cursor = conn.execute("PRAGMA table_info(tickets)")
            tck_cols = {row["name"] for row in cursor.fetchall()}
            if tck_cols:
                if "checklist_json" not in tck_cols:
                    conn.execute("ALTER TABLE tickets ADD COLUMN checklist_json TEXT DEFAULT '[]'")
                if "assignee_type" not in tck_cols:
                    conn.execute("ALTER TABLE tickets ADD COLUMN assignee_type TEXT DEFAULT 'TEAM'")
                if "assignee_display_name" not in tck_cols:
                    conn.execute("ALTER TABLE tickets ADD COLUMN assignee_display_name TEXT DEFAULT ''")

            # 14. Phase 7: Remediation Ticket History Ledger
            conn.execute("""
                CREATE TABLE IF NOT EXISTS ticket_history (
                    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
                    ticket_id          TEXT NOT NULL REFERENCES tickets(ticket_id) ON DELETE CASCADE,
                    organization_id    TEXT NOT NULL,
                    old_status         TEXT,
                    new_status         TEXT NOT NULL,
                    note               TEXT,
                    changed_by         TEXT NOT NULL DEFAULT 'system',
                    changed_at         TEXT NOT NULL
                )
            """)

            # Performance indexes
            conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_trail_finding_id ON audit_trail(finding_id, id);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_audit_trail_timestamp ON audit_trail(timestamp DESC);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_pipeline_exec_timestamp ON pipeline_execution_log(timestamp DESC);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_pipeline_exec_status ON pipeline_execution_log(status);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_memberships_org ON organization_memberships(organization_id);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_memberships_user ON organization_memberships(user_id);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_assets_org ON registered_assets(organization_id);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_scan_runs_org ON scan_runs(organization_id);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_scan_runs_asset ON scan_runs(asset_id);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_scan_runs_status ON scan_runs(status);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_submissions_scan_run ON scanner_submissions(scan_run_id);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_submissions_org_asset ON scanner_submissions(organization_id, asset_id);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_submissions_hash ON scanner_submissions(scan_run_id, scanner, payload_hash);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_events_scan_run ON scan_run_events(scan_run_id, event_id);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_events_org ON scan_run_events(organization_id);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_results_scan_run ON scan_run_results(scan_run_id);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_results_org ON scan_run_results(organization_id);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_agents_org ON scanner_agents(organization_id);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_jobs_org ON scanner_jobs(organization_id);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_jobs_scan_run ON scanner_jobs(scan_run_id);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_jobs_status ON scanner_jobs(status);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_sse_tokens_expiry ON sse_stream_tokens(expires_at);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_events_scan_run_created ON scan_run_events(organization_id, scan_run_id, created_at);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_tickets_org_finding ON tickets(organization_id, finding_id);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_tickets_org_status ON tickets(organization_id, status);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_tickets_due_at ON tickets(due_at ASC);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_ticket_history_ticket ON ticket_history(ticket_id, id);")

            # Seed a mock scanner agent with all capabilities if not present (for demo/eval ease)
            existing_mock = conn.execute(
                "SELECT 1 FROM scanner_agents WHERE agent_id = 'mock-scanner-agent-001'"
            ).fetchone()
            if not existing_mock:
                conn.execute(
                    """
                    INSERT INTO scanner_agents
                      (agent_id, organization_id, display_name, token_hash, status,
                       capabilities_json, created_at, created_by_user_id)
                    VALUES
                      ('mock-scanner-agent-001', 'ORG-DEMO-001', 'Mock Production Scanner Agent',
                       'mock_hash', 'ACTIVE', '["NUCLEI", "ZAP", "WAPITI"]', ?, 'system')
                    """,
                    (datetime.now(timezone.utc).isoformat(),),
                )

            conn.commit()
        finally:
            conn.close()



def compute_hash(
    finding_id: str,
    m5_risk_score: int,
    analyst_action: str,
    rationale: str,
    role: str,
    timestamp: str,
    previous_hash: str,
    data_source: str = "LIVE",
    finding_snapshot_hash: str = "",
) -> str:
    """SHA-256 of all immutable event fields concatenated with '|'."""
    raw = "|".join([
        str(finding_id).strip(),
        str(m5_risk_score),
        str(analyst_action).strip().upper(),
        str(rationale or "").strip(),
        str(role or "security_analyst").strip(),
        str(timestamp).strip(),
        str(data_source or "LIVE").strip().upper(),
        str(finding_snapshot_hash or "").strip(),
        str(previous_hash).strip(),
    ])
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def insert_audit_event(
    finding_id: str,
    m5_risk_score: int,
    analyst_action: str,
    rationale: str = "",
    role: str = "security_analyst",
    timestamp: Optional[str] = None,
    data_source: str = "LIVE",
    finding_snapshot_hash: str = "",
) -> Dict[str, Any]:
    """
    Insert a new audit event into SQLite.
    Fetches the previous event's hash to chain with SHA-256.
    Returns the inserted row as a dictionary.
    """
    clean_finding_id = str(finding_id).strip()[:64]
    clean_action = str(analyst_action).strip().upper()[:100]
    clean_rationale = str(rationale or "").strip()[:2000]
    clean_role = str(role or "security_analyst").strip()[:128]
    clean_m5 = max(0, min(100, int(m5_risk_score)))
    clean_source = str(data_source or "LIVE").strip().upper()[:20]
    clean_snapshot = str(finding_snapshot_hash or "").strip()[:64]

    if not timestamp:
        timestamp = datetime.now(timezone.utc).isoformat()
    clean_timestamp = str(timestamp).strip()[:50]

    with _lock:
        conn = _get_conn()
        try:
            # Get the latest event hash for this finding to chain from
            row = conn.execute(
                """
                SELECT event_hash FROM audit_trail
                WHERE finding_id = ?
                ORDER BY id DESC LIMIT 1
                """,
                (clean_finding_id,),
            ).fetchone()
            previous_hash = row["event_hash"] if row else "GENESIS"

            event_hash = compute_hash(
                clean_finding_id,
                clean_m5,
                clean_action,
                clean_rationale,
                clean_role,
                clean_timestamp,
                previous_hash,
                data_source=clean_source,
                finding_snapshot_hash=clean_snapshot,
            )

            conn.execute(
                """
                INSERT INTO audit_trail
                  (finding_id, m5_risk_score, analyst_action, rationale,
                   role, timestamp, data_source, finding_snapshot_hash, previous_hash, event_hash)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (clean_finding_id, clean_m5, clean_action, clean_rationale,
                 clean_role, clean_timestamp, clean_source, clean_snapshot, previous_hash, event_hash),
            )
            conn.commit()

            inserted = conn.execute(
                "SELECT * FROM audit_trail WHERE event_hash = ?", (event_hash,)
            ).fetchone()
            return dict(inserted)
        finally:
            conn.close()


def get_audit_events(finding_id: str, desc: bool = True) -> List[Dict[str, Any]]:
    """
    Return all audit events for a finding.
    By default returns newest first (desc=True), or chronological (desc=False).
    """
    clean_finding_id = str(finding_id).strip()[:64]
    order = "DESC" if desc else "ASC"
    with _lock:
        conn = _get_conn()
        try:
            rows = conn.execute(
                f"SELECT * FROM audit_trail WHERE finding_id = ? ORDER BY id {order}",
                (clean_finding_id,),
            ).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()


def verify_chain(finding_id: str) -> Dict[str, Any]:
    """
    Walk the cryptographic chain for a finding and verify every SHA-256 hash link.
    Returns { valid: bool, broken_at: int | None, total: int, message: str | None }
    """
    clean_finding_id = str(finding_id).strip()[:64]
    events = get_audit_events(clean_finding_id, desc=False)
    if not events:
        return {"valid": True, "broken_at": None, "total": 0, "message": "No audit records found"}

    prev_hash = "GENESIS"
    for ev in events:
        if ev["previous_hash"] != prev_hash:
            return {
                "valid": False,
                "broken_at": ev["id"],
                "total": len(events),
                "message": f"Previous hash mismatch at record #{ev['id']}"
            }

        expected = compute_hash(
            ev["finding_id"],
            ev["m5_risk_score"],
            ev["analyst_action"],
            ev["rationale"],
            ev["role"],
            ev["timestamp"],
            ev["previous_hash"],
            data_source=ev.get("data_source", "LIVE"),
            finding_snapshot_hash=ev.get("finding_snapshot_hash", ""),
        )
        if expected != ev["event_hash"]:
            return {
                "valid": False,
                "broken_at": ev["id"],
                "total": len(events),
                "message": f"Event hash mismatch at record #{ev['id']}"
            }

        prev_hash = ev["event_hash"]

    return {
        "valid": True,
        "broken_at": None,
        "total": len(events),
        "latest_hash": prev_hash,
        "message": "SHA-256 cryptographic chain fully validated"
    }


def insert_pipeline_run_log(
    pipeline_run_id: str,
    request_id: str,
    triggered_by_user_id: str,
    triggered_by_email: str,
    triggered_by_role: str,
    data_origin: str = "LIVE_SCAN",
    raw_finding_count: int = 0,
    canonical_finding_count: int = 0,
    status: str = "SUCCESS",
    timestamp: Optional[str] = None,
    error_message: str = "",
) -> Dict[str, Any]:
    """
    Record an operational pipeline execution entry in SQLite.
    Returns the inserted log record.
    """
    if not timestamp:
        timestamp = datetime.now(timezone.utc).isoformat()

    with _lock:
        conn = _get_conn()
        try:
            conn.execute(
                """
                INSERT INTO pipeline_execution_log
                  (pipeline_run_id, request_id, triggered_by_user_id, triggered_by_email,
                   triggered_by_role, data_origin, raw_finding_count, canonical_finding_count,
                   status, timestamp, error_message)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    pipeline_run_id,
                    request_id,
                    triggered_by_user_id,
                    triggered_by_email,
                    triggered_by_role,
                    data_origin,
                    raw_finding_count,
                    canonical_finding_count,
                    status,
                    timestamp,
                    error_message,
                ),
            )
            conn.commit()

            row = conn.execute(
                "SELECT * FROM pipeline_execution_log WHERE pipeline_run_id = ?",
                (pipeline_run_id,),
            ).fetchone()
            return dict(row) if row else {}
        finally:
            conn.close()


def get_pipeline_run_logs(limit: int = 50) -> List[Dict[str, Any]]:
    """Retrieve operational pipeline execution logs (newest first)."""
    with _lock:
        conn = _get_conn()
        try:
            rows = conn.execute(
                "SELECT * FROM pipeline_execution_log ORDER BY id DESC LIMIT ?",
                (limit,),
            ).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()


# Initialise database table on module load
init_db()


# ═══════════════════════════════════════════════════════════════
# Phase 1 CRUD — Organizations
# ═══════════════════════════════════════════════════════════════

def create_organization(organization_id: str, display_name: str) -> Dict[str, Any]:
    """Insert a new organization. Returns the created row."""
    ts = datetime.now(timezone.utc).isoformat()
    with _lock:
        conn = _get_conn()
        try:
            conn.execute(
                "INSERT INTO organizations (organization_id, display_name, created_at, is_active) VALUES (?, ?, ?, 1)",
                (organization_id, display_name, ts),
            )
            conn.commit()
            row = conn.execute(
                "SELECT * FROM organizations WHERE organization_id = ?", (organization_id,)
            ).fetchone()
            return dict(row) if row else {}
        finally:
            conn.close()


def get_organization(organization_id: str) -> Optional[Dict[str, Any]]:
    """Fetch a single organization by ID."""
    with _lock:
        conn = _get_conn()
        try:
            row = conn.execute(
                "SELECT * FROM organizations WHERE organization_id = ?", (organization_id,)
            ).fetchone()
            return dict(row) if row else None
        finally:
            conn.close()


def list_organizations(active_only: bool = True) -> List[Dict[str, Any]]:
    """List organizations, optionally filtering to active only."""
    with _lock:
        conn = _get_conn()
        try:
            if active_only:
                rows = conn.execute(
                    "SELECT * FROM organizations WHERE is_active = 1 ORDER BY display_name"
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM organizations ORDER BY display_name"
                ).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()


# ═══════════════════════════════════════════════════════════════
# Phase 1 CRUD — Organization Memberships
# ═══════════════════════════════════════════════════════════════

def upsert_membership(membership_id: str, organization_id: str, user_id: str, role: str = "VIEWER") -> Dict[str, Any]:
    """Insert or update an organization membership."""
    ts = datetime.now(timezone.utc).isoformat()
    with _lock:
        conn = _get_conn()
        try:
            conn.execute(
                """
                INSERT INTO organization_memberships (membership_id, organization_id, user_id, role, created_at, is_active)
                VALUES (?, ?, ?, ?, ?, 1)
                ON CONFLICT(organization_id, user_id) DO UPDATE SET role=excluded.role, is_active=1
                """,
                (membership_id, organization_id, user_id, role, ts),
            )
            conn.commit()
            row = conn.execute(
                "SELECT * FROM organization_memberships WHERE organization_id = ? AND user_id = ?",
                (organization_id, user_id),
            ).fetchone()
            return dict(row) if row else {}
        finally:
            conn.close()


def get_user_membership(organization_id: str, user_id: str) -> Optional[Dict[str, Any]]:
    """Check if a user belongs to an organization (active membership only)."""
    with _lock:
        conn = _get_conn()
        try:
            row = conn.execute(
                "SELECT * FROM organization_memberships WHERE organization_id = ? AND user_id = ? AND is_active = 1",
                (organization_id, user_id),
            ).fetchone()
            return dict(row) if row else None
        finally:
            conn.close()


def list_user_organizations(user_id: str) -> List[Dict[str, Any]]:
    """Return all active organizations a user belongs to, with org display names."""
    with _lock:
        conn = _get_conn()
        try:
            rows = conn.execute(
                """
                SELECT o.organization_id, o.display_name, o.created_at, o.is_active,
                       m.membership_id, m.role AS membership_role, m.created_at AS joined_at
                FROM organization_memberships m
                JOIN organizations o ON o.organization_id = m.organization_id
                WHERE m.user_id = ? AND m.is_active = 1 AND o.is_active = 1
                ORDER BY o.display_name
                """,
                (user_id,),
            ).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()


def list_org_members(organization_id: str) -> List[Dict[str, Any]]:
    """List all active members of an organization."""
    with _lock:
        conn = _get_conn()
        try:
            rows = conn.execute(
                "SELECT * FROM organization_memberships WHERE organization_id = ? AND is_active = 1 ORDER BY created_at",
                (organization_id,),
            ).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()


# ═══════════════════════════════════════════════════════════════
# Phase 1 CRUD — Registered Assets
# ═══════════════════════════════════════════════════════════════

def create_registered_asset(
    asset_id: str,
    organization_id: str,
    display_name: str,
    host: str,
    normalized_host: str,
    port: Optional[int],
    environment: str,
    criticality: str,
    internet_facing: Optional[bool],
    data_sensitivity: str,
    created_by: str,
) -> Dict[str, Any]:
    """Insert a new registered asset (PENDING status). Raises sqlite3.IntegrityError on duplicate host:port within org."""
    ts = datetime.now(timezone.utc).isoformat()
    internet_val = None if internet_facing is None else (1 if internet_facing else 0)
    with _lock:
        conn = _get_conn()
        try:
            conn.execute(
                """
                INSERT INTO registered_assets
                  (asset_id, organization_id, display_name, host, normalized_host, port,
                   environment, criticality, internet_facing, data_sensitivity,
                   authorization_status, created_by, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'PENDING', ?, ?, ?)
                """,
                (
                    asset_id, organization_id, display_name, host, normalized_host, port,
                    environment, criticality, internet_val, data_sensitivity,
                    created_by, ts, ts,
                ),
            )
            conn.commit()
            row = conn.execute(
                "SELECT * FROM registered_assets WHERE asset_id = ?", (asset_id,)
            ).fetchone()
            return dict(row) if row else {}
        finally:
            conn.close()


def get_registered_asset(organization_id: str, asset_id: str) -> Optional[Dict[str, Any]]:
    """Fetch an asset scoped strictly to an organization. Returns None if not found or wrong org."""
    with _lock:
        conn = _get_conn()
        try:
            row = conn.execute(
                "SELECT * FROM registered_assets WHERE asset_id = ? AND organization_id = ?",
                (asset_id, organization_id),
            ).fetchone()
            return dict(row) if row else None
        finally:
            conn.close()


def list_registered_assets(organization_id: str) -> List[Dict[str, Any]]:
    """List all registered assets for an organization."""
    with _lock:
        conn = _get_conn()
        try:
            rows = conn.execute(
                "SELECT * FROM registered_assets WHERE organization_id = ? ORDER BY display_name",
                (organization_id,),
            ).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()


def update_asset_authorization(
    organization_id: str,
    asset_id: str,
    new_status: str,
    updated_by: str,
) -> Optional[Dict[str, Any]]:
    """
    Transition asset authorization status. Valid values: PENDING, AUTHORIZED, DISABLED.
    Scoped to organization_id — cross-org updates are silently rejected (0 rows affected → None).
    """
    ts = datetime.now(timezone.utc).isoformat()
    with _lock:
        conn = _get_conn()
        try:
            cur = conn.execute(
                """
                UPDATE registered_assets
                SET authorization_status = ?, updated_at = ?
                WHERE asset_id = ? AND organization_id = ?
                """,
                (new_status, ts, asset_id, organization_id),
            )
            conn.commit()
            if cur.rowcount == 0:
                return None
            row = conn.execute(
                "SELECT * FROM registered_assets WHERE asset_id = ?", (asset_id,)
            ).fetchone()
            return dict(row) if row else None
        finally:
            conn.close()


def get_authorized_asset_catalog(organization_id: str) -> List[Dict[str, Any]]:
    """Return AUTHORIZED assets for an org, formatted for AssetResolver catalog integration."""
    with _lock:
        conn = _get_conn()
        try:
            rows = conn.execute(
                """
                SELECT * FROM registered_assets
                WHERE organization_id = ? AND authorization_status = 'AUTHORIZED'
                ORDER BY display_name
                """,
                (organization_id,),
            ).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()


# ═══════════════════════════════════════════════════════════════
# Phase 1 CRUD — Scan Runs
# ═══════════════════════════════════════════════════════════════

_VALID_SCAN_RUN_TRANSITIONS: Dict[str, List[str]] = {
    "CREATED":           ["WAITING_FOR_INPUT", "CANCELLED"],
    "WAITING_FOR_INPUT": ["INGESTING", "CANCELLED"],
    "INGESTING":         ["PROCESSING", "FAILED", "CANCELLED"],
    "PROCESSING":        ["COMPLETED", "FAILED"],
    "COMPLETED":         [],
    "FAILED":            [],
    "CANCELLED":         [],
}

SUPPORTED_SCANNERS = frozenset(["ZAP", "NUCLEI", "WAPITI"])


def create_scan_run(
    scan_run_id: str,
    organization_id: str,
    asset_id: str,
    created_by_user_id: str,
    scanner_selections: List[str],
    data_origin: str = "LIVE_SCAN",
) -> Dict[str, Any]:
    """
    Create a new scan run in CREATED status.
    Validates scanner_selections against SUPPORTED_SCANNERS.
    Phase 1 only: does NOT execute scanners.
    """
    invalid = [s for s in scanner_selections if s.upper() not in SUPPORTED_SCANNERS]
    if invalid:
        raise ValueError(f"Unsupported scanners: {invalid}. Supported: {sorted(SUPPORTED_SCANNERS)}")

    import json as _json
    selections_json = _json.dumps([s.upper() for s in scanner_selections])
    ts = datetime.now(timezone.utc).isoformat()

    with _lock:
        conn = _get_conn()
        try:
            conn.execute(
                """
                INSERT INTO scan_runs
                  (scan_run_id, organization_id, asset_id, created_by_user_id,
                   status, scanner_selections, data_origin, created_at, updated_at)
                VALUES (?, ?, ?, ?, 'CREATED', ?, ?, ?, ?)
                """,
                (scan_run_id, organization_id, asset_id, created_by_user_id,
                 selections_json, data_origin, ts, ts),
            )
            conn.commit()
            row = conn.execute(
                "SELECT * FROM scan_runs WHERE scan_run_id = ?", (scan_run_id,)
            ).fetchone()
            return dict(row) if row else {}
        finally:
            conn.close()


def get_scan_run(organization_id: str, scan_run_id: str) -> Optional[Dict[str, Any]]:
    """Fetch a scan run scoped strictly to an organization."""
    with _lock:
        conn = _get_conn()
        try:
            row = conn.execute(
                "SELECT * FROM scan_runs WHERE scan_run_id = ? AND organization_id = ?",
                (scan_run_id, organization_id),
            ).fetchone()
            return dict(row) if row else None
        finally:
            conn.close()


def list_scan_runs(organization_id: str, limit: int = 50) -> List[Dict[str, Any]]:
    """List scan runs for an organization, newest first."""
    with _lock:
        conn = _get_conn()
        try:
            rows = conn.execute(
                "SELECT * FROM scan_runs WHERE organization_id = ? ORDER BY created_at DESC LIMIT ?",
                (organization_id, limit),
            ).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()


def transition_scan_run(
    organization_id: str,
    scan_run_id: str,
    new_status: str,
    error_message: str = "",
) -> Optional[Dict[str, Any]]:
    """
    Advance a scan run's status machine. Returns updated row or raises ValueError on invalid transition.
    Cross-org calls return None.
    """
    with _lock:
        conn = _get_conn()
        try:
            row = conn.execute(
                "SELECT * FROM scan_runs WHERE scan_run_id = ? AND organization_id = ?",
                (scan_run_id, organization_id),
            ).fetchone()
            if not row:
                return None

            current_status = row["status"]
            allowed = _VALID_SCAN_RUN_TRANSITIONS.get(current_status, [])
            if new_status not in allowed:
                raise ValueError(
                    f"Invalid scan run transition: {current_status} → {new_status}. "
                    f"Allowed from {current_status}: {allowed}"
                )

            ts = datetime.now(timezone.utc).isoformat()
            started_at = row["started_at"]
            completed_at = row["completed_at"]

            if new_status == "INGESTING" and not started_at:
                started_at = ts
            if new_status in ("COMPLETED", "FAILED", "CANCELLED") and not completed_at:
                completed_at = ts

            conn.execute(
                """
                UPDATE scan_runs
                SET status = ?, updated_at = ?, started_at = ?, completed_at = ?, error_message = ?
                WHERE scan_run_id = ? AND organization_id = ?
                """,
                (new_status, ts, started_at, completed_at, error_message,
                 scan_run_id, organization_id),
            )
            conn.commit()
            updated = conn.execute(
                "SELECT * FROM scan_runs WHERE scan_run_id = ?", (scan_run_id,)
            ).fetchone()
            return dict(updated) if updated else None
        finally:
            conn.close()


# ═══════════════════════════════════════════════════════════════
# Phase 2 CRUD — Scanner Submissions
# ═══════════════════════════════════════════════════════════════

def create_scanner_submission(
    submission_id: str,
    scan_run_id: str,
    organization_id: str,
    asset_id: str,
    scanner: str,
    submission_type: str,
    received_by_user_id: str,
    original_filename: Optional[str],
    content_type: Optional[str],
    file_size_bytes: int,
    storage_path: str,
    raw_finding_count: int,
    processing_status: str,
    payload_hash: str,
    idempotency_key: str = "",
    error_code: str = "",
    error_message: str = "",
) -> Dict[str, Any]:
    """Record a raw scanner submission in SQLite."""
    ts = datetime.now(timezone.utc).isoformat()
    with _lock:
        conn = _get_conn()
        try:
            conn.execute(
                """
                INSERT INTO scanner_submissions
                  (submission_id, scan_run_id, organization_id, asset_id, scanner,
                   submission_type, received_by_user_id, received_at, original_filename,
                   content_type, file_size_bytes, storage_path, raw_finding_count,
                   processing_status, error_code, error_message, payload_hash, idempotency_key)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    submission_id, scan_run_id, organization_id, asset_id, scanner.upper(),
                    submission_type, received_by_user_id, ts, original_filename,
                    content_type, file_size_bytes, storage_path, raw_finding_count,
                    processing_status, error_code, error_message, payload_hash, idempotency_key
                ),
            )
            conn.commit()
            row = conn.execute(
                "SELECT * FROM scanner_submissions WHERE submission_id = ?", (submission_id,)
            ).fetchone()
            return dict(row) if row else {}
        finally:
            conn.close()


def get_submission_by_hash(scan_run_id: str, scanner: str, payload_hash: str) -> Optional[Dict[str, Any]]:
    """Check for existing submission with matching payload_hash for idempotency."""
    with _lock:
        conn = _get_conn()
        try:
            row = conn.execute(
                """
                SELECT * FROM scanner_submissions
                WHERE scan_run_id = ? AND scanner = ? AND payload_hash = ?
                """,
                (scan_run_id, scanner.upper(), payload_hash),
            ).fetchone()
            return dict(row) if row else None
        finally:
            conn.close()


def list_submissions_for_run(organization_id: str, scan_run_id: str) -> List[Dict[str, Any]]:
    """List scanner submissions for a scan run scoped to organization_id."""
    with _lock:
        conn = _get_conn()
        try:
            rows = conn.execute(
                """
                SELECT * FROM scanner_submissions
                WHERE scan_run_id = ? AND organization_id = ?
                ORDER BY received_at ASC
                """,
                (scan_run_id, organization_id),
            ).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()


# ═══════════════════════════════════════════════════════════════
# Phase 2 CRUD — Real Stage Event Ledger
# ═══════════════════════════════════════════════════════════════

def insert_scan_run_event(
    event_id: str,
    organization_id: str,
    scan_run_id: str,
    event_type: str,
    stage: str,
    message: str,
    status: str = "INFO",
    metadata_json: str = "{}",
) -> Dict[str, Any]:
    """Persist a real backend scan run stage event."""
    ts = datetime.now(timezone.utc).isoformat()
    with _lock:
        conn = _get_conn()
        try:
            conn.execute(
                """
                INSERT INTO scan_run_events
                  (event_id, organization_id, scan_run_id, event_type, stage, status, message, metadata_json, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (event_id, organization_id, scan_run_id, event_type, stage, status, message, metadata_json, ts),
            )
            conn.commit()
            row = conn.execute(
                "SELECT * FROM scan_run_events WHERE event_id = ?", (event_id,)
            ).fetchone()
            return dict(row) if row else {}
        finally:
            conn.close()


def list_scan_run_events(organization_id: str, scan_run_id: str) -> List[Dict[str, Any]]:
    """Retrieve all backend events for a scan run scoped to organization_id."""
    with _lock:
        conn = _get_conn()
        try:
            rows = conn.execute(
                """
                SELECT rowid AS seq, * FROM scan_run_events
                WHERE scan_run_id = ? AND organization_id = ?
                ORDER BY rowid ASC
                """,
                (scan_run_id, organization_id),
            ).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()


def list_scan_run_events_after(
    organization_id: str,
    scan_run_id: str,
    after_event_id: Optional[str] = None,
    limit: int = 200,
) -> List[Dict[str, Any]]:
    """
    Replay cursor: return persisted events for this org+scan_run with rowid greater
    than the Last-Event-ID's row, then in insertion order.

    If after_event_id does not belong to this organization+scan_run, the cursor is
    ignored (treated as start-of-stream). Cross-org event IDs never leak rows.
    """
    with _lock:
        conn = _get_conn()
        try:
            after_seq = 0
            if after_event_id:
                row = conn.execute(
                    """
                    SELECT rowid AS seq FROM scan_run_events
                    WHERE event_id = ? AND organization_id = ? AND scan_run_id = ?
                    """,
                    (after_event_id, organization_id, scan_run_id),
                ).fetchone()
                if row:
                    after_seq = int(row["seq"])

            rows = conn.execute(
                """
                SELECT rowid AS seq, * FROM scan_run_events
                WHERE organization_id = ? AND scan_run_id = ? AND rowid > ?
                ORDER BY rowid ASC
                LIMIT ?
                """,
                (organization_id, scan_run_id, after_seq, limit),
            ).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()


def issue_sse_stream_token(
    token_hash: str,
    user_id: str,
    organization_id: str,
    scan_run_id: str,
    expires_at: str,
) -> None:
    """Persist a hashed short-lived SSE stream token bound to org + scan run + user."""
    ts = datetime.now(timezone.utc).isoformat()
    with _lock:
        conn = _get_conn()
        try:
            conn.execute("DELETE FROM sse_stream_tokens WHERE expires_at < ?", (ts,))
            conn.execute(
                """
                INSERT INTO sse_stream_tokens
                  (token_hash, user_id, organization_id, scan_run_id, expires_at, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (token_hash, user_id, organization_id, scan_run_id, expires_at, ts),
            )
            conn.commit()
        finally:
            conn.close()


def get_sse_stream_token(token_hash: str) -> Optional[Dict[str, Any]]:
    """Lookup a stream token by hash. Returns None if missing or expired."""
    now = datetime.now(timezone.utc).isoformat()
    with _lock:
        conn = _get_conn()
        try:
            row = conn.execute(
                """
                SELECT * FROM sse_stream_tokens
                WHERE token_hash = ? AND expires_at > ?
                """,
                (token_hash, now),
            ).fetchone()
            return dict(row) if row else None
        finally:
            conn.close()


def consume_sse_stream_token(token_hash: str) -> Optional[Dict[str, Any]]:
    """
    Atomically lookup and consume a single-use stream token ticket.
    Returns token record if valid, unexpired, and not previously used.
    Rejects used or expired tickets atomically (single-use guarantee).
    """
    now = datetime.now(timezone.utc).isoformat()
    with _lock:
        conn = _get_conn()
        try:
            row = conn.execute(
                """
                SELECT * FROM sse_stream_tokens
                WHERE token_hash = ? AND expires_at > ? AND (used_at IS NULL OR used_at = '')
                """,
                (token_hash, now),
            ).fetchone()
            if not row:
                return None

            cursor = conn.execute(
                """
                UPDATE sse_stream_tokens
                SET used_at = ?
                WHERE token_hash = ? AND (used_at IS NULL OR used_at = '') AND expires_at > ?
                """,
                (now, token_hash, now),
            )
            conn.commit()

            if cursor.rowcount == 1:
                rec = dict(row)
                rec["used_at"] = now
                return rec
            return None
        finally:
            conn.close()


# ═══════════════════════════════════════════════════════════════
# Phase 2 CRUD — Scan Run Results & Multi-Scanner Consensus
# ═══════════════════════════════════════════════════════════════

def update_scan_run_consensus(
    organization_id: str,
    scan_run_id: str,
    received_scanner: str,
    raw_findings_added: int,
    failed_scanner: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    """
    Update received_scanners and pending_scanners lists in scan_runs table.
    Tracks received, pending, and failed scanners truthfully against scan_runs.scanner_selections.
    """
    import json as _json
    ts = datetime.now(timezone.utc).isoformat()
    with _lock:
        conn = _get_conn()
        try:
            row = conn.execute(
                "SELECT * FROM scan_runs WHERE scan_run_id = ? AND organization_id = ?",
                (scan_run_id, organization_id),
            ).fetchone()
            if not row:
                return None

            selections = _json.loads(row["scanner_selections"] or "[]")
            received = set(_json.loads(row["received_scanners"] or "[]"))
            failed = set(_json.loads(row["failed_scanners"] or "[]"))

            if received_scanner and received_scanner.upper() not in received:
                received.add(received_scanner.upper())
            if failed_scanner and failed_scanner.upper() not in failed:
                failed.add(failed_scanner.upper())

            pending = [s for s in selections if s not in received and s not in failed]
            new_raw_count = row["raw_count"] + max(0, raw_findings_added)

            conn.execute(
                """
                UPDATE scan_runs
                SET status = 'INGESTING',
                    received_scanners = ?,
                    pending_scanners = ?,
                    failed_scanners = ?,
                    raw_count = ?,
                    last_ingested_at = ?,
                    updated_at = ?
                WHERE scan_run_id = ? AND organization_id = ?
                """,
                (
                    _json.dumps(sorted(list(received))),
                    _json.dumps(pending),
                    _json.dumps(sorted(list(failed))),
                    new_raw_count,
                    ts,
                    ts,
                    scan_run_id,
                    organization_id,
                ),
            )
            conn.commit()
            updated = conn.execute(
                "SELECT * FROM scan_runs WHERE scan_run_id = ?", (scan_run_id,)
            ).fetchone()
            return dict(updated) if updated else None
        finally:
            conn.close()


def atomic_acquire_processing_lock(organization_id: str, scan_run_id: str) -> bool:
    """
    Race-safe atomic state transition to PROCESSING.
    Returns True if THIS caller successfully acquired the lock and transitioned state.
    Returns False if scan run was already PROCESSING, COMPLETED, or FAILED.
    """
    ts = datetime.now(timezone.utc).isoformat()
    with _lock:
        conn = _get_conn()
        try:
            cur = conn.execute(
                """
                UPDATE scan_runs
                SET status = 'PROCESSING', processing_started_at = ?, updated_at = ?
                WHERE scan_run_id = ? AND organization_id = ?
                  AND status IN ('CREATED', 'WAITING_FOR_INPUT', 'INGESTING')
                """,
                (ts, ts, scan_run_id, organization_id),
            )
            conn.commit()
            return cur.rowcount > 0
        finally:
            conn.close()


def save_scan_run_results(
    result_id: str,
    organization_id: str,
    scan_run_id: str,
    asset_id: str,
    raw_finding_count: int,
    canonical_finding_count: int,
    findings_json: str,
    summary_json: str,
) -> Dict[str, Any]:
    """Persist final pipeline execution results for a scan run."""
    ts = datetime.now(timezone.utc).isoformat()
    with _lock:
        conn = _get_conn()
        try:
            conn.execute(
                """
                INSERT INTO scan_run_results
                  (result_id, organization_id, scan_run_id, asset_id,
                   raw_finding_count, canonical_finding_count, findings_json, summary_json, completed_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(scan_run_id) DO UPDATE SET
                  findings_json = excluded.findings_json,
                  summary_json = excluded.summary_json,
                  canonical_finding_count = excluded.canonical_finding_count,
                  completed_at = excluded.completed_at
                """,
                (result_id, organization_id, scan_run_id, asset_id,
                 raw_finding_count, canonical_finding_count, findings_json, summary_json, ts),
            )
            conn.commit()
            row = conn.execute(
                "SELECT * FROM scan_run_results WHERE scan_run_id = ?", (scan_run_id,)
            ).fetchone()
            return dict(row) if row else {}
        finally:
            conn.close()


def get_scan_run_results(organization_id: str, scan_run_id: str) -> Optional[Dict[str, Any]]:
    """Retrieve scan run results scoped strictly to organization_id."""
    with _lock:
        conn = _get_conn()
        try:
            row = conn.execute(
                """
                SELECT * FROM scan_run_results
                WHERE scan_run_id = ? AND organization_id = ?
                """,
                (scan_run_id, organization_id),
            ).fetchone()
            return dict(row) if row else None
        finally:
            conn.close()


def _enrich_canonical_finding_record(
    item: Dict[str, Any],
    asset_lookup: Dict[str, Dict[str, Any]],
    scan_run_row: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Enriches a canonical finding record with authoritative registered asset metadata
    and synchronizes human-readable explanation strings with the resolved asset context.
    """
    res = dict(item)
    if "scan_run_id" not in res or not res["scan_run_id"]:
        res["scan_run_id"] = scan_run_row["scan_run_id"]
    if "organization_id" not in res or not res["organization_id"]:
        res["organization_id"] = scan_run_row["organization_id"]

    res.setdefault("detail", {})
    res["detail"].setdefault("asset_context", {})

    asset_key = res.get("asset_id") or scan_run_row.get("asset_id")
    a_info = asset_lookup.get(asset_key) if asset_key else None

    if a_info:
        # Authoritative resolved asset context
        resolved_name = a_info["display_name"]
        resolved_crit = a_info["criticality"]
        resolved_env = a_info["environment"]
        resolved_facing = bool(a_info["internet_facing"]) if a_info.get("internet_facing") is not None else None
        resolved_sens = a_info.get("data_sensitivity", "CONFIDENTIAL")

        res["asset_id"] = a_info["asset_id"]
        res["asset_criticality"] = resolved_crit
        res["detail"]["asset_context"]["asset_id"] = a_info["asset_id"]
        res["detail"]["asset_context"]["asset_name"] = resolved_name
        res["detail"]["asset_context"]["criticality"] = resolved_crit
        res["detail"]["asset_context"]["environment"] = resolved_env
        res["detail"]["asset_context"]["data_sensitivity"] = resolved_sens
        if resolved_facing is not None:
            res["internet_exposure"] = resolved_facing
            res["detail"]["asset_context"]["internet_facing"] = resolved_facing
            res["detail"]["asset_context"]["internet_exposure"] = resolved_facing

        # Synchronize explanation text with resolved asset
        if "explanation" in res["detail"] and isinstance(res["detail"]["explanation"], dict):
            exp = dict(res["detail"]["explanation"])
            if "management" in exp and isinstance(exp["management"], str):
                mgmt = exp["management"]
                # Replace Unresolved Asset with real resolved name
                mgmt = mgmt.replace("Unresolved Asset", resolved_name)
                mgmt = mgmt.replace("on asset UNMAPPED", f"on {resolved_name}")
                # Replace 'which is a unknown asset'
                mgmt = re.sub(r"which is a\s+unknown asset", f"which is a {resolved_crit.lower()} asset", mgmt, flags=re.IGNORECASE)
                mgmt = re.sub(r"which is an?\s+unclassified asset(?:\s+in the registry)?", f"which is a {resolved_crit.lower()} asset", mgmt, flags=re.IGNORECASE)
                # Strip UNKNOWN-classified data
                mgmt = re.sub(r"\s*This system handles UNKNOWN-classified data\.?", "", mgmt, flags=re.IGNORECASE)
                exp["management"] = mgmt.strip()

            if "technical" in exp and isinstance(exp["technical"], str):
                tech = exp["technical"]
                tech = tech.replace("on asset Unresolved Asset", f"on asset {resolved_name}")
                tech = tech.replace("on asset UNMAPPED", f"on asset {resolved_name}")
                tech = re.sub(r"\s*This system handles UNKNOWN-classified data\.?", "", tech, flags=re.IGNORECASE)
                exp["technical"] = tech.strip()
            res["detail"]["explanation"] = exp
    else:
        # Genuinely unresolved asset
        current_name = res["detail"]["asset_context"].get("asset_name")
        if not current_name or current_name.startswith("host-"):
            res["detail"]["asset_context"]["asset_name"] = "Unresolved Asset"
        if not res.get("asset_criticality"):
            res["asset_criticality"] = "UNKNOWN"
            res["detail"]["asset_context"]["criticality"] = "UNKNOWN"

        if "explanation" in res["detail"] and isinstance(res["detail"]["explanation"], dict):
            exp = dict(res["detail"]["explanation"])
            if "management" in exp and isinstance(exp["management"], str):
                mgmt = exp["management"]
                # Clean grammar for genuinely unmapped
                mgmt = re.sub(r"which is a\s+unknown asset", "which is currently unclassified in the asset registry", mgmt, flags=re.IGNORECASE)
                mgmt = re.sub(r"\s*This system handles UNKNOWN-classified data\.?", "", mgmt, flags=re.IGNORECASE)
                exp["management"] = mgmt.strip()

            if "technical" in exp and isinstance(exp["technical"], str):
                tech = exp["technical"]
                tech = re.sub(r"\s*This system handles UNKNOWN-classified data\.?", "", tech, flags=re.IGNORECASE)
                exp["technical"] = tech.strip()
            res["detail"]["explanation"] = exp

    return res


def get_canonical_finding_by_id(
    finding_id: str,
    organization_id: Optional[str] = None,
    user_org_ids: Optional[List[str]] = None,
) -> Optional[Dict[str, Any]]:
    """
    Look up a canonical finding across scan_run_results scoped to tenant organization(s).
    """
    clean_id = (finding_id or "").strip().lower()
    if not clean_id:
        return None

    conditions = []
    params = []

    if organization_id:
        if user_org_ids is not None and organization_id not in user_org_ids:
            return None
        conditions.append("organization_id = ?")
        params.append(organization_id)
    elif user_org_ids is not None:
        if len(user_org_ids) == 0:
            return None
        placeholders = ",".join("?" for _ in user_org_ids)
        conditions.append(f"organization_id IN ({placeholders})")
        params.extend(user_org_ids)

    where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""
    query = f"""
        SELECT scan_run_id, organization_id, asset_id, findings_json, completed_at
        FROM scan_run_results
        {where_clause}
        ORDER BY completed_at DESC
    """

    with _lock:
        conn = _get_conn()
        try:
            asset_rows = conn.execute("SELECT asset_id, display_name, criticality, environment, internet_facing, data_sensitivity FROM registered_assets").fetchall()
            asset_lookup = { a["asset_id"]: dict(a) for a in asset_rows }

            rows = conn.execute(query, params).fetchall()
            for r in rows:
                try:
                    findings = json.loads(r["findings_json"])
                    for f in findings:
                        f_id = (f.get("finding_id") or "").strip().lower()
                        cve = (f.get("cve_id") or "").strip().lower()
                        if f_id == clean_id or cve == clean_id:
                            return _enrich_canonical_finding_record(f, asset_lookup, r)
                except Exception as e:
                    logger.warning("Error parsing findings_json for scan run %s: %s", r["scan_run_id"], e)
            return None
        finally:
            conn.close()


def list_canonical_findings(
    organization_id: Optional[str] = None,
    user_org_ids: Optional[List[str]] = None,
    scan_run_id: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """
    Retrieve all canonical findings across scan runs for authorized organization(s).
    """
    conditions = []
    params = []

    if scan_run_id:
        conditions.append("scan_run_id = ?")
        params.append(scan_run_id)

    if organization_id:
        if user_org_ids is not None and organization_id not in user_org_ids:
            return []
        conditions.append("organization_id = ?")
        params.append(organization_id)
    elif user_org_ids is not None:
        if len(user_org_ids) == 0:
            return []
        placeholders = ",".join("?" for _ in user_org_ids)
        conditions.append(f"organization_id IN ({placeholders})")
        params.extend(user_org_ids)

    where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""
    query = f"""
        SELECT scan_run_id, organization_id, asset_id, findings_json, completed_at
        FROM scan_run_results
        {where_clause}
        ORDER BY completed_at DESC
    """

    results = []
    seen_ids = set()
    seen_vuln_keys = set()

    with _lock:
        conn = _get_conn()
        try:
            asset_rows = conn.execute("SELECT asset_id, display_name, criticality, environment, internet_facing, data_sensitivity FROM registered_assets").fetchall()
            asset_lookup = { a["asset_id"]: dict(a) for a in asset_rows }

            rows = conn.execute(query, params).fetchall()
            for r in rows:
                try:
                    findings = json.loads(r["findings_json"])
                    for f in findings:
                        f_id = f.get("finding_id")
                        v_name = (f.get("vulnerability_name") or "").strip().lower()
                        asset = (f.get("asset_id") or r["asset_id"] or "").strip().lower()
                        target = (f.get("target_host") or f.get("host") or "").strip().lower()
                        
                        # When querying across multiple historical scan runs (no specific scan_run_id),
                        # retain the latest scan finding per (asset, vulnerability_name, target)
                        vuln_key = (asset, v_name, target) if not scan_run_id else f_id

                        if f_id and f_id not in seen_ids and vuln_key not in seen_vuln_keys:
                            seen_ids.add(f_id)
                            seen_vuln_keys.add(vuln_key)
                            enriched = _enrich_canonical_finding_record(f, asset_lookup, r)
                            results.append(enriched)
                except Exception as e:
                    logger.warning("Error parsing findings_json for scan run %s: %s", r["scan_run_id"], e)
            return results
        finally:
            conn.close()



# ═══════════════════════════════════════════════════════════════
# Phase 4 CRUD — Scanner Agents & Machine Authentication
# ═══════════════════════════════════════════════════════════════

def create_scanner_agent(
    agent_id: str,
    organization_id: str,
    display_name: str,
    token_hash: str,
    created_by_user_id: str,
    capabilities_json: str = "{}",
) -> Dict[str, Any]:
    """Register a new scanner agent."""
    ts = datetime.now(timezone.utc).isoformat()
    with _lock:
        conn = _get_conn()
        try:
            conn.execute(
                """
                INSERT INTO scanner_agents
                  (agent_id, organization_id, display_name, token_hash, status,
                   capabilities_json, created_at, created_by_user_id)
                VALUES (?, ?, ?, ?, 'ACTIVE', ?, ?, ?)
                """,
                (agent_id, organization_id, display_name, token_hash, capabilities_json, ts, created_by_user_id),
            )
            conn.commit()
            row = conn.execute("SELECT * FROM scanner_agents WHERE agent_id = ?", (agent_id,)).fetchone()
            return dict(row) if row else {}
        finally:
            conn.close()


def get_scanner_agent(agent_id: str) -> Optional[Dict[str, Any]]:
    """Lookup agent by ID."""
    with _lock:
        conn = _get_conn()
        try:
            row = conn.execute("SELECT * FROM scanner_agents WHERE agent_id = ?", (agent_id,)).fetchone()
            return dict(row) if row else None
        finally:
            conn.close()


def get_scanner_agent_by_token_hash(token_hash: str) -> Optional[Dict[str, Any]]:
    """Lookup active/valid agent by token hash."""
    with _lock:
        conn = _get_conn()
        try:
            row = conn.execute(
                "SELECT * FROM scanner_agents WHERE token_hash = ? AND status = 'ACTIVE'",
                (token_hash,),
            ).fetchone()
            return dict(row) if row else None
        finally:
            conn.close()


def list_scanner_agents(organization_id: str) -> List[Dict[str, Any]]:
    """List scanner agents registered for an organization."""
    with _lock:
        conn = _get_conn()
        try:
            rows = conn.execute(
                "SELECT * FROM scanner_agents WHERE organization_id = ? ORDER BY created_at DESC",
                (organization_id,),
            ).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()


def revoke_scanner_agent(organization_id: str, agent_id: str) -> bool:
    """Revoke a scanner agent."""
    ts = datetime.now(timezone.utc).isoformat()
    with _lock:
        conn = _get_conn()
        try:
            cur = conn.execute(
                """
                UPDATE scanner_agents
                SET status = 'REVOKED', revoked_at = ?
                WHERE agent_id = ? AND organization_id = ? AND status != 'REVOKED'
                """,
                (ts, agent_id, organization_id),
            )
            conn.commit()
            return cur.rowcount > 0
        finally:
            conn.close()


def update_agent_heartbeat(agent_id: str, capabilities_json: Optional[str] = None) -> None:
    """Update last_seen_at timestamp and capabilities for an agent."""
    ts = datetime.now(timezone.utc).isoformat()
    with _lock:
        conn = _get_conn()
        try:
            if capabilities_json:
                conn.execute(
                    "UPDATE scanner_agents SET last_seen_at = ?, capabilities_json = ? WHERE agent_id = ?",
                    (ts, capabilities_json, agent_id),
                )
            else:
                conn.execute(
                    "UPDATE scanner_agents SET last_seen_at = ? WHERE agent_id = ?",
                    (ts, agent_id),
                )
            conn.commit()
        finally:
            conn.close()


def normalize_scanner_id(scanner_str: Optional[str]) -> Optional[str]:
    """Normalize casing and aliases to canonical scanner identifier: NUCLEI, ZAP, WAPITI."""
    if not scanner_str or not isinstance(scanner_str, str):
        return None
    s = scanner_str.strip().upper().replace(" ", "_")
    if s in ("NUCLEI",):
        return "NUCLEI"
    if s in ("ZAP", "OWASP_ZAP", "OWASPZAP"):
        return "ZAP"
    if s in ("WAPITI",):
        return "WAPITI"
    return None


def get_active_scanner_capabilities(organization_id: str) -> Dict[str, Dict[str, Any]]:
    """
    Aggregate capabilities from all active, non-revoked scanner agents for an organization.
    Returns a dictionary keyed by canonical scanner IDs (NUCLEI, ZAP, WAPITI).
    A scanner is available if at least one ACTIVE agent reports available == True.
    """
    res: Dict[str, Dict[str, Any]] = {
        "NUCLEI": {"available": False, "version": None, "health_status": "UNAVAILABLE"},
        "ZAP": {"available": False, "version": None, "health_status": "UNAVAILABLE"},
        "WAPITI": {"available": False, "version": None, "health_status": "UNAVAILABLE"},
    }

    with _lock:
        conn = _get_conn()
        try:
            rows = conn.execute(
                """
                SELECT capabilities_json, status, last_seen_at FROM scanner_agents
                WHERE organization_id = ? AND status = 'ACTIVE'
                """,
                (organization_id,),
            ).fetchall()
        finally:
            conn.close()

    for row in rows:
        cap_str = row["capabilities_json"]
        if not cap_str:
            continue
        try:
            caps_data = json.loads(cap_str)
        except Exception:
            continue

        if isinstance(caps_data, list):
            for item in caps_data:
                cid = normalize_scanner_id(str(item))
                if cid and cid in res:
                    res[cid]["available"] = True
                    res[cid]["health_status"] = "AVAILABLE"
        elif isinstance(caps_data, dict):
            for k, v in caps_data.items():
                cid = normalize_scanner_id(str(k))
                if not cid or cid not in res:
                    continue
                if isinstance(v, dict):
                    if v.get("available") is True:
                        res[cid]["available"] = True
                        res[cid]["health_status"] = "AVAILABLE"
                        if v.get("version") and not res[cid]["version"]:
                            res[cid]["version"] = str(v["version"])
                elif v is True:
                    res[cid]["available"] = True
                    res[cid]["health_status"] = "AVAILABLE"

    return res


# ═══════════════════════════════════════════════════════════════
# Phase 4 CRUD — Scanner Jobs Queue
# ═══════════════════════════════════════════════════════════════

def create_scanner_job(
    scanner_job_id: str,
    organization_id: str,
    scan_run_id: str,
    asset_id: str,
    scanner: str,
    max_attempts: int = 3,
) -> Dict[str, Any]:
    """Create a new QUEUED scanner job."""
    ts = datetime.now(timezone.utc).isoformat()
    with _lock:
        conn = _get_conn()
        try:
            conn.execute(
                """
                INSERT INTO scanner_jobs
                  (scanner_job_id, organization_id, scan_run_id, asset_id, scanner,
                   status, attempt, max_attempts, created_at)
                VALUES (?, ?, ?, ?, ?, 'QUEUED', 1, ?, ?)
                """,
                (scanner_job_id, organization_id, scan_run_id, asset_id, scanner.upper(), max_attempts, ts),
            )
            conn.commit()
            row = conn.execute("SELECT * FROM scanner_jobs WHERE scanner_job_id = ?", (scanner_job_id,)).fetchone()
            return dict(row) if row else {}
        finally:
            conn.close()


def get_scanner_job(scanner_job_id: str) -> Optional[Dict[str, Any]]:
    """Fetch scanner job by ID."""
    with _lock:
        conn = _get_conn()
        try:
            row = conn.execute("SELECT * FROM scanner_jobs WHERE scanner_job_id = ?", (scanner_job_id,)).fetchone()
            return dict(row) if row else None
        finally:
            conn.close()


def list_scanner_jobs_for_run(organization_id: str, scan_run_id: str) -> List[Dict[str, Any]]:
    """List scanner jobs for a specific scan run."""
    with _lock:
        conn = _get_conn()
        try:
            rows = conn.execute(
                """
                SELECT * FROM scanner_jobs
                WHERE organization_id = ? AND scan_run_id = ?
                ORDER BY created_at ASC
                """,
                (organization_id, scan_run_id),
            ).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()


def claim_scanner_job_atomically(
    organization_id: str,
    agent_id: str,
    supported_scanners: List[str],
    scan_run_id: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    """
    Race-safe atomic job claim.
    Finds the oldest QUEUED job matching agent's organization and supported scanners.
    Transitions status to CLAIMED and assigns agent_id.
    """
    ts = datetime.now(timezone.utc).isoformat()
    scanners_upper = [s.upper() for s in supported_scanners]
    if not scanners_upper:
        return None

    placeholders = ",".join("?" for _ in scanners_upper)
    params = [organization_id] + scanners_upper

    run_clause = ""
    if scan_run_id:
        run_clause = " AND scan_run_id = ?"
        params.append(scan_run_id)

    with _lock:
        conn = _get_conn()
        try:
            query = f"""
                SELECT scanner_job_id FROM scanner_jobs
                WHERE organization_id = ? AND status = 'QUEUED' AND scanner IN ({placeholders}){run_clause}
                ORDER BY created_at ASC LIMIT 1
            """
            row = conn.execute(query, params).fetchone()
            if not row:
                return None

            job_id = row["scanner_job_id"]

            cur = conn.execute(
                """
                UPDATE scanner_jobs
                SET status = 'CLAIMED', agent_id = ?, claimed_at = ?
                WHERE scanner_job_id = ? AND status = 'QUEUED'
                """,
                (agent_id, ts, job_id),
            )
            conn.commit()

            if cur.rowcount == 1:
                job_row = conn.execute("SELECT * FROM scanner_jobs WHERE scanner_job_id = ?", (job_id,)).fetchone()
                return dict(job_row) if job_row else None
            return None
        finally:
            conn.close()


def update_scanner_job_status(
    scanner_job_id: str,
    status: str,
    error_code: Optional[str] = None,
    error_message: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    """Update scanner job status and timestamps."""
    ts = datetime.now(timezone.utc).isoformat()
    with _lock:
        conn = _get_conn()
        try:
            if status == "RUNNING":
                conn.execute(
                    "UPDATE scanner_jobs SET status = 'RUNNING', started_at = ? WHERE scanner_job_id = ?",
                    (ts, scanner_job_id),
                )
            elif status == "COMPLETED":
                conn.execute(
                    "UPDATE scanner_jobs SET status = 'COMPLETED', completed_at = ? WHERE scanner_job_id = ?",
                    (ts, scanner_job_id),
                )
            elif status == "FAILED":
                conn.execute(
                    """
                    UPDATE scanner_jobs
                    SET status = 'FAILED', failed_at = ?, error_code = ?, error_message = ?
                    WHERE scanner_job_id = ?
                    """,
                    (ts, error_code, error_message, scanner_job_id),
                )
            elif status in ("UPLOADING", "CANCELLED"):
                conn.execute(
                    "UPDATE scanner_jobs SET status = ? WHERE scanner_job_id = ?",
                    (status, scanner_job_id),
                )
            conn.commit()
            row = conn.execute("SELECT * FROM scanner_jobs WHERE scanner_job_id = ?", (scanner_job_id,)).fetchone()
            return dict(row) if row else None
        finally:
            conn.close()


def cancel_jobs_for_scan_run(organization_id: str, scan_run_id: str) -> None:
    """Cancel all pending/running jobs for a scan run."""
    ts = datetime.now(timezone.utc).isoformat()
    with _lock:
        conn = _get_conn()
        try:
            conn.execute(
                """
                UPDATE scanner_jobs
                SET status = 'CANCELLED', failed_at = ?, error_code = 'USER_CANCELLED', error_message = 'Scan run cancelled by user.'
                WHERE organization_id = ? AND scan_run_id = ? AND status IN ('QUEUED', 'CLAIMED', 'RUNNING', 'UPLOADING')
                """,
                (ts, organization_id, scan_run_id),
            )
            conn.commit()
        finally:
            conn.close()


# ═══════════════════════════════════════════════════════════════
# Phase 7 CRUD — Remediation Tickets & Tasks
# ═══════════════════════════════════════════════════════════════

def create_remediation_ticket(
    ticket_id: str,
    organization_id: str,
    finding_id: str,
    cve_id: Optional[str],
    asset_id: str,
    asset_name: str,
    vulnerability_name: str,
    risk_score: int,
    priority: str,
    sla_hours: int,
    discovered_at: str,
    due_at: str,
    status: str = "OPEN",
    assigned_to: Optional[str] = None,
    created_by: str = "system",
) -> Dict[str, Any]:
    """
    Idempotently insert a new remediation ticket for a finding within an organization.
    If a ticket already exists for (organization_id, finding_id), returns the existing ticket unchanged.
    """
    ts = datetime.now(timezone.utc).isoformat()
    with _lock:
        conn = _get_conn()
        try:
            # Check for existing ticket
            existing = conn.execute(
                "SELECT * FROM tickets WHERE organization_id = ? AND finding_id = ?",
                (organization_id, finding_id),
            ).fetchone()
            if existing:
                return dict(existing)

            conn.execute(
                """
                INSERT INTO tickets
                  (ticket_id, organization_id, finding_id, cve_id, asset_id, asset_name,
                   vulnerability_name, risk_score, priority, sla_hours, discovered_at,
                   due_at, status, assigned_to, created_at, updated_at, resolved_at, external_refs)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, '{}')
                """,
                (
                    ticket_id, organization_id, finding_id, cve_id, asset_id, asset_name,
                    vulnerability_name, risk_score, priority, sla_hours, discovered_at,
                    due_at, status, assigned_to, ts, ts
                ),
            )

            # Record genesis history event
            conn.execute(
                """
                INSERT INTO ticket_history
                  (ticket_id, organization_id, old_status, new_status, note, changed_by, changed_at)
                VALUES (?, ?, NULL, ?, 'Ticket generated by remediation engine', ?, ?)
                """,
                (ticket_id, organization_id, status, created_by, ts),
            )
            conn.commit()

            row = conn.execute("SELECT * FROM tickets WHERE ticket_id = ?", (ticket_id,)).fetchone()
            return dict(row) if row else {}
        finally:
            conn.close()


def get_remediation_ticket(organization_id: str, ticket_id: str) -> Optional[Dict[str, Any]]:
    """Retrieve ticket by ticket_id scoped strictly to organization_id."""
    with _lock:
        conn = _get_conn()
        try:
            row = conn.execute(
                "SELECT * FROM tickets WHERE ticket_id = ? AND organization_id = ?",
                (ticket_id, organization_id),
            ).fetchone()
            return dict(row) if row else None
        finally:
            conn.close()


def get_remediation_ticket_by_finding_id(organization_id: str, finding_id: str) -> Optional[Dict[str, Any]]:
    """Retrieve ticket by finding_id scoped strictly to organization_id."""
    with _lock:
        conn = _get_conn()
        try:
            row = conn.execute(
                "SELECT * FROM tickets WHERE finding_id = ? AND organization_id = ?",
                (finding_id, organization_id),
            ).fetchone()
            return dict(row) if row else None
        finally:
            conn.close()


def list_remediation_tickets(
    organization_id: str,
    status: Optional[str] = None,
    priority: Optional[str] = None,
    limit: int = 100,
) -> List[Dict[str, Any]]:
    """List remediation tickets scoped to organization_id ordered by due_at ascending."""
    query = "SELECT * FROM tickets WHERE organization_id = ?"
    params: List[Any] = [organization_id]
    if status:
        query += " AND status = ?"
        params.append(status.upper())
    if priority:
        query += " AND priority = ?"
        params.append(priority.upper())
    query += " ORDER BY due_at ASC LIMIT ?"
    params.append(limit)

    with _lock:
        conn = _get_conn()
        try:
            rows = conn.execute(query, params).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()


def update_remediation_ticket_status(
    organization_id: str,
    ticket_id: str,
    new_status: str,
    note: str = "",
    changed_by: str = "system",
) -> Optional[Dict[str, Any]]:
    """Transition ticket status with history recording. Enforces tenant boundary."""
    ts = datetime.now(timezone.utc).isoformat()
    clean_status = new_status.upper()
    resolved_at = ts if clean_status == "RESOLVED" else None

    with _lock:
        conn = _get_conn()
        try:
            ticket = conn.execute(
                "SELECT * FROM tickets WHERE ticket_id = ? AND organization_id = ?",
                (ticket_id, organization_id),
            ).fetchone()
            if not ticket:
                return None

            old_status = ticket["status"]
            conn.execute(
                """
                UPDATE tickets
                SET status = ?, updated_at = ?, resolved_at = COALESCE(?, resolved_at)
                WHERE ticket_id = ? AND organization_id = ?
                """,
                (clean_status, ts, resolved_at, ticket_id, organization_id),
            )

            conn.execute(
                """
                INSERT INTO ticket_history
                  (ticket_id, organization_id, old_status, new_status, note, changed_by, changed_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (ticket_id, organization_id, old_status, clean_status, note, changed_by, ts),
            )
            conn.commit()

            updated = conn.execute(
                "SELECT * FROM tickets WHERE ticket_id = ?", (ticket_id,)
            ).fetchone()
            return dict(updated) if updated else None
        finally:
            conn.close()


VERIFIED_ORGS_TEAMS = {
    "secops": ("SOC Operations Team", "TEAM"),
    "appsec-team": ("Application Security Team", "TEAM"),
    "payments-infra": ("Payments Infrastructure Team", "TEAM"),
    "dev-lead": ("Development Lead", "TEAM"),
    "cloud-eng": ("Cloud Engineering Team", "TEAM"),
}


def resolve_assignee_identity(assignee: str, organization_id: Optional[str] = None) -> Dict[str, str]:
    raw = (assignee or "").strip()
    key = raw.lower()
    org_id = organization_id or "ORG-RIZZOLVE-DEMO"

    # 1. Query organization_teams table in DB
    try:
        conn = _get_conn()
        try:
            team_row = conn.execute(
                "SELECT * FROM organization_teams WHERE organization_id = ? AND LOWER(team_id) = ?",
                (org_id, key)
            ).fetchone()
            if team_row:
                if not team_row["is_active"]:
                    raise ValueError(f"Team '{key}' is inactive in organization {org_id}")
                return {
                    "assignee_id": team_row["team_id"],
                    "assignee_display_name": team_row["display_name"],
                    "assignee_type": "TEAM"
                }
        finally:
            conn.close()
    except ValueError:
        raise
    except Exception:
        pass

    # 2. Fallback to verified dictionary if pre-init
    if key in VERIFIED_ORGS_TEAMS:
        display_name, assignee_type = VERIFIED_ORGS_TEAMS[key]
        return {"assignee_id": key, "assignee_display_name": display_name, "assignee_type": assignee_type}

    # 3. Check if user email / id
    try:
        from users import get_user_by_email, get_user_by_id
        u = get_user_by_email(raw) or get_user_by_id(raw)
        if u:
            return {"assignee_id": u.user_id, "assignee_display_name": u.display_name, "assignee_type": "USER"}
    except Exception:
        pass

    return {"assignee_id": raw, "assignee_display_name": f"External ({raw})" if raw else "Unassigned", "assignee_type": "EXTERNAL"}


def assign_remediation_ticket(
    organization_id: str,
    ticket_id: str,
    assignee: str,
    changed_by: str = "system",
) -> Optional[Dict[str, Any]]:
    """Assign an owner to a remediation ticket and auto-advance OPEN -> ASSIGNED idempotently."""
    ts = datetime.now(timezone.utc).isoformat()
    clean_assignee = (assignee or "").strip()
    ident = resolve_assignee_identity(clean_assignee, organization_id)

    with _lock:
        conn = _get_conn()
        try:
            ticket = conn.execute(
                "SELECT * FROM tickets WHERE ticket_id = ? AND organization_id = ?",
                (ticket_id, organization_id),
            ).fetchone()
            if not ticket:
                return None

            if ticket["assigned_to"] == clean_assignee:
                # Idempotent: already assigned to this exact assignee
                if not ticket["assignee_display_name"] and ident["assignee_display_name"]:
                    conn.execute(
                        "UPDATE tickets SET assignee_type = ?, assignee_display_name = ? WHERE ticket_id = ? AND organization_id = ?",
                        (ident["assignee_type"], ident["assignee_display_name"], ticket_id, organization_id)
                    )
                    conn.commit()
                    ticket = conn.execute(
                        "SELECT * FROM tickets WHERE ticket_id = ? AND organization_id = ?",
                        (ticket_id, organization_id),
                    ).fetchone()
                return dict(ticket)

            old_status = ticket["status"]
            new_status = "ASSIGNED" if old_status == "OPEN" else old_status

            conn.execute(
                """
                UPDATE tickets
                SET assigned_to = ?, assignee_type = ?, assignee_display_name = ?, status = ?, updated_at = ?
                WHERE ticket_id = ? AND organization_id = ?
                """,
                (clean_assignee, ident["assignee_type"], ident["assignee_display_name"], new_status, ts, ticket_id, organization_id),
            )

            conn.execute(
                """
                INSERT INTO ticket_history
                  (ticket_id, organization_id, old_status, new_status, note, changed_by, changed_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (ticket_id, organization_id, old_status, new_status, f"Assigned to {ident['assignee_display_name']} ({clean_assignee})", changed_by, ts),
            )
            conn.commit()

            updated = conn.execute(
                "SELECT * FROM tickets WHERE ticket_id = ?", (ticket_id,)
            ).fetchone()
            return dict(updated) if updated else None
        finally:
            conn.close()


DEFAULT_CHECKLIST_STEPS = [
    {
        "step_id": "step-1",
        "title": "Upgrade Log4j to >= 2.17.1 (Vendor Patch)",
        "description": "Apply vendor security update or replace log4j-core JAR in deployment pipeline.",
        "status": "COMPLETED",
        "completed_by": "secops [SOC Operations Team]",
        "completed_at": "2026-08-26T16:00:00Z"
    },
    {
        "step_id": "step-2",
        "title": "Deploy WAF Virtual Patching Rule",
        "description": "Block incoming JNDI lookup strings (${jndi:ldap, ${jndi:rmi) at edge reverse proxy.",
        "status": "IN_PROGRESS",
        "completed_by": None,
        "completed_at": None
    },
    {
        "step_id": "step-3",
        "title": "Set -Dlog4j2.formatMsgNoLookups=true in JVM args",
        "description": "Disable message lookup pattern evaluation across payment service JVM clusters.",
        "status": "IN_PROGRESS",
        "completed_by": None,
        "completed_at": None
    },
    {
        "step_id": "step-4",
        "title": "Execute Post-Remediation Dynamic Verification Scan",
        "description": "Run Nuclei CVE-2021-44228 template verification to confirm closure before resolving task.",
        "status": "NOT_STARTED",
        "completed_by": None,
        "completed_at": None
    }
]


def get_remediation_checklist(organization_id: str, ticket_id: str) -> List[Dict[str, Any]]:
    """Retrieve tracked checklist steps for a ticket."""
    import json
    with _lock:
        conn = _get_conn()
        try:
            ticket = conn.execute(
                "SELECT checklist_json FROM tickets WHERE ticket_id = ? AND organization_id = ?",
                (ticket_id, organization_id),
            ).fetchone()
            if not ticket:
                return []
            raw = ticket["checklist_json"]
            steps = json.loads(raw) if raw and raw != "[]" else []
            if not steps:
                steps = list(DEFAULT_CHECKLIST_STEPS)
            return steps
        finally:
            conn.close()


def update_remediation_checklist_step(
    organization_id: str,
    ticket_id: str,
    step_id: str,
    new_status: str,
    actor_name: str = "Analyst",
    actor_role: str = "ANALYST",
) -> List[Dict[str, Any]]:
    """Update a specific checklist step status and persist to SQLite."""
    import json
    ts = datetime.now(timezone.utc).isoformat()
    clean_status = new_status.upper()

    with _lock:
        conn = _get_conn()
        try:
            ticket = conn.execute(
                "SELECT checklist_json FROM tickets WHERE ticket_id = ? AND organization_id = ?",
                (ticket_id, organization_id),
            ).fetchone()
            if not ticket:
                raise KeyError(f"Ticket {ticket_id} not found in organization {organization_id}")

            raw = ticket["checklist_json"]
            steps = json.loads(raw) if raw and raw != "[]" else list(DEFAULT_CHECKLIST_STEPS)

            found = False
            for step in steps:
                if step.get("step_id") == step_id:
                    step["status"] = clean_status
                    if clean_status == "COMPLETED":
                        step["completed_by"] = f"{actor_name} [{actor_role}]"
                        step["completed_at"] = ts
                    elif clean_status == "NOT_STARTED":
                        step["completed_by"] = None
                        step["completed_at"] = None
                    found = True
                    break

            if not found:
                raise KeyError(f"Checklist step {step_id} not found on ticket {ticket_id}")

            conn.execute(
                "UPDATE tickets SET checklist_json = ?, updated_at = ? WHERE ticket_id = ? AND organization_id = ?",
                (json.dumps(steps), ts, ticket_id, organization_id),
            )
            conn.commit()
            return steps
        finally:
            conn.close()


def get_remediation_ticket_history(organization_id: str, ticket_id: str) -> List[Dict[str, Any]]:
    """Get complete audit history for a remediation ticket."""
    with _lock:
        conn = _get_conn()
        try:
            rows = conn.execute(
                """
                SELECT old_status, new_status, note, changed_by, changed_at
                FROM ticket_history
                WHERE ticket_id = ? AND organization_id = ?
                ORDER BY id ASC
                """,
                (ticket_id, organization_id),
            ).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()


def set_remediation_ticket_external_ref(
    organization_id: str,
    ticket_id: str,
    system_name: str,
    ref: str,
) -> Optional[Dict[str, Any]]:
    """Record an external reference (e.g. Jira issue key or GitHub issue URL) on a ticket."""
    import json
    with _lock:
        conn = _get_conn()
        try:
            ticket = conn.execute(
                "SELECT * FROM tickets WHERE ticket_id = ? AND organization_id = ?",
                (ticket_id, organization_id),
            ).fetchone()
            if not ticket:
                return None

            refs = json.loads(ticket["external_refs"] or "{}")
            refs[system_name] = ref
            ts = datetime.now(timezone.utc).isoformat()

            conn.execute(
                """
                UPDATE tickets
                SET external_refs = ?, updated_at = ?
                WHERE ticket_id = ? AND organization_id = ?
                """,
                (json.dumps(refs), ts, ticket_id, organization_id),
            )
            conn.commit()

            updated = conn.execute(
                "SELECT * FROM tickets WHERE ticket_id = ?", (ticket_id,)
            ).fetchone()
            return dict(updated) if updated else None
        finally:
            conn.close()


