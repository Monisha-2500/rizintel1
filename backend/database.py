"""
database.py — SQLite Tamper-Evident Audit Trail for RizIntel Analyst Decisions

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
import os
from datetime import datetime, timezone
from threading import Lock
from typing import List, Dict, Optional, Any

DB_PATH = os.getenv("RIZINTEL_DB_PATH", os.path.join(os.path.dirname(__file__), "data", "audit_trail.db"))

# Ensure data directory exists
os.makedirs(os.path.dirname(os.path.abspath(DB_PATH)), exist_ok=True)

_lock = Lock()


def _get_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Create the audit_trail table if it does not already exist."""
    with _lock:
        conn = _get_conn()
        try:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS audit_trail (
                    id             INTEGER PRIMARY KEY AUTOINCREMENT,
                    finding_id     TEXT    NOT NULL,
                    m5_risk_score  INTEGER NOT NULL,
                    analyst_action TEXT    NOT NULL,
                    rationale      TEXT    DEFAULT '',
                    role           TEXT    NOT NULL DEFAULT 'security_analyst',
                    timestamp      TEXT    NOT NULL,
                    previous_hash  TEXT    NOT NULL,
                    event_hash     TEXT    NOT NULL UNIQUE
                )
            """)
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
) -> str:
    """SHA-256 of all immutable event fields concatenated with '|'."""
    raw = "|".join([
        str(finding_id).strip(),
        str(m5_risk_score),
        str(analyst_action).strip(),
        str(rationale or "").strip(),
        str(role or "security_analyst").strip(),
        str(timestamp).strip(),
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
                clean_finding_id, clean_m5, clean_action,
                clean_rationale, clean_role, clean_timestamp, previous_hash
            )

            conn.execute(
                """
                INSERT INTO audit_trail
                  (finding_id, m5_risk_score, analyst_action, rationale,
                   role, timestamp, previous_hash, event_hash)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (clean_finding_id, clean_m5, clean_action, clean_rationale,
                 clean_role, clean_timestamp, previous_hash, event_hash),
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


# Initialise database table on module load
init_db()


