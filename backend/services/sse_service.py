"""
sse_service.py — Phase 3 Server-Sent Events delivery for ScanRun live operations.

Source of truth is persisted Phase 2 tables (scan_run_events, scanner_submissions,
scan_runs). This module does NOT invent pipeline stages, timers, or mock scanner
events. It only:
  1. Authenticates the subscriber (Bearer JWT or short-lived stream token).
  2. Replays missed persisted events after Last-Event-ID.
  3. Polls the ledger at a bounded interval and streams new rows.
  4. Emits lightweight heartbeats (connection health only).

Enterprise scale: replace the poll loop with Redis Pub/Sub (or another broker)
publishing scan_run_id channels after insert_scan_run_event, while keeping
SQLite/Postgres as the replay log for reconnect.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, AsyncIterator, Dict, List, Optional

from fastapi import HTTPException, Request, status

from auth import AuthenticatedUser, decode_access_token, get_display_title_for_role
from database import (
    get_scan_run,
    get_scan_run_results,
    get_sse_stream_token,
    consume_sse_stream_token,
    issue_sse_stream_token,
    list_scan_run_events_after,
    list_submissions_for_run,
)
from users import UserRole, get_user_by_email, get_user_by_id

logger = logging.getLogger("rizintel.sse")

SSE_POLL_SECONDS = float(os.getenv("RIZINTEL_SSE_POLL_SECONDS", "0.4"))
SSE_HEARTBEAT_SECONDS = float(os.getenv("RIZINTEL_SSE_HEARTBEAT_SECONDS", "15"))
SSE_STREAM_TOKEN_TTL_SECONDS = int(os.getenv("RIZINTEL_SSE_STREAM_TOKEN_TTL", "90"))
SSE_BATCH_LIMIT = 100

SCANNER_EVENT_TYPES = {
    "SCANNER_UPLOAD_STARTED",
    "SCANNER_REPORT_RECEIVED",
    "SCANNER_PARSE_COMPLETED",
    "SCANNER_PARSE_FAILED",
}

PIPELINE_EVENT_TYPES = {
    "PROCESSING_STARTED",
    "NORMALIZATION_STARTED",
    "NORMALIZATION_COMPLETED",
    "DEDUPLICATION_COMPLETED",
    "CONFIDENCE_COMPLETED",
    "THREAT_ENRICHMENT_COMPLETED",
    "RISK_SCORING_COMPLETED",
    "EXPLANATION_COMPLETED",
    "SLA_COMPLETED",
}

STAGE_LABELS = {
    "SCANNER_UPLOAD_STARTED": "Receiving scanner report",
    "SCANNER_REPORT_RECEIVED": "Scanner report received",
    "SCANNER_PARSE_COMPLETED": "Scanner parse completed",
    "SCANNER_PARSE_FAILED": "Scanner parse failed",
    "PROCESSING_STARTED": "Pipeline processing started",
    "NORMALIZATION_STARTED": "Normalization started",
    "NORMALIZATION_COMPLETED": "Normalization completed",
    "DEDUPLICATION_COMPLETED": "Deduplication completed",
    "CONFIDENCE_COMPLETED": "Confidence evaluation completed",
    "THREAT_ENRICHMENT_COMPLETED": "Threat intelligence completed",
    "RISK_SCORING_COMPLETED": "Risk scoring completed",
    "EXPLANATION_COMPLETED": "Explanation completed",
    "SLA_COMPLETED": "SLA completed",
    "SCAN_COMPLETED": "Scan run completed",
    "SCAN_FAILED": "Scan run failed",
    "SCAN_CANCELLED": "Scan run cancelled",
}


def _parse_json(value: Any, default: Any) -> Any:
    if value is None:
        return default
    if isinstance(value, (dict, list)):
        return value
    if isinstance(value, str):
        try:
            return json.loads(value)
        except (ValueError, TypeError):
            return default
    return default


def classify_sse_type(event_type: str) -> str:
    if event_type in SCANNER_EVENT_TYPES:
        return "scanner_status"
    if event_type in PIPELINE_EVENT_TYPES:
        return "pipeline_stage"
    if event_type == "SCAN_COMPLETED":
        return "completed"
    if event_type == "SCAN_FAILED":
        return "failed"
    if event_type in ("SCAN_CANCELLED",):
        return "scan_run"
    return "scan_run"


def _hash_stream_token(raw_token: str) -> str:
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


def create_stream_token(user_id: str, organization_id: str, scan_run_id: str) -> Dict[str, Any]:
    raw = secrets.token_urlsafe(32)
    expires = datetime.now(timezone.utc) + timedelta(seconds=SSE_STREAM_TOKEN_TTL_SECONDS)
    issue_sse_stream_token(
        token_hash=_hash_stream_token(raw),
        user_id=user_id,
        organization_id=organization_id,
        scan_run_id=scan_run_id,
        expires_at=expires.isoformat(),
    )
    return {
        "stream_token": raw,
        "expires_in": SSE_STREAM_TOKEN_TTL_SECONDS,
        "organization_id": organization_id,
        "scan_run_id": scan_run_id,
        "auth_model": "short_lived_stream_token",
    }


def authenticate_sse_user(
    authorization: Optional[str],
    stream_token: Optional[str],
    organization_id: str,
    scan_run_id: str,
) -> AuthenticatedUser:
    """
    SSE auth model (in order):
      1. Authorization: Bearer <JWT> — same as all other v1 APIs (preferred; used by fetch()).
      2. stream_token query param — 90s token issued by POST .../stream-token, bound to
         this user + organization + scan_run. Never a long-lived JWT.
    """
    if authorization:
        parts = authorization.strip().split()
        if len(parts) != 2 or parts[0].lower() != "bearer":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid Authorization header format. Expected 'Bearer <token>'.",
                headers={"WWW-Authenticate": "Bearer"},
            )
        payload = decode_access_token(parts[1])
        user_id = payload.get("sub")
        user = get_user_by_id(user_id) if user_id else None
        if not user:
            user = get_user_by_email(payload.get("email", ""))
        if not user or not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication required. Please provide a valid Bearer token.",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return AuthenticatedUser(
            user_id=user.user_id,
            username=user.email,
            email=user.email,
            display_name=user.display_name,
            role=user.role,
            display_title=get_display_title_for_role(user.role),
        )

    if stream_token:
        rec = consume_sse_stream_token(_hash_stream_token(stream_token))
        if rec:
            if rec["organization_id"] != organization_id or rec["scan_run_id"] != scan_run_id:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Stream token is not valid for this scan run or organization.",
                )
            user = get_user_by_id(rec["user_id"])
            if not user or not user.is_active:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Authenticated user no longer exists.",
                )
            return AuthenticatedUser(
                user_id=user.user_id,
                username=user.email,
                email=user.email,
                display_name=user.display_name,
                role=user.role if isinstance(user.role, UserRole) else UserRole(user.role),
                display_title=get_display_title_for_role(
                    user.role if isinstance(user.role, UserRole) else UserRole(user.role)
                ),
            )

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Stream token is missing, expired, invalid, or already consumed.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Authentication required. Provide Bearer JWT in Authorization header or single-use stream_token.",
        headers={"WWW-Authenticate": "Bearer"},
    )


def derive_counts(
    events: List[Dict[str, Any]],
    submissions: List[Dict[str, Any]],
    results: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    """Return only counts that exist in persisted submissions/events/results."""
    counts: Dict[str, Any] = {}

    if submissions:
        raw_total = sum(int(s.get("raw_finding_count") or 0) for s in submissions)
        counts["raw_signals"] = raw_total

    for ev in events:
        meta = _parse_json(ev.get("metadata_json"), {})
        et = ev.get("event_type")
        if et == "NORMALIZATION_COMPLETED" and isinstance(meta, dict) and "raw_count" in meta:
            counts["normalized"] = meta["raw_count"]
        if et == "DEDUPLICATION_COMPLETED" and isinstance(meta, dict) and "canonical_count" in meta:
            counts["canonical"] = meta["canonical_count"]
        if et == "SCAN_COMPLETED" and isinstance(meta, dict):
            if "raw_finding_count" in meta:
                counts["raw_signals"] = meta["raw_finding_count"]
            if "canonical_finding_count" in meta:
                counts["canonical"] = meta["canonical_finding_count"]
            nested = meta.get("pipeline_summary") or {}
            inner = nested.get("summary") if isinstance(nested, dict) else None
            if isinstance(inner, dict):
                if "raw_findings" in inner:
                    counts["raw_signals"] = inner["raw_findings"]
                    counts["normalized"] = inner["raw_findings"]
                if "unique_findings" in inner:
                    counts["canonical"] = inner["unique_findings"]
                if "duplicates_correlated" in inner:
                    counts["duplicates_correlated"] = inner["duplicates_correlated"]
                if "actionable_findings" in inner:
                    counts["confirmed"] = inner["actionable_findings"]
                if "pending_review_findings" in inner:
                    counts["needs_review"] = inner["pending_review_findings"]
                if "likely_noise_findings" in inner:
                    counts["suppressed"] = inner["likely_noise_findings"]

    if "raw_signals" in counts and "canonical" in counts and "duplicates_correlated" not in counts:
        counts["duplicates_correlated"] = max(0, int(counts["raw_signals"]) - int(counts["canonical"]))

    if results:
        if results.get("raw_finding_count") is not None:
            counts.setdefault("raw_signals", results["raw_finding_count"])
        if results.get("canonical_finding_count") is not None:
            counts.setdefault("canonical", results["canonical_finding_count"])
        summary = _parse_json(results.get("summary_json"), {})
        inner = summary.get("pipeline_summary", {}).get("summary") if isinstance(summary, dict) else None
        if isinstance(inner, dict):
            if "actionable_findings" in inner:
                counts.setdefault("confirmed", inner["actionable_findings"])
            if "pending_review_findings" in inner:
                counts.setdefault("needs_review", inner["pending_review_findings"])
            if "likely_noise_findings" in inner:
                counts.setdefault("suppressed", inner["likely_noise_findings"])
            if "duplicates_correlated" in inner:
                counts.setdefault("duplicates_correlated", inner["duplicates_correlated"])

    return counts


def scanner_cards_from_state(
    scan_run: Dict[str, Any],
    submissions: List[Dict[str, Any]],
    events: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    selections = _parse_json(scan_run.get("scanner_selections"), [])
    by_scanner = {str(s.get("scanner", "")).upper(): s for s in submissions}
    failed = {str(s.get("scanner", "")).upper() for s in submissions if s.get("processing_status") == "FAILED"}

    latest_scanner_event: Dict[str, str] = {}
    for ev in events:
        meta = _parse_json(ev.get("metadata_json"), {})
        scanner = None
        if isinstance(meta, dict):
            scanner = meta.get("scanner")
        if not scanner and ev.get("event_type") in SCANNER_EVENT_TYPES:
            msg = ev.get("message") or ""
            for name in ("ZAP", "NUCLEI", "WAPITI"):
                if name in msg.upper():
                    scanner = name
                    break
        if scanner:
            latest_scanner_event[str(scanner).upper()] = ev.get("event_type")

    cards = []
    for name in selections:
        key = str(name).upper()
        sub = by_scanner.get(key)
        status = "PENDING"
        if sub:
            ps = (sub.get("processing_status") or "").upper()
            if ps == "TARGET_REVIEW_REQUIRED":
                status = "TARGET_REVIEW_REQUIRED"
            elif ps in ("FAILED", "PARSE_FAILED"):
                status = "FAILED"
            elif ps in ("PARSED", "RECEIVED", "PARSED_UNKNOWN_TARGET"):
                status = "RECEIVED"
            else:
                status = ps or "RECEIVED"
        elif latest_scanner_event.get(key) == "SCANNER_UPLOAD_STARTED":
            status = "RECEIVING"
        elif latest_scanner_event.get(key) == "SCANNER_PARSE_FAILED" or key in failed:
            status = "FAILED"

        card = {
            "scanner": key,
            "status": status,
        }
        if sub:
            card["raw_finding_count"] = sub.get("raw_finding_count")
            card["received_at"] = sub.get("received_at")
            card["processing_status"] = sub.get("processing_status")
            if sub.get("error_message"):
                card["error_message"] = sub.get("error_message")
        cards.append(card)
    return cards


def build_snapshot(organization_id: str, scan_run_id: str) -> Dict[str, Any]:
    run = get_scan_run(organization_id, scan_run_id) or {}
    submissions = list_submissions_for_run(organization_id, scan_run_id)
    events = list_scan_run_events_after(organization_id, scan_run_id, after_event_id=None, limit=5000)
    results = get_scan_run_results(organization_id, scan_run_id)
    return {
        "scan_run_id": scan_run_id,
        "organization_id": organization_id,
        "status": run.get("status"),
        "asset_id": run.get("asset_id"),
        "created_by_user_id": run.get("created_by_user_id"),
        "scanner_selections": _parse_json(run.get("scanner_selections"), []),
        "received_scanners": _parse_json(run.get("received_scanners"), []),
        "pending_scanners": _parse_json(run.get("pending_scanners"), []),
        "failed_scanners": _parse_json(run.get("failed_scanners"), []),
        "scanners": scanner_cards_from_state(run, submissions, events),
        "counts": derive_counts(events, submissions, results),
        "command_center_ready": run.get("status") == "COMPLETED",
    }


def format_sse(event_name: str, payload: Dict[str, Any], event_id: Optional[str] = None) -> str:
    chunks = []
    if event_id:
        chunks.append(f"id: {event_id}")
    chunks.append(f"event: {event_name}")
    chunks.append(f"data: {json.dumps(payload, default=str)}")
    return "\n".join(chunks) + "\n\n"


def envelope_from_persisted_event(row: Dict[str, Any], snapshot: Dict[str, Any]) -> Dict[str, Any]:
    event_type = row.get("event_type")
    meta = _parse_json(row.get("metadata_json"), {})
    return {
        "sse_type": classify_sse_type(event_type),
        "event_id": row.get("event_id"),
        "seq": row.get("seq"),
        "organization_id": row.get("organization_id"),
        "scan_run_id": row.get("scan_run_id"),
        "event_type": event_type,
        "stage": row.get("stage"),
        "status": row.get("status"),
        "message": row.get("message"),
        "label": STAGE_LABELS.get(event_type, event_type),
        "metadata": meta if isinstance(meta, dict) else {},
        "created_at": row.get("created_at"),
        "snapshot": snapshot,
    }


async def scan_run_sse_generator(
    request: Request,
    organization_id: str,
    scan_run_id: str,
    last_event_id: Optional[str],
) -> AsyncIterator[str]:
    """
    Poll persisted scan_run_events with a sleep interval (prototype-safe).
    Disconnects are detected via request.is_disconnected(); no busy loop.
    """
    cursor = last_event_id
    last_heartbeat = asyncio.get_event_loop().time()
    snapshot = build_snapshot(organization_id, scan_run_id)
    yield format_sse(
        "scan_run",
        {
            "sse_type": "scan_run",
            "event_id": None,
            "event_type": "SNAPSHOT",
            "scan_run_id": scan_run_id,
            "organization_id": organization_id,
            "message": "Live stream connected",
            "snapshot": snapshot,
            "created_at": datetime.now(timezone.utc).isoformat(),
        },
    )

    try:
        while True:
            if await request.is_disconnected():
                logger.debug("SSE client disconnected org=%s run=%s", organization_id, scan_run_id)
                break

            batch = list_scan_run_events_after(
                organization_id, scan_run_id, after_event_id=cursor, limit=SSE_BATCH_LIMIT
            )
            if batch:
                snapshot = build_snapshot(organization_id, scan_run_id)
                for row in batch:
                    env = envelope_from_persisted_event(row, snapshot)
                    yield format_sse(env["sse_type"], env, event_id=row.get("event_id"))
                    cursor = row.get("event_id")

            now = asyncio.get_event_loop().time()
            if now - last_heartbeat >= SSE_HEARTBEAT_SECONDS:
                last_heartbeat = now
                yield format_sse(
                    "heartbeat",
                    {
                        "sse_type": "heartbeat",
                        "ts": datetime.now(timezone.utc).isoformat(),
                        "scan_run_id": scan_run_id,
                    },
                )
                yield ": keepalive\n\n"

            await asyncio.sleep(SSE_POLL_SECONDS)
    except asyncio.CancelledError:
        logger.debug("SSE generator cancelled org=%s run=%s", organization_id, scan_run_id)
        raise
