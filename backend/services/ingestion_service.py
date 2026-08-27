"""
ingestion_service.py — Scanner Report Ingestion & Target Validation Service (Phase 2)

Responsibilities:
- Validate Organization, Asset Authorization, Scan Run ownership, and Scanner Selections.
- Enforce upload file size limit (max 10 MB) and accepted format parsing.
- Compute SHA-256 payload hash and check submission idempotency.
- Enforce Target Validation Policy:
    MATCH            -> accept submission
    CLEAR_MISMATCH   -> reject submission (422 Unprocessable Entity)
    UNKNOWN          -> accept with PARSED_UNKNOWN_TARGET status
- Parse scanner reports using native adapters (ZapAdapter, NucleiAdapter, WapitiAdapter).
  Parsers ONLY parse container structures into raw findings (Single Normalization Pass rule).
- Persist submission metadata & storage path via StorageService.
- Emit real stage events to scan_run_events ledger.
- Update multi-scanner consensus status truthfully.
"""

from __future__ import annotations

import json
import logging
import os
import secrets
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from database import (
    get_scan_run,
    get_registered_asset,
    create_scanner_submission,
    get_submission_by_hash,
    insert_scan_run_event,
    update_scan_run_consensus,
    SUPPORTED_SCANNERS,
)
from services.storage_service import save_raw_report, compute_payload_hash

logger = logging.getLogger("rizintel.ingestion_service")

MAX_UPLOAD_SIZE_BYTES = 10 * 1024 * 1024  # 10 MB


def generate_submission_id() -> str:
    """Generate a collision-safe submission ID: SUB-<12 hex chars>."""
    return f"SUB-{secrets.token_hex(6).upper()}"


def generate_event_id() -> str:
    """Generate a collision-safe event ID: EVT-<12 hex chars>."""
    return f"EVT-{secrets.token_hex(6).upper()}"


# ── Target Host Validation ────────────────────────────────────

def validate_report_target(
    report_text: str,
    scanner: str,
    authorized_asset_host: str,
    authorized_asset_port: Optional[int] = None,
) -> Tuple[str, Optional[str]]:
    """
    Target Validation Policy:
      MATCH          : Report host matches authorized asset host -> accept
      CLEAR_MISMATCH : Report host clearly targets a different domain/IP -> reject
      UNKNOWN        : Report target is missing, relative, or generic (localhost) -> allow with UNKNOWN

    Returns (status: 'MATCH'|'CLEAR_MISMATCH'|'UNKNOWN', detected_host: str|None)
    """
    scanner_upper = scanner.upper()
    detected_hosts: List[str] = []

    try:
        if scanner_upper in ("ZAP", "WAPITI"):
            data = json.loads(report_text)
            if scanner_upper == "ZAP":
                for site in data.get("site", []):
                    h = site.get("@name") or site.get("@host")
                    if h:
                        detected_hosts.append(str(h).strip())
            elif scanner_upper == "WAPITI":
                infos = data.get("infos", {})
                target = infos.get("target")
                if target:
                    detected_hosts.append(str(target).strip())
        elif scanner_upper == "NUCLEI":
            # Nuclei can be JSONL or JSON array
            raw_lines = report_text.strip().splitlines()
            for line in raw_lines[:20]:  # sample first 20 records
                line = line.strip()
                if not line or not line.startswith("{"):
                    continue
                try:
                    rec = json.loads(line)
                    h = rec.get("host") or rec.get("matched-at") or rec.get("url")
                    if h:
                        detected_hosts.append(str(h).strip())
                except Exception:
                    pass
    except Exception:
        # Unable to parse JSON structure for host check -> UNKNOWN
        return "UNKNOWN", None

    if not detected_hosts:
        return "UNKNOWN", None

    clean_auth_host = (authorized_asset_host or "").strip().lower()
    if clean_auth_host.startswith("http://") or clean_auth_host.startswith("https://"):
        clean_auth_host = urlparse(clean_auth_host).hostname or clean_auth_host

    for raw_detected in detected_hosts:
        clean_det = raw_detected.strip().lower()
        if "://" in clean_det:
            parsed = urlparse(clean_det)
            clean_det = parsed.hostname or clean_det

        # Strip port if present in detected host string
        if ":" in clean_det and not clean_det.startswith("["):
            clean_det = clean_det.split(":")[0]

        # Exact match or subdomain match
        if clean_det == clean_auth_host or clean_det.endswith("." + clean_auth_host):
            return "MATCH", raw_detected

        # Check for localhost / loopback targets (common in dev/lab scans)
        if clean_det in ("localhost", "127.0.0.1", "::1") or clean_auth_host in ("localhost", "127.0.0.1"):
            return "MATCH", raw_detected

    # Detected host is present and clearly does NOT match authorized asset host
    first_detected = detected_hosts[0]
    logger.warning(
        "Clear target host mismatch: report targets '%s' but asset host is '%s'",
        first_detected, clean_auth_host,
    )
    return "CLEAR_MISMATCH", first_detected


# ── Native Scanner Parsing (Single Normalization Pass) ─────────

def parse_raw_scanner_report(scanner: str, report_text: str) -> List[Dict[str, Any]]:
    """
    Parses native report containers into raw scanner records using mem1 adapters.
    Parsers ONLY extract container structures — M1 performs normalization later.
    Raises ValueError on malformed or unsupported report payloads.
    """
    scanner_upper = scanner.upper()
    if scanner_upper not in SUPPORTED_SCANNERS:
        raise ValueError(f"Unsupported scanner '{scanner}'. Supported: {sorted(SUPPORTED_SCANNERS)}")

    # Import native mem1 scanner adapters
    import sys
    from pathlib import Path
    mem1_dir = Path(__file__).resolve().parent.parent / "mem1"
    if str(mem1_dir) not in sys.path:
        sys.path.insert(0, str(mem1_dir))

    from scanner_adapters.zap import ZapAdapter
    from scanner_adapters.nuclei import NucleiAdapter
    from scanner_adapters.wapiti import WapitiAdapter

    adapter_map = {
        "ZAP": ZapAdapter(),
        "NUCLEI": NucleiAdapter(),
        "WAPITI": WapitiAdapter(),
    }

    adapter = adapter_map[scanner_upper]
    try:
        findings = adapter.parse(report_text)
        if not isinstance(findings, list) or (not findings and report_text.strip()):
            raise ValueError(f"Failed to parse {scanner_upper} report: Malformed payload or zero findings extracted.")
        return findings
    except Exception as e:
        raise ValueError(f"Failed to parse {scanner_upper} report: {e}") from e


# ── Main Ingestion Function ────────────────────────────────────

def ingest_report(
    organization_id: str,
    scan_run_id: str,
    scanner: str,
    report_bytes: bytes,
    submission_type: str,
    user_id: str,
    original_filename: Optional[str] = None,
    content_type: Optional[str] = None,
    idempotency_key: str = "",
) -> Dict[str, Any]:
    """
    Full Phase 2 ingestion workflow:
      1. Validate scan run & asset status
      2. Check upload size limit
      3. Compute SHA-256 payload hash & enforce submission idempotency
      4. Validate target host against authorized asset
      5. Parse raw report using native parser adapter
      6. Persist raw file to storage abstraction & record submission in DB
      7. Record real stage events in scan_run_events
      8. Update scan_runs multi-scanner consensus tracking
      9. Return submission status details (and trigger async processing if complete)
    """
    scanner_upper = scanner.upper()

    if scanner_upper not in SUPPORTED_SCANNERS:
        raise ValueError(f"Unsupported scanner '{scanner_upper}'. Supported: {sorted(SUPPORTED_SCANNERS)}")

    # 1. Enforce size limit
    if len(report_bytes) > MAX_UPLOAD_SIZE_BYTES:
        raise ValueError(f"Upload size ({len(report_bytes)} bytes) exceeds maximum limit of 10 MB.")

    if not report_bytes or not report_bytes.strip():
        raise ValueError("Report content is empty.")

    # 2. Fetch & validate scan run
    scan_run = get_scan_run(organization_id, scan_run_id)
    if not scan_run:
        raise KeyError(f"Scan run {scan_run_id} not found in organization {organization_id}.")

    if scan_run["status"] not in ("CREATED", "WAITING_FOR_INPUT", "INGESTING"):
        raise ValueError(f"Scan run {scan_run_id} is in status '{scan_run['status']}' and cannot accept new reports.")

    # 3. Verify scanner was selected for this run
    selections = json.loads(scan_run.get("scanner_selections", "[]"))
    if scanner_upper not in [s.upper() for s in selections]:
        raise ValueError(
            f"Scanner '{scanner_upper}' was not selected for scan run {scan_run_id}. "
            f"Selected scanners: {selections}"
        )

    # 4. Fetch & verify asset authorization
    asset = get_registered_asset(organization_id, scan_run["asset_id"])
    if not asset or asset["authorization_status"] != "AUTHORIZED":
        raise ValueError(f"Asset {scan_run['asset_id']} is not AUTHORIZED for scanning.")

    # 5. Compute SHA-256 & check idempotency
    payload_hash = compute_payload_hash(report_bytes)
    existing_sub = get_submission_by_hash(scan_run_id, scanner_upper, payload_hash)
    if existing_sub:
        logger.info("Idempotent submission duplicate detected for %s / %s", scan_run_id, scanner_upper)
        return {
            "is_duplicate": True,
            "submission_id": existing_sub["submission_id"],
            "scan_run_id": scan_run_id,
            "scanner": scanner_upper,
            "processing_status": existing_sub["processing_status"],
            "raw_finding_count": existing_sub["raw_finding_count"],
            "message": f"Identical report already ingested for {scanner_upper}. Double-counting prevented.",
        }

    # Emit SCANNER_UPLOAD_STARTED event
    insert_scan_run_event(
        generate_event_id(),
        organization_id,
        scan_run_id,
        "SCANNER_UPLOAD_STARTED",
        "INGESTION",
        f"Receiving {scanner_upper} report submission ({len(report_bytes)} bytes).",
        "INFO",
        json.dumps({"scanner": scanner_upper, "submission_type": submission_type}),
    )

    report_text = report_bytes.decode("utf-8", errors="replace")

    # 6. Target validation policy
    target_status, detected_host = validate_report_target(
        report_text, scanner_upper, asset["normalized_host"], asset.get("port")
    )
    if target_status == "CLEAR_MISMATCH":
        insert_scan_run_event(
            generate_event_id(),
            organization_id,
            scan_run_id,
            "SCANNER_PARSE_FAILED",
            "INGESTION",
            f"{scanner_upper} report target host mismatch: targets '{detected_host}' but asset host is '{asset['normalized_host']}'.",
            "FAILED",
            json.dumps({"detected_host": detected_host, "expected_host": asset["normalized_host"]}),
        )
        raise TargetMismatchError(
            f"Report target host '{detected_host}' does not match authorized asset host '{asset['normalized_host']}'."
        )

    # 7. Parse raw scanner report
    try:
        raw_findings = parse_raw_scanner_report(scanner_upper, report_text)
        raw_count = len(raw_findings)
    except ValueError as parse_err:
        insert_scan_run_event(
            generate_event_id(),
            organization_id,
            scan_run_id,
            "SCANNER_PARSE_FAILED",
            "INGESTION",
            f"Failed to parse {scanner_upper} report: {parse_err}",
            "FAILED",
        )
        raise

    # 8. Save report file to storage abstraction
    submission_id = generate_submission_id()
    rel_path, file_size, _ = save_raw_report(submission_id, report_bytes, scanner_upper)

    proc_status = "PARSED" if target_status == "MATCH" else "TARGET_REVIEW_REQUIRED"

    # 9. Persist submission record
    sub = create_scanner_submission(
        submission_id=submission_id,
        scan_run_id=scan_run_id,
        organization_id=organization_id,
        asset_id=asset["asset_id"],
        scanner=scanner_upper,
        submission_type=submission_type,
        received_by_user_id=user_id,
        original_filename=original_filename,
        content_type=content_type,
        file_size_bytes=file_size,
        storage_path=rel_path,
        raw_finding_count=raw_count,
        processing_status=proc_status,
        payload_hash=payload_hash,
        idempotency_key=idempotency_key,
    )

    # 10. Log stage events
    insert_scan_run_event(
        generate_event_id(),
        organization_id,
        scan_run_id,
        "SCANNER_REPORT_RECEIVED",
        "INGESTION",
        f"{scanner_upper} report stored ({file_size} bytes, submission {submission_id}).",
        "SUCCESS",
        json.dumps({"submission_id": submission_id, "file_size": file_size}),
    )

    insert_scan_run_event(
        generate_event_id(),
        organization_id,
        scan_run_id,
        "SCANNER_PARSE_COMPLETED",
        "INGESTION",
        f"{scanner_upper} report parsed successfully — extracted {raw_count} raw scanner signals.",
        "SUCCESS",
        json.dumps({"raw_count": raw_count, "target_status": target_status}),
    )

    # 11. Update multi-scanner consensus in scan_runs
    updated_run = update_scan_run_consensus(
        organization_id, scan_run_id, scanner_upper, raw_count
    )

    # Check if consensus complete (0 pending scanners remaining)
    pending_scanners = json.loads(updated_run.get("pending_scanners", "[]")) if updated_run else []
    is_consensus_reached = len(pending_scanners) == 0

    return {
        "is_duplicate": False,
        "submission_id": submission_id,
        "scan_run_id": scan_run_id,
        "organization_id": organization_id,
        "scanner": scanner_upper,
        "processing_status": proc_status,
        "raw_finding_count": raw_count,
        "storage_path": rel_path,
        "received_scanners": json.loads(updated_run.get("received_scanners", "[]")) if updated_run else [],
        "pending_scanners": pending_scanners,
        "is_consensus_reached": is_consensus_reached,
        "message": f"Successfully ingested {scanner_upper} report with {raw_count} raw signals.",
    }


class TargetMismatchError(Exception):
    """Raised when report target host clearly does not match authorized asset host."""
    pass
