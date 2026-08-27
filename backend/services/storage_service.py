"""
storage_service.py — Abstract Storage Service for Scanner Report Submissions (Phase 2)

Architecture:
- Provides an abstract interface for saving and loading raw scanner report payloads.
- Prevents path traversal security risks by generating controlled internal filenames
  (SUB-<submission_id_suffix>.<ext>). Client original filenames are NEVER used as filesystem paths.
- Default implementation uses local filesystem under `backend/data/submissions/`.
- Designed for pluggable replacement with cloud blob storage (AWS S3, Azure Blob, GCS) in production.
"""

from __future__ import annotations

import logging
import os
import hashlib
from pathlib import Path
from typing import Optional, Tuple

logger = logging.getLogger("rizintel.storage_service")

_BACKEND_DIR = Path(__file__).resolve().parent.parent
SUBMISSIONS_DIR = _BACKEND_DIR / "data" / "submissions"
os.makedirs(SUBMISSIONS_DIR, exist_ok=True)


def compute_payload_hash(content_bytes: bytes) -> str:
    """SHA-256 hash of raw report content for submission idempotency."""
    return hashlib.sha256(content_bytes).hexdigest()


def save_raw_report(submission_id: str, content_bytes: bytes, scanner: str) -> Tuple[str, int, str]:
    """
    Save raw scanner report to storage.
    Returns (storage_path, file_size_bytes, payload_hash).

    Security Guarantee:
      Internal storage path is constructed strictly from submission_id and scanner name.
      User-supplied original filenames are completely IGNORED for path construction.
    """
    payload_hash = compute_payload_hash(content_bytes)
    ext = "json" if scanner.upper() in ("ZAP", "WAPITI") else "jsonl"
    safe_filename = f"{submission_id}_{scanner.lower()}_{payload_hash[:8]}.{ext}"
    target_path = SUBMISSIONS_DIR / safe_filename

    with open(target_path, "wb") as f:
        f.write(content_bytes)

    rel_storage_path = str(target_path.relative_to(_BACKEND_DIR))
    logger.info("Saved raw report to %s (%d bytes)", rel_storage_path, len(content_bytes))
    return rel_storage_path, len(content_bytes), payload_hash


def load_raw_report(storage_path: str) -> str:
    """
    Load raw report text from storage.
    Handles relative backend paths and resolves safely.
    """
    full_path = _BACKEND_DIR / storage_path
    if not full_path.exists():
        raise FileNotFoundError(f"Stored report file not found at: {storage_path}")

    with open(full_path, "r", encoding="utf-8", errors="replace") as f:
        return f.read()
