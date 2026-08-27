"""
asset_service.py — Registered Asset Registry Service (Phase 1)

Responsibilities:
- Register assets with normalized host/port deduplication per organization.
- Manage authorization states: PENDING -> AUTHORIZED -> DISABLED.
- Produce an AssetResolver-compatible catalog from AUTHORIZED assets.
- Enforce tenant isolation — all lookups scoped by organization_id.

Asset Uniqueness Policy:
  Within a single organization, two ACTIVE (non-DISABLED) assets cannot share
  the same (normalized_host, port) pair.
  The same host:port may exist independently in different organizations without leakage.

Integration with AssetResolver:
  AssetResolver's matching logic is FROZEN. This service produces catalog entries
  matching the schema expected by AssetResolver without altering it.
"""

from __future__ import annotations

import logging
import secrets
import sqlite3
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from database import (
    create_registered_asset,
    get_registered_asset,
    list_registered_assets,
    update_asset_authorization,
    get_authorized_asset_catalog,
)

logger = logging.getLogger("rizintel.asset_service")

VALID_AUTH_STATUSES = frozenset(["PENDING", "AUTHORIZED", "DISABLED"])
VALID_ENVIRONMENTS = frozenset(["production", "staging", "development", "lab"])
VALID_CRITICALITIES = frozenset(["CRITICAL", "HIGH", "MEDIUM", "LOW"])
VALID_SENSITIVITIES = frozenset(["RESTRICTED", "CONFIDENTIAL", "INTERNAL", "PUBLIC"])


def generate_asset_id() -> str:
    """Generate a collision-safe asset ID: ASSET-<10 hex chars>."""
    return f"ASSET-{secrets.token_hex(5).upper()}"


def normalize_host(raw_host: str) -> tuple[str, Optional[int]]:
    """
    Normalize a host string for deduplication.

    Input forms accepted:
      - plain hostname: 'payments.corp'
      - IP: '10.0.0.5'
      - host:port: 'api.corp:8443'
      - URL: 'https://payments.corp:443/api'

    Returns: (normalized_host_lowercase, port_or_None)
    """
    if not raw_host:
        raise ValueError("Host cannot be empty.")

    raw = raw_host.strip()

    # URL form
    if "://" in raw or raw.startswith("//"):
        try:
            parsed = urlparse(raw if "://" in raw else f"http:{raw}")
            host = (parsed.hostname or "").strip().lower()
            port = parsed.port
            if not host:
                raise ValueError(f"Cannot parse host from: {raw_host}")
            return host, port
        except Exception as e:
            raise ValueError(f"Invalid host/URL: {raw_host}") from e

    # host:port form
    if ":" in raw and not raw.startswith("["):
        parts = raw.rsplit(":", 1)
        try:
            port = int(parts[1])
            return parts[0].strip().lower(), port
        except ValueError:
            pass

    return raw.lower(), None


def register_asset(
    organization_id: str,
    display_name: str,
    host: str,
    port: Optional[int],
    environment: str,
    criticality: str,
    internet_facing: Optional[bool],
    data_sensitivity: str,
    created_by: str,
) -> Dict[str, Any]:
    """
    Register a new asset for an organization.
    Normalizes host/port and enforces uniqueness within the org.
    Returns the created asset row.
    Raises:
        ValueError: invalid field values
        ConflictError: duplicate active host:port within org
    """
    # Validate enums
    if environment not in VALID_ENVIRONMENTS:
        raise ValueError(f"Invalid environment '{environment}'. Valid: {sorted(VALID_ENVIRONMENTS)}")
    if criticality not in VALID_CRITICALITIES:
        raise ValueError(f"Invalid criticality '{criticality}'. Valid: {sorted(VALID_CRITICALITIES)}")
    if data_sensitivity not in VALID_SENSITIVITIES:
        raise ValueError(f"Invalid data_sensitivity '{data_sensitivity}'. Valid: {sorted(VALID_SENSITIVITIES)}")

    # Normalize host
    normalized_host, inferred_port = normalize_host(host)
    resolved_port = port if port is not None else inferred_port

    asset_id = generate_asset_id()

    try:
        row = create_registered_asset(
            asset_id=asset_id,
            organization_id=organization_id,
            display_name=display_name.strip(),
            host=host.strip(),
            normalized_host=normalized_host,
            port=resolved_port,
            environment=environment,
            criticality=criticality,
            internet_facing=internet_facing,
            data_sensitivity=data_sensitivity,
            created_by=created_by,
        )
        return _serialize_asset(row)
    except sqlite3.IntegrityError as e:
        msg = str(e)
        if "uidx_asset_host_port_org" in msg or "UNIQUE constraint" in msg:
            raise ConflictError(
                f"An active asset with host '{normalized_host}'"
                + (f":{resolved_port}" if resolved_port else "")
                + f" already exists in organization {organization_id}."
            ) from e
        raise


def get_asset(organization_id: str, asset_id: str) -> Optional[Dict[str, Any]]:
    """Fetch an asset scoped to its organization. Returns None if not found or cross-org."""
    row = get_registered_asset(organization_id, asset_id)
    return _serialize_asset(row) if row else None


def list_assets(organization_id: str) -> List[Dict[str, Any]]:
    """List all registered assets for an organization."""
    rows = list_registered_assets(organization_id)
    return [_serialize_asset(r) for r in rows]


def set_authorization_status(
    organization_id: str,
    asset_id: str,
    new_status: str,
    updated_by: str,
) -> Dict[str, Any]:
    """
    Transition asset authorization status.
    Valid: PENDING, AUTHORIZED, DISABLED.
    Scoped to org — cross-org is rejected.
    """
    if new_status not in VALID_AUTH_STATUSES:
        raise ValueError(f"Invalid authorization_status '{new_status}'. Valid: {sorted(VALID_AUTH_STATUSES)}")

    row = update_asset_authorization(organization_id, asset_id, new_status, updated_by)
    if row is None:
        raise KeyError(f"Asset {asset_id} not found in organization {organization_id}.")
    return _serialize_asset(row)


def build_asset_resolver_catalog(organization_id: str) -> Dict[str, Dict[str, Any]]:
    """
    Build an AssetResolver-compatible catalog dict from AUTHORIZED assets.
    Keys are asset_id strings; values match the schema expected by AssetResolver.
    This is an adapter-only call — AssetResolver matching logic is not modified.
    """
    rows = get_authorized_asset_catalog(organization_id)
    catalog = {}
    for r in rows:
        catalog[r["asset_id"]] = {
            "asset_id": r["asset_id"],
            "asset_name": r["display_name"],
            "host": r["normalized_host"],
            "port": r["port"],
            "environment": r["environment"],
            "criticality": r["criticality"],
            "internet_facing": bool(r["internet_facing"]) if r["internet_facing"] is not None else None,
            "data_sensitivity": r["data_sensitivity"],
        }
    return catalog


def _serialize_asset(row: Dict[str, Any]) -> Dict[str, Any]:
    """Convert raw DB row to API-safe dict (booleans, nulls normalized)."""
    result = dict(row)
    # Normalize integer 0/1 to Python bool for internet_facing
    if result.get("internet_facing") is not None:
        result["internet_facing"] = bool(result["internet_facing"])
    return result


class ConflictError(Exception):
    """Raised when a uniqueness constraint would be violated."""
    pass
