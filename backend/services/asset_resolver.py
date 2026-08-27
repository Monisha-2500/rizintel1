"""
asset_resolver.py
=================
Centralized, deterministic asset resolution mechanism for RizIntel.

Resolves scanner findings to asset context using normalized identifiers:
- Exact Asset ID
- Hostname / Host
- Normalized URL / Hostname
- Host:Port combination
- IP Address

Guarantees:
- Deterministic, unambiguous matching only.
- Strict isolation: no arbitrary or default production asset fallback.
- Unmatched findings resolve to 'UNMAPPED' with safe, neutral context.
- Zero fabrication of asset criticality, environment, exposure, or data sensitivity.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import urlparse

logger = logging.getLogger("rizintel.asset_resolver")

# Canonical neutral asset context for unmapped findings (explicitly UNKNOWN, not fabricated)
UNMAPPED_ASSET_ID = "UNMAPPED"
UNMAPPED_ASSET_NAME = "Unresolved Asset"
UNMAPPED_ENVIRONMENT = "UNKNOWN"
UNMAPPED_CRITICALITY = "UNKNOWN"
UNMAPPED_INTERNET_EXPOSURE = None   # genuinely unknown — not False, not True
UNMAPPED_DATA_SENSITIVITY = "UNKNOWN"


def normalize_identifier(identifier: Optional[str]) -> Tuple[Optional[str], Optional[int]]:
    """
    Normalizes a URL, hostname, host:port, or IP string.
    Returns (clean_hostname_or_ip, port).
    
    Examples:
    - 'https://payments.internal.corp/api/v1?test=1' -> ('payments.internal.corp', 443)
    - 'http://127.0.0.1:8001/WebGoat/start.mvc' -> ('127.0.0.1', 8001)
    - 'localhost:3000/' -> ('localhost', 3000)
    - 'PAYMENTS.INTERNAL.CORP' -> ('payments.internal.corp', None)
    - '127.0.0.1' -> ('127.0.0.1', None)
    """
    if not identifier:
        return None, None

    raw = str(identifier).strip()
    if not raw:
        return None, None

    # Handle protocol presence
    if "://" in raw or raw.startswith("//"):
        try:
            parsed = urlparse(raw if "://" in raw else f"http:{raw}")
            host = (parsed.hostname or "").strip().lower()
            port = parsed.port
            if not port and parsed.scheme:
                if parsed.scheme.lower() == "https":
                    port = 443
                elif parsed.scheme.lower() == "http":
                    port = 80
            return (host if host else None), port
        except Exception:
            pass

    # Strip query/path/fragment if attached without protocol
    # E.g. '127.0.0.1:8001/WebGoat/start.mvc?foo=bar'
    cleaned = raw.split("?")[0].split("#")[0].split("/")[0].strip().lower()

    if ":" in cleaned:
        parts = cleaned.split(":")
        host = parts[0].strip().lower()
        try:
            port = int(parts[1])
        except (ValueError, IndexError):
            port = None
        return (host if host else None), port

    return (cleaned if cleaned else None), None


def build_neutral_asset_context(host_hint: Optional[str] = None) -> Dict[str, Any]:
    """
    Constructs a safe, schema-compliant neutral asset context dictionary
    for findings that have no matching asset in the catalog.

    All fields carry explicit UNKNOWN / None semantics.
    internet_facing/internet_exposure are None (genuinely unknown exposure,
    NOT False which would falsely imply 'confirmed internal').
    """
    display_name = f"Unresolved Asset ({host_hint})" if host_hint else UNMAPPED_ASSET_NAME
    return {
        "asset_id": UNMAPPED_ASSET_ID,
        "asset_name": display_name,
        "environment": UNMAPPED_ENVIRONMENT,
        "criticality": UNMAPPED_CRITICALITY,
        "asset_criticality": UNMAPPED_CRITICALITY,
        "internet_facing": UNMAPPED_INTERNET_EXPOSURE,    # None
        "internet_exposure": UNMAPPED_INTERNET_EXPOSURE,  # None
        "data_sensitivity": UNMAPPED_DATA_SENSITIVITY,
    }


class AssetResolver:
    """
    Centralized resolver indexing asset catalogs for deterministic resolution.
    """

    def __init__(self, catalog: Optional[Dict[str, Dict[str, Any]]] = None):
        self.catalog = catalog or {}
        self._by_asset_id: Dict[str, Dict[str, Any]] = {}
        self._by_host_port: Dict[str, Dict[str, Any]] = {}
        self._by_host: Dict[str, List[Dict[str, Any]]] = {}
        self._build_index()

    def _build_index(self) -> None:
        """Builds lookup indices from the provided asset catalog."""
        for key, raw_entry in self.catalog.items():
            if not isinstance(raw_entry, dict):
                continue

            entry = dict(raw_entry)
            asset_id = str(entry.get("asset_id") or key).strip()
            if not asset_id or asset_id.upper() == UNMAPPED_ASSET_ID:
                continue

            # Ensure canonical asset_id is present
            entry["asset_id"] = asset_id
            asset_id_lower = asset_id.lower()
            self._by_asset_id[asset_id_lower] = entry

            # Collect all host/URL identifiers for this asset
            identifiers: Set[str] = set()

            # 1. The catalog key itself if it looks like a host/URL
            if key != asset_id:
                identifiers.add(key)

            # 2. Singular host/hostname/url/ip fields
            for field in ["host", "hostname", "url", "ip", "target", "endpoint"]:
                val = entry.get(field)
                if val and isinstance(val, str):
                    identifiers.add(val)

            # 3. Plural host/url collections
            for list_field in ["hosts", "hostnames", "urls", "ip_addresses", "aliases", "endpoints"]:
                vals = entry.get(list_field)
                if isinstance(vals, (list, set, tuple)):
                    for v in vals:
                        if v and isinstance(v, str):
                            identifiers.add(v)

            # Index each normalized identifier
            for ident in identifiers:
                host, port = normalize_identifier(ident)
                if not host:
                    continue

                if port is not None:
                    host_port_key = f"{host}:{port}"
                    self._by_host_port[host_port_key] = entry

                if host not in self._by_host:
                    self._by_host[host] = []
                if entry not in self._by_host[host]:
                    self._by_host[host].append(entry)

    def resolve(
        self,
        finding_or_host: Any,
        port: Optional[int] = None,
    ) -> Tuple[str, Dict[str, Any]]:
        """
        Resolves a finding dictionary or host string to (asset_id, asset_context).
        
        Resolution Precedence:
        1. Explicit valid asset_id match against catalog (if not 'UNMAPPED')
        2. Exact host:port match
        3. Unambiguous exact hostname / IP match
        4. Fallback to UNMAPPED neutral context (NO arbitrary production asset)
        """
        if isinstance(finding_or_host, str):
            candidate_asset_id = None
            raw_host = finding_or_host
            raw_url = None
            candidate_port = port
        elif isinstance(finding_or_host, dict):
            # Extract fields from finding dictionary
            asset_obj = finding_or_host.get("asset") or {}
            candidate_asset_id = (
                finding_or_host.get("asset_id")
                or asset_obj.get("asset_id")
            )
            raw_host = (
                finding_or_host.get("host")
                or asset_obj.get("host")
                or finding_or_host.get("matched-at")
                or finding_or_host.get("target")
            )
            raw_url = (
                finding_or_host.get("url")
                or asset_obj.get("url")
                or finding_or_host.get("matched-at")
            )
            candidate_port = (
                finding_or_host.get("port")
                or asset_obj.get("port")
                or port
            )
        else:
            return UNMAPPED_ASSET_ID, build_neutral_asset_context()

        # Step 1: Explicit Asset ID lookup if valid
        if candidate_asset_id and str(candidate_asset_id).upper() != UNMAPPED_ASSET_ID:
            aid_key = str(candidate_asset_id).strip().lower()
            if aid_key in self._by_asset_id:
                return self._by_asset_id[aid_key]["asset_id"], self._by_asset_id[aid_key]

        # Extract normalized host and port candidates
        extracted_host, extracted_port = normalize_identifier(raw_url or raw_host)
        effective_port = candidate_port or extracted_port
        clean_host = extracted_host

        if not clean_host and raw_host:
            clean_host, maybe_port = normalize_identifier(raw_host)
            if not effective_port:
                effective_port = maybe_port

        if not clean_host:
            return UNMAPPED_ASSET_ID, build_neutral_asset_context()

        # Step 2: Exact Host:Port match (highest priority for multi-service hosts)
        if effective_port is not None:
            host_port_key = f"{clean_host}:{effective_port}"
            if host_port_key in self._by_host_port:
                matched = self._by_host_port[host_port_key]
                return matched["asset_id"], matched

        # Step 3: Exact Hostname / IP match (when unambiguous)
        if clean_host in self._by_host:
            candidates = self._by_host[clean_host]
            if len(candidates) == 1:
                matched = candidates[0]
                return matched["asset_id"], matched
            elif len(candidates) > 1:
                # If multiple assets share a host IP (e.g. 127.0.0.1) on different ports,
                # but no port matched, do not guess arbitrarily.
                logger.warning(
                    f"Ambiguous host '{clean_host}' matched multiple assets without port match: "
                    f"{[c.get('asset_id') for c in candidates]}"
                )

        # Step 4: Unmapped - Return safe neutral context
        host_hint = f"{clean_host}:{effective_port}" if effective_port else clean_host
        return UNMAPPED_ASSET_ID, build_neutral_asset_context(host_hint=host_hint)
