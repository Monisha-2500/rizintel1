"""
agent_service.py — Scanner Agent Machine Identity & Token Management (Phase 4)

Responsibilities:
- Register dedicated machine identities for scanner agents (Lead/Admin RBAC).
- Generate single-time viewable plaintext secrets and store SHA-256 hashes server-side.
- Perform constant-time authentication on machine identity tokens.
- Support agent revocation and capabilities registration.
"""

from __future__ import annotations

import json
import secrets
from typing import Any, Dict, List, Optional
from database import (
    create_scanner_agent,
    get_scanner_agent,
    get_scanner_agent_by_token_hash,
    list_scanner_agents,
    revoke_scanner_agent,
    update_agent_heartbeat,
)
from services.storage_service import compute_payload_hash

def generate_agent_id() -> str:
    """Generate collision-safe agent ID: AGENT-<10 hex chars>."""
    return f"AGENT-{secrets.token_hex(5).upper()}"


def register_agent(
    organization_id: str,
    display_name: str,
    created_by_user_id: str,
    capabilities: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Register a new scanner agent for an organization.
    Generates a cryptographically random secret string.
    Returns agent metadata along with `plaintext_secret` (returned ONCE).
    """
    agent_id = generate_agent_id()
    raw_secret = f"agt_{secrets.token_urlsafe(32)}"
    token_hash = compute_payload_hash(raw_secret.encode("utf-8"))
    capabilities_json = json.dumps(capabilities or {})

    agent = create_scanner_agent(
        agent_id=agent_id,
        organization_id=organization_id,
        display_name=display_name,
        token_hash=token_hash,
        created_by_user_id=created_by_user_id,
        capabilities_json=capabilities_json,
    )

    agent_dict = dict(agent)
    agent_dict.pop("token_hash", None)

    return {
        "agent": agent_dict,
        "plaintext_secret": raw_secret,
    }


def authenticate_agent(raw_token: str) -> Optional[Dict[str, Any]]:
    """
    Authenticate a machine scanner agent token.
    Hashes input raw_token and performs DB lookup for ACTIVE status agent.
    Updates agent's last_seen_at timestamp.
    """
    if not raw_token or not raw_token.strip():
        return None

    clean_token = raw_token.replace("AgentToken ", "").replace("Bearer ", "").strip()
    token_hash = compute_payload_hash(clean_token.encode("utf-8"))

    agent = get_scanner_agent_by_token_hash(token_hash)
    if agent and agent.get("status") == "ACTIVE":
        update_agent_heartbeat(agent["agent_id"])
        return agent
    return None


def get_agents_for_org(organization_id: str) -> List[Dict[str, Any]]:
    """List scanner agents for an organization without exposing token hashes."""
    agents = list_scanner_agents(organization_id)
    for a in agents:
        a.pop("token_hash", None)
    return agents


def revoke_agent(organization_id: str, agent_id: str) -> bool:
    """Revoke a scanner agent."""
    return revoke_scanner_agent(organization_id, agent_id)
