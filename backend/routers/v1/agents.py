"""
agents.py — Human Management Router for Scanner Agents (Phase 4)

Endpoints:
- POST /api/v1/organizations/{org_id}/scanner-agents (Security Lead / Admin only)
- GET  /api/v1/organizations/{org_id}/scanner-agents (Org Members)
- POST /api/v1/organizations/{org_id}/scanner-agents/{agent_id}/revoke (Security Lead / Admin only)
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Path, Body
from pydantic import BaseModel, Field

from auth import AuthenticatedUser, get_current_user, require_roles
from users import UserRole
from services.org_service import assert_membership
from services.agent_service import register_agent, get_agents_for_org, revoke_agent

router = APIRouter(prefix="/api/v1/organizations", tags=["Scanner Agents"])

_require_lead_up = require_roles([UserRole.SECURITY_LEAD, UserRole.ADMIN])


class RegisterAgentRequest(BaseModel):
    display_name: str = Field(..., min_length=2, max_length=100)
    capabilities: Optional[Dict[str, Any]] = None


@router.post("/{organization_id}/scanner-agents", summary="Register a new scanner agent for an organization")
def register_scanner_agent_endpoint(
    organization_id: str = Path(...),
    payload: RegisterAgentRequest = Body(...),
    user: AuthenticatedUser = Depends(_require_lead_up),
) -> Dict[str, Any]:
    """
    Register a dedicated scanner agent identity.
    Security Lead / Admin RBAC required.
    Returns agent metadata and single-time viewable plaintext secret.
    """
    assert_membership(organization_id, user.user_id)

    res = register_agent(
        organization_id=organization_id,
        display_name=payload.display_name,
        created_by_user_id=user.user_id,
        capabilities=payload.capabilities,
    )
    return res


@router.get("/{organization_id}/scanner-agents", summary="List scanner agents registered for an organization")
def list_scanner_agents_endpoint(
    organization_id: str = Path(...),
    user: AuthenticatedUser = Depends(get_current_user),
) -> List[Dict[str, Any]]:
    """List scanner agents for an organization. Accessible to all org members."""
    assert_membership(organization_id, user.user_id)
    return get_agents_for_org(organization_id)


@router.post("/{organization_id}/scanner-agents/{agent_id}/revoke", summary="Revoke a scanner agent")
def revoke_scanner_agent_endpoint(
    organization_id: str = Path(...),
    agent_id: str = Path(...),
    user: AuthenticatedUser = Depends(_require_lead_up),
) -> Dict[str, Any]:
    """Revoke an active scanner agent. Security Lead / Admin RBAC required."""
    assert_membership(organization_id, user.user_id)

    success = revoke_agent(organization_id, agent_id)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scanner agent '{agent_id}' not found or already revoked.",
        )
    return {"message": f"Scanner agent '{agent_id}' revoked successfully.", "agent_id": agent_id}
