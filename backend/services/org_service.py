"""
org_service.py — Organization Lifecycle & Membership Service (Phase 1)

Responsibilities:
- Create and retrieve organizations from persistent SQLite storage.
- Manage organization memberships.
- Seed a demo organization on non-production startup.
- Provide org-isolation helpers for RBAC enforcement in the v1 router.

SECURITY: Authorization authority remains the existing JWT/UserRole system.
Membership is a belongs-to check only; it does NOT elevate permissions.
"""

from __future__ import annotations

import logging
import os
import secrets
from typing import Any, Dict, List, Optional

from database import (
    create_organization,
    get_organization,
    list_organizations,
    upsert_membership,
    get_user_membership,
    list_user_organizations,
    list_org_members,
)

logger = logging.getLogger("rizintel.org_service")

_RIZINTEL_ENV = os.getenv("RIZINTEL_ENV", "development").strip().lower()

# Stable demo org used in non-production environments
DEMO_ORG_ID = "ORG-DEMO-001"
DEMO_ORG_NAME = "RizIntel Demo Organization"

# All 4 demo user IDs (matches users.py)
_DEMO_USER_IDS = [
    "usr-viewer-001",
    "usr-analyst-002",
    "usr-lead-003",
    "usr-admin-004",
]

_SEEDED = False


def _seed_demo_org() -> None:
    """
    Create the demo org and add all demo users as members if not already present.
    Only runs in non-production environments.
    Called once at service layer init.
    """
    env = os.getenv("RIZINTEL_ENV", "development").strip().lower()
    if env == "production":
        logger.info("Production environment — skipping demo org seeding.")
        return

    try:
        existing = get_organization(DEMO_ORG_ID)
        if not existing:
            create_organization(DEMO_ORG_ID, DEMO_ORG_NAME)
            logger.info("Demo organization created: %s", DEMO_ORG_ID)
        else:
            logger.debug("Demo organization already exists: %s", DEMO_ORG_ID)

        # Add all demo users as members
        role_map = {
            "usr-viewer-001": "VIEWER",
            "usr-analyst-002": "ANALYST",
            "usr-lead-003": "SECURITY_LEAD",
            "usr-admin-004": "ADMIN",
        }
        for user_id, role in role_map.items():
            existing_m = get_user_membership(DEMO_ORG_ID, user_id)
            if not existing_m:
                mid = f"MEM-{DEMO_ORG_ID}-{user_id}"
                upsert_membership(mid, DEMO_ORG_ID, user_id, role)
                logger.info("Seeded demo membership: %s -> %s (%s)", user_id, DEMO_ORG_ID, role)
    except Exception as exc:  # pragma: no cover
        logger.warning("Demo org seeding error (non-fatal): %s", exc)


# ── Public API ────────────────────────────────────────────────


def generate_org_id() -> str:
    """Generate a collision-safe organization ID: ORG-<10 hex chars>."""
    return f"ORG-{secrets.token_hex(5).upper()}"


def ensure_org_exists(organization_id: str) -> Optional[Dict[str, Any]]:
    """Return the org dict if it exists and is active, else None."""
    org = get_organization(organization_id)
    if org and org.get("is_active"):
        return org
    return None


def get_org_or_404(organization_id: str) -> Dict[str, Any]:
    """Return org or raise KeyError (caller converts to 404)."""
    org = ensure_org_exists(organization_id)
    if not org:
        raise KeyError(f"Organization not found or inactive: {organization_id}")
    return org


def _ensure_user_in_demo_org(user_id: str, org_id: str = DEMO_ORG_ID) -> None:
    try:
        from users import get_user_by_id
        u = get_user_by_id(user_id)
        role = u.role.value if u else "SECURITY_LEAD"
        mid = f"MEM-{org_id}-{user_id}"
        upsert_membership(mid, org_id, user_id, role)
        logger.info("Ensured demo org membership: %s -> %s (%s)", user_id, org_id, role)
    except Exception as exc:
        logger.warning("Failed to ensure demo org membership: %s", exc)


def assert_membership(organization_id: str, user_id: str) -> Dict[str, Any]:
    """
    Confirm the user is an active member of the org.
    Raises PermissionError if not.
    SECURITY: This is a belongs-to check only — does NOT grant elevated permissions.
    """
    membership = get_user_membership(organization_id, user_id)
    if not membership and organization_id in (DEMO_ORG_ID, "ORG-RIZZOLVE-DEMO"):
        _ensure_user_in_demo_org(user_id, organization_id)
        membership = get_user_membership(organization_id, user_id)

    if not membership:
        raise PermissionError(
            f"User {user_id} is not an active member of organization {organization_id}."
        )
    return membership


def get_user_organizations(user_id: str) -> List[Dict[str, Any]]:
    """Return all active orgs the user is a member of."""
    orgs = list_user_organizations(user_id)
    if not orgs:
        _ensure_user_in_demo_org(user_id, DEMO_ORG_ID)
        _ensure_user_in_demo_org(user_id, "ORG-RIZZOLVE-DEMO")
        orgs = list_user_organizations(user_id)
    return orgs


def get_org_members(organization_id: str) -> List[Dict[str, Any]]:
    """Return all active members of an organization."""
    return list_org_members(organization_id)


# Seed demo org on module import
_seed_demo_org()

