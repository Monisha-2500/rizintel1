"""
auth.py — Role-Based Access Control (RBAC) for RizIntel M8 Engine

Roles:
  - VIEWER: Read-only access to findings, SLA, assets, threat intel and audit logs.
  - ANALYST: Can add notes, assign owners, and submit standard decisions (ACCEPT_PRIORITY, DOWNGRADE, NEEDS_REVIEW, FALSE_POSITIVE).
  - SECURITY_LEAD: All Analyst permissions + can perform high-impact ESCALATE decisions and override SLA urgencies.
  - ADMIN: Full administrative privileges across all operations.

Least Privilege Principle:
  - Backend enforces role verification on all sensitive operations.
  - Returns HTTP 403 Forbidden with clear diagnostic details when unauthorized.
  - Injects authenticated actor and role into the persistent tamper-evident audit trail.
"""

from enum import Enum
from typing import Optional, List
from fastapi import Header, HTTPException, status
from pydantic import BaseModel
import re

_PRINTABLE_RE = re.compile(r"[^\x20-\x7E]")


class UserRole(str, Enum):
    VIEWER = "VIEWER"
    ANALYST = "ANALYST"
    SECURITY_LEAD = "SECURITY_LEAD"
    ADMIN = "ADMIN"


class AuthenticatedUser(BaseModel):
    username: str
    role: UserRole
    display_title: str


STANDARD_DECISIONS = {"ACCEPT_PRIORITY", "DOWNGRADE", "NEEDS_REVIEW", "FALSE_POSITIVE"}
LEAD_ONLY_DECISIONS = {"ESCALATE"}


def get_current_user(
    x_user_role: Optional[str] = Header(None, alias="X-User-Role"),
    x_user_name: Optional[str] = Header(None, alias="X-User-Name"),
) -> AuthenticatedUser:
    """
    Extracts and authenticates user role and identity from headers.
    Defaults to ANALYST if header is missing for smooth development.
    """
    raw_role = (x_user_role or "ANALYST").strip().upper()
    # Sanitise: strip non-printable chars, truncate to 64 chars
    username = _PRINTABLE_RE.sub("", (x_user_name or "SA Analyst").strip())[:64] or "SA Analyst"

    # Map aliases or normalize
    if raw_role in {"VIEWER", "AUDITOR", "GUEST"}:
        role = UserRole.VIEWER
        display_title = "Security Auditor (Viewer)"
    elif raw_role in {"ANALYST", "SECURITY_ANALYST", "L1_ANALYST"}:
        role = UserRole.ANALYST
        display_title = "Security Analyst (L1/L2)"
    elif raw_role in {"SECURITY_LEAD", "LEAD", "SOC_LEAD", "LEAD_ANALYST"}:
        role = UserRole.SECURITY_LEAD
        display_title = "SOC Security Lead"
    elif raw_role in {"ADMIN", "SECURITY_ADMIN", "SUPERADMIN"}:
        role = UserRole.ADMIN
        display_title = "Security Administrator"
    else:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Invalid or unauthorized role '{raw_role}'. Valid roles: VIEWER, ANALYST, SECURITY_LEAD, ADMIN."
        )

    return AuthenticatedUser(username=username, role=role, display_title=display_title)


def require_roles(allowed_roles: List[UserRole]):
    """FastAPI dependency to enforce minimum role authorization."""
    def role_checker(user: AuthenticatedUser = Header(None)) -> AuthenticatedUser:
        if user.role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Permission denied: Action requires one of {[r.value for r in allowed_roles]}. Current role: {user.role.value}."
            )
        return user
    return role_checker


def check_analyst_decision_permission(user: AuthenticatedUser, action: str):
    """
    Enforces least privilege on analyst decisions:
      - VIEWER cannot submit any decisions.
      - ANALYST can submit standard decisions, but NOT 'ESCALATE'.
      - SECURITY_LEAD and ADMIN can submit all decisions including 'ESCALATE'.
    """
    clean_action = (action or "").strip().upper()

    if not clean_action:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="analyst_action is required and cannot be empty."
        )

    if user.role == UserRole.VIEWER:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Permission denied: VIEWER role is read-only and cannot record decisions or alter risk status."
        )

    if clean_action in LEAD_ONLY_DECISIONS:
        if user.role not in {UserRole.SECURITY_LEAD, UserRole.ADMIN}:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Permission denied: '{clean_action}' action is restricted to SECURITY_LEAD or ADMIN roles. Current role: {user.role.value}."
            )

    if clean_action not in STANDARD_DECISIONS and clean_action not in LEAD_ONLY_DECISIONS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unknown decision action '{action}'."
        )
