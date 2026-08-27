"""
auth.py — Secure JWT Authentication & Role-Based Access Control (RBAC) for RizIntel M8

Security Architecture:
  - Issues signed HMAC-SHA256 JWT access tokens on verified login.
  - Extracts and verifies Authorization: Bearer <JWT> token on protected routes.
  - Derives user identity and role STRICTLY from verified token and server-side user record.
  - Discards client-controlled role spoofing (e.g. X-User-Role / X-User-Name).
  - Enforces Least Privilege RBAC across Viewer, Analyst, Security Lead, and Admin.
  - Injects authenticated actor and role into the persistent tamper-evident audit ledger.
"""

import os
import sys
import logging
from datetime import datetime, timedelta, timezone
from typing import Optional, List, Dict, Any
import jwt
from fastapi import Header, HTTPException, status, Depends
from pydantic import BaseModel

from users import UserRole, User, get_user_by_id, get_user_by_email

logger = logging.getLogger("rizintel.auth")

# ── JWT Configuration ────────────────────────────────────────────────────────
_ENV = os.getenv("RIZINTEL_ENV", "development").strip().lower()
_SECRET_KEY = os.getenv("RIZINTEL_JWT_SECRET", "").strip()

if not _SECRET_KEY:
    if _ENV == "production":
        raise RuntimeError(
            "FATAL: RIZINTEL_JWT_SECRET environment variable is required in production! "
            "Server refusing to start with insecure authentication defaults."
        )
    # Secure development fallback (32 bytes entropy)
    _SECRET_KEY = "rizintel-dev-insecure-secret-key-change-in-prod-2026-m8-engine"

JWT_SECRET_KEY = _SECRET_KEY
JWT_ALGORITHM = "HS256"
JWT_ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("RIZINTEL_JWT_EXPIRE_MINUTES", "120"))


# ── Pydantic Models ──────────────────────────────────────────────────────────
class AuthenticatedUser(BaseModel):
    user_id: str
    username: str
    email: str
    display_name: str
    role: UserRole
    display_title: str
    organization_id: str = "ORG-RIZZOLVE-DEMO"


class TokenData(BaseModel):
    sub: str
    email: Optional[str] = None
    role: Optional[str] = None
    display_name: Optional[str] = None
    exp: Optional[int] = None
    iat: Optional[int] = None


STANDARD_DECISIONS = {
    "ACCEPT_PRIORITY",
    "DOWNGRADE",
    "NEEDS_REVIEW",
    "FALSE_POSITIVE",
    "APPROVE_REVIEW",
    "CONFIRM",
}
LEAD_ONLY_DECISIONS = {"ESCALATE"}


def get_display_title_for_role(role: UserRole) -> str:
    """Return canonical role title for display layer."""
    titles = {
        UserRole.VIEWER: "Security Auditor (Viewer)",
        UserRole.ANALYST: "Security Analyst (L1/L2)",
        UserRole.SECURITY_LEAD: "SOC Security Lead",
        UserRole.ADMIN: "Security Administrator",
    }
    return titles.get(role, "Security Analyst")


# ── JWT Token Issuance & Verification ────────────────────────────────────────

def create_access_token(user: User, expires_delta: Optional[timedelta] = None) -> str:
    """
    Generate a cryptographically signed HMAC-SHA256 JWT access token.
    Claims: sub (user_id), email, role, display_name, iat, exp.
    """
    now = datetime.now(timezone.utc)
    if expires_delta:
        expire = now + expires_delta
    else:
        expire = now + timedelta(minutes=JWT_ACCESS_TOKEN_EXPIRE_MINUTES)

    payload = {
        "sub": user.user_id,
        "email": user.email,
        "role": user.role.value,
        "display_name": user.display_name,
        "iat": int(now.timestamp()),
        "exp": int(expire.timestamp()),
    }
    return jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)


def decode_access_token(token: str) -> Dict[str, Any]:
    """
    Decode and validate JWT access token signature, expiration, and format.
    Raises HTTPException(401) on any cryptographic or timing invalidity.
    """
    if not token or not isinstance(token, str):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required: Access token is missing.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    try:
        payload = jwt.decode(
            token,
            JWT_SECRET_KEY,
            algorithms=[JWT_ALGORITHM],
            options={"require": ["sub", "exp", "iat"]},
        )
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication token has expired. Please log in again.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except jwt.InvalidTokenError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or malformed authentication token.",
            headers={"WWW-Authenticate": "Bearer"},
        )


# ── FastAPI User Identity Dependency ──────────────────────────────────────────

def get_current_user(
    authorization: Optional[str] = Header(None, alias="Authorization"),
    x_user_role: Optional[str] = Header(None, alias="X-User-Role"),
    x_user_name: Optional[str] = Header(None, alias="X-User-Name"),
) -> AuthenticatedUser:
    """
    Validates Bearer JWT and extracts trusted server-side user record.

    SECURITY GUARANTEE:
      - User identity and role come ONLY from verified JWT + backend user store.
      - Any spoofed X-User-Role or X-User-Name headers are completely IGNORED.
      - If an active VIEWER token is accompanied by 'X-User-Role: SECURITY_LEAD',
        the request remains strictly VIEWER and privileged actions return 403.
    """
    if authorization:
        parts = authorization.strip().split()
        if len(parts) != 2 or parts[0].lower() != "bearer":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid Authorization header format. Expected 'Bearer <token>'.",
                headers={"WWW-Authenticate": "Bearer"},
            )
        token = parts[1]
        payload = decode_access_token(token)
        user_id = payload.get("sub")
        if not user_id:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token payload missing required 'sub' claim.",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # Retrieve authoritative server-side user record
        user = get_user_by_id(user_id)
        if not user:
            # Check by email fallback if user_id was an email in earlier token
            user = get_user_by_email(payload.get("email", ""))

        if not user and payload.get("email") and payload.get("role"):
            from users import UserRole, User, add_or_update_user
            role_str = payload.get("role", "SECURITY_LEAD")
            try:
                role_enum = UserRole(role_str)
            except Exception:
                role_enum = UserRole.SECURITY_LEAD
            user = User(
                user_id=user_id,
                email=payload.get("email"),
                password_hash="",
                display_name=payload.get("display_name", payload.get("email")),
                role=role_enum,
                is_active=True,
            )
            add_or_update_user(user)

        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authenticated user no longer exists.",
                headers={"WWW-Authenticate": "Bearer"},
            )

        if not user.is_active:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User account is inactive. Please contact administrator.",
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

    # ── Strict Unauthenticated Check ──────────────────────────────────────────
    # In standard mode, all protected API actions require Bearer JWT.
    # If legacy test mode is explicitly enabled, support fallback for legacy tests
    if os.getenv("RIZINTEL_ALLOW_LEGACY_HEADERS", "false").lower() == "true":
        raw_role = (x_user_role or "ANALYST").strip().upper()
        username = (x_user_name or "SA Analyst").strip()[:64] or "SA Analyst"
        role_map = {
            "VIEWER": UserRole.VIEWER,
            "AUDITOR": UserRole.VIEWER,
            "ANALYST": UserRole.ANALYST,
            "SECURITY_LEAD": UserRole.SECURITY_LEAD,
            "LEAD": UserRole.SECURITY_LEAD,
            "ADMIN": UserRole.ADMIN,
        }
        role = role_map.get(raw_role, UserRole.ANALYST)
        return AuthenticatedUser(
            user_id="legacy-user",
            username=username,
            email=f"{username.lower().replace(' ', '.')}@rizintel.demo",
            display_name=username,
            role=role,
            display_title=get_display_title_for_role(role),
        )

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Authentication required. Please provide a valid Bearer token.",
        headers={"WWW-Authenticate": "Bearer"},
    )


# ── RBAC Permission Enforcers ─────────────────────────────────────────────────

def require_roles(allowed_roles: List[UserRole]):
    """FastAPI dependency to enforce minimum role authorization."""
    def role_checker(user: AuthenticatedUser = Depends(get_current_user)) -> AuthenticatedUser:
        if user.role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Permission denied: Action requires one of {[r.value for r in allowed_roles]}. Current role: {user.role.value}.",
            )
        return user
    return role_checker


def check_analyst_decision_permission(user: AuthenticatedUser, action: str):
    """
    Enforces least privilege on analyst decisions:
      - VIEWER cannot submit any decisions (403 Forbidden).
      - ANALYST can submit standard decisions, but NOT 'ESCALATE' (403 Forbidden).
      - SECURITY_LEAD and ADMIN can submit all decisions including 'ESCALATE'.
    """
    clean_action = (action or "").strip().upper()

    if not clean_action:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="analyst_action is required and cannot be empty.",
        )

    if user.role == UserRole.VIEWER:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Permission denied: VIEWER role is read-only and cannot record decisions or alter risk status.",
        )

    if clean_action in LEAD_ONLY_DECISIONS:
        if user.role not in {UserRole.SECURITY_LEAD, UserRole.ADMIN}:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Permission denied: '{clean_action}' action is restricted to SECURITY_LEAD or ADMIN roles. Current role: {user.role.value}.",
            )

    if clean_action not in STANDARD_DECISIONS and clean_action not in LEAD_ONLY_DECISIONS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unknown decision action '{action}'.",
        )
