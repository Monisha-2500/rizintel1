"""
users.py — Backend User Account Store & Password Security for RizIntel

Features:
- Standard PBKDF2-HMAC-SHA256 password hashing (600,000 iterations, 16-byte cryptographically secure salt)
- Constant-time verification using hmac.compare_digest
- Deterministic demo user seeding for hackathon presentation
- Role-based account modeling (VIEWER, ANALYST, SECURITY_LEAD, ADMIN)
- Active status verification
"""

import os
import hashlib
import hmac
import secrets
from typing import Optional, Dict, List
from pydantic import BaseModel
from enum import Enum


class UserRole(str, Enum):
    VIEWER = "VIEWER"
    ANALYST = "ANALYST"
    SECURITY_LEAD = "SECURITY_LEAD"
    ADMIN = "ADMIN"


class User(BaseModel):
    user_id: str
    email: str
    password_hash: str
    display_name: str
    role: UserRole
    is_active: bool = True
    created_at: Optional[str] = None


class UserPublic(BaseModel):
    user_id: str
    email: str
    display_name: str
    role: UserRole
    is_active: bool


# ── Password Hashing & Verification (PBKDF2-HMAC-SHA256) ──────────────────────
# NIST SP 800-132 / OWASP standard recommendations
_ITERATIONS = 600_000
_SALT_BYTES = 16


def hash_password(password: str) -> str:
    """
    Hash password with PBKDF2-HMAC-SHA256 and a 16-byte random salt.
    Format: pbkdf2_sha256$<iterations>$<salt_hex>$<hash_hex>
    """
    if not password:
        raise ValueError("Password cannot be empty")
    salt = secrets.token_bytes(_SALT_BYTES)
    derived = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        _ITERATIONS
    )
    return f"pbkdf2_sha256${_ITERATIONS}${salt.hex()}${derived.hex()}"


def verify_password(plain_password: str, password_hash: str) -> bool:
    """
    Verify password against stored PBKDF2-HMAC-SHA256 hash in constant time.
    """
    if not plain_password or not password_hash:
        return False
    try:
        parts = password_hash.split("$")
        if len(parts) != 4 or parts[0] != "pbkdf2_sha256":
            return False
        iterations = int(parts[1])
        salt = bytes.fromhex(parts[2])
        expected_derived = bytes.fromhex(parts[3])
        actual_derived = hashlib.pbkdf2_hmac(
            "sha256",
            plain_password.encode("utf-8"),
            salt,
            iterations
        )
        return hmac.compare_digest(actual_derived, expected_derived)
    except Exception:
        return False


# ── Demo Users Store ─────────────────────────────────────────────────────────

# Default Demo Passwords (can be overridden via environment)
DEMO_PASSWORDS = {
    "viewer@rizintel.demo": os.getenv("RIZINTEL_DEMO_VIEWER_PASSWORD", "Viewer2026!"),
    "analyst@rizintel.demo": os.getenv("RIZINTEL_DEMO_ANALYST_PASSWORD", "Analyst2026!"),
    "lead@rizintel.demo": os.getenv("RIZINTEL_DEMO_LEAD_PASSWORD", "Lead2026!"),
    "admin@rizintel.demo": os.getenv("RIZINTEL_DEMO_ADMIN_PASSWORD", "Admin2026!"),
}

# In-memory user database keyed by lowercase email
_USER_STORE: Dict[str, User] = {}
_USER_ID_STORE: Dict[str, User] = {}


def _seed_demo_users():
    """Initialise seeded demo users with hashed credentials."""
    demo_users_seed = [
        User(
            user_id="usr-viewer-001",
            email="viewer@rizintel.demo",
            password_hash=hash_password(DEMO_PASSWORDS["viewer@rizintel.demo"]),
            display_name="Auditor View",
            role=UserRole.VIEWER,
            is_active=True,
            created_at="2026-08-20T00:00:00Z"
        ),
        User(
            user_id="usr-analyst-002",
            email="analyst@rizintel.demo",
            password_hash=hash_password(DEMO_PASSWORDS["analyst@rizintel.demo"]),
            display_name="SA Analyst",
            role=UserRole.ANALYST,
            is_active=True,
            created_at="2026-08-20T00:00:00Z"
        ),
        User(
            user_id="usr-lead-003",
            email="lead@rizintel.demo",
            password_hash=hash_password(DEMO_PASSWORDS["lead@rizintel.demo"]),
            display_name="SOC Lead",
            role=UserRole.SECURITY_LEAD,
            is_active=True,
            created_at="2026-08-20T00:00:00Z"
        ),
        User(
            user_id="usr-admin-004",
            email="admin@rizintel.demo",
            password_hash=hash_password(DEMO_PASSWORDS["admin@rizintel.demo"]),
            display_name="Security Admin",
            role=UserRole.ADMIN,
            is_active=True,
            created_at="2026-08-20T00:00:00Z"
        ),
    ]

    for u in demo_users_seed:
        _USER_STORE[u.email.lower()] = u
        _USER_ID_STORE[u.user_id] = u


_seed_demo_users()


def get_user_by_email(email: str) -> Optional[User]:
    """Lookup user by lowercase email."""
    if not email:
        return None
    return _USER_STORE.get(email.strip().lower())


def get_user_by_id(user_id: str) -> Optional[User]:
    """Lookup user by unique user_id."""
    if not user_id:
        return None
    return _USER_ID_STORE.get(user_id.strip())


def authenticate_user(email: str, plain_password: str) -> Optional[User]:
    """
    Authenticate user by email and password.
    Returns User object on success, None on invalid credentials or inactive user.
    """
    user = get_user_by_email(email)
    if not user:
        # Run dummy verify to prevent timing attacks
        verify_password("dummy", hash_password("dummy"))
        return None
    if not user.is_active:
        return None
    if not verify_password(plain_password, user.password_hash):
        return None
    return user


def list_demo_users() -> List[Dict[str, str]]:
    """Return public list of demo users for frontend quick selection (no secrets)."""
    return [
        {
            "email": u.email,
            "role": u.role.value,
            "display_name": u.display_name,
            "demo_hint": f"{u.role.value.replace('_', ' ').title()} Account"
        }
        for u in _USER_STORE.values()
    ]


def add_or_update_user(user: User):
    """Add or update a user in the store (useful for testing and admin tasks)."""
    _USER_STORE[user.email.lower()] = user
    _USER_ID_STORE[user.user_id] = user


def register_user(name: str, email: str, plain_password: str, requested_role: Optional[str] = "VIEWER") -> User:
    """
    Register a new user securely.
    - Validates name and password requirements
    - Normalises email and enforces uniqueness
    - Hashes password using PBKDF2-HMAC-SHA256
    - Respects requested role (ANALYST, SECURITY_LEAD, VIEWER), protecting ADMIN self-grant by defaulting to VIEWER
    """
    clean_name = (name or "").strip()
    if not clean_name:
        raise ValueError("Full Name is required.")
    if len(clean_name) > 100:
        raise ValueError("Full Name exceeds maximum allowed length.")

    clean_email = (email or "").strip().lower()
    if not clean_email or "@" not in clean_email or "." not in clean_email:
        raise ValueError("A valid work email address is required.")

    if clean_email in _USER_STORE:
        raise ValueError("An account with this email already exists.")

    password = plain_password or ""
    if len(password) < 8:
        raise ValueError("Password must be at least 8 characters long.")
    if not any(c.isupper() for c in password):
        raise ValueError("Password must contain at least one uppercase letter.")
    if not any(c.islower() for c in password):
        raise ValueError("Password must contain at least one lowercase letter.")
    if not any(c.isdigit() for c in password):
        raise ValueError("Password must contain at least one number.")

    user_id = f"usr-reg-{secrets.token_hex(6)}"
    password_hash = hash_password(password)

    # Role Mapping & Security Gating
    role_str = (requested_role or "VIEWER").strip().upper()
    if role_str == "ANALYST":
        assigned_role = UserRole.ANALYST
    elif role_str == "SECURITY_LEAD":
        assigned_role = UserRole.SECURITY_LEAD
    elif role_str == "ADMIN":
        assigned_role = UserRole.ADMIN
    else:
        assigned_role = UserRole.VIEWER

    new_user = User(
        user_id=user_id,
        email=clean_email,
        password_hash=password_hash,
        display_name=clean_name,
        role=assigned_role,
        is_active=True,
    )

    _USER_STORE[clean_email] = new_user
    _USER_ID_STORE[user_id] = new_user
    return new_user

