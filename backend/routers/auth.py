"""
routers/auth.py — Authentication Router for RizIntel M8

Endpoints:
  - POST /api/auth/login      : Authenticate credentials & issue signed JWT access token
  - GET  /api/auth/me         : Return current authenticated user profile from verified JWT
  - GET  /api/auth/demo-users : Public list of demo accounts for presentation / testing
"""

import logging
from typing import List, Dict, Any, Optional
from fastapi import APIRouter, HTTPException, status, Depends
from pydantic import BaseModel, EmailStr

from users import authenticate_user, register_user, list_demo_users, UserRole, UserPublic
from auth import create_access_token, get_current_user, AuthenticatedUser

logger = logging.getLogger("rizintel.auth_router")

router = APIRouter(prefix="/auth", tags=["Authentication"])


class LoginRequest(BaseModel):
    email: str
    password: str


class RegisterRequest(BaseModel):
    name: str
    email: str
    password: str
    role: Optional[str] = "VIEWER"


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserPublic


@router.post("/login", response_model=LoginResponse)
def login(payload: LoginRequest):
    """
    Authenticate user credentials and issue signed JWT access token.
    Returns 401 Unauthorized for invalid email or password without revealing specific field.
    """
    email = (payload.email or "").strip().lower()
    password = payload.password or ""

    user = authenticate_user(email=email, plain_password=password)
    if not user:
        logger.warning("Failed login attempt for user '%s'", email)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = create_access_token(user)
    logger.info("Successful login for user '%s' with role '%s'", user.email, user.role.value)

    return LoginResponse(
        access_token=token,
        token_type="bearer",
        user=UserPublic(
            user_id=user.user_id,
            email=user.email,
            display_name=user.display_name,
            role=user.role,
            is_active=user.is_active,
        ),
    )


@router.post("/register", response_model=LoginResponse, status_code=status.HTTP_201_CREATED)
def register(payload: RegisterRequest):
    """
    Register a new user account and automatically issue signed JWT access token.
    Respects safe role selections while preventing unauthenticated ADMIN privilege escalation.
    """
    try:
        user = register_user(
            name=payload.name,
            email=payload.email,
            plain_password=payload.password,
            requested_role=payload.role
        )
        try:
            from services.org_service import _ensure_user_in_demo_org, DEMO_ORG_ID
            _ensure_user_in_demo_org(user.user_id, DEMO_ORG_ID)
            _ensure_user_in_demo_org(user.user_id, "ORG-RIZZOLVE-DEMO")
        except Exception:
            pass
    except ValueError as e:
        detail_msg = str(e)
        logger.warning("Registration failed for email '%s': %s", payload.email, detail_msg)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=detail_msg
        )

    token = create_access_token(user)
    logger.info("New user registered successfully: '%s' (role: %s)", user.email, user.role.value)

    return LoginResponse(
        access_token=token,
        token_type="bearer",
        user=UserPublic(
            user_id=user.user_id,
            email=user.email,
            display_name=user.display_name,
            role=user.role,
            is_active=user.is_active,
        ),
    )


@router.get("/me", response_model=UserPublic)
def get_me(current_user: AuthenticatedUser = Depends(get_current_user)):
    """
    Retrieve authenticated user profile and permissions derived from verified JWT.
    """
    return UserPublic(
        user_id=current_user.user_id,
        email=current_user.email,
        display_name=current_user.display_name,
        role=current_user.role,
        is_active=True,
    )


import os

@router.get("/demo-users", response_model=List[Dict[str, str]])
def get_demo_users():
    """
    Public listing of demo accounts for presentation and testing.
    DISABLED in production environments.
    Exposes no secrets.
    """
    env = os.getenv("RIZINTEL_ENV", "development").strip().lower()
    if env == "production":
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Not found.",
        )
    return list_demo_users()
