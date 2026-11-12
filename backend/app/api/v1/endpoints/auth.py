from datetime import datetime, timezone
import re
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session
from app.api.deps import get_current_user, get_db, require_roles
from app.core.config import settings
from app.core.security import create_access_token, hash_password, verify_password
from app.models.domain import AuditLog, Organization, User, UserRole
from app.schemas.auth import (
    TokenResponse,
    UserLoginRequest,
    UserRegisterRequest,
    UserResponse,
)

router = APIRouter(prefix="/auth", tags=["Authentication & RBAC"])


def _slugify(text: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", text.lower()).strip("-")
    return slug or "org"


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
def register_user(
    payload: UserRegisterRequest,
    request: Request,
    db: Session = Depends(get_db),
):
    """Register a new user. The first user in a new organization becomes ADMIN."""
    existing_user = db.query(User).filter(User.email == payload.email.lower()).first()
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="An account with this email already exists.",
        )

    base_slug = _slugify(payload.organization_name)
    org = db.query(Organization).filter(Organization.slug == base_slug).first()

    if org is None:
        org = Organization(name=payload.organization_name.strip(), slug=base_slug)
        db.add(org)
        db.flush()
        assigned_role = UserRole.ADMIN
    else:
        assigned_role = UserRole.SECURITY_ANALYST

    user = User(
        organization_id=org.id,
        email=payload.email.lower(),
        full_name=payload.full_name.strip(),
        hashed_password=hash_password(payload.password),
        role=assigned_role,
    )
    db.add(user)
    db.flush()

    db.add(
        AuditLog(
            organization_id=org.id,
            actor_user_id=user.id,
            action="USER_REGISTERED",
            target_type="User",
            target_id=str(user.id),
            ip_address=request.client.host if request.client else "unknown",
            details={"email": user.email, "role": assigned_role.value},
        )
    )
    db.commit()
    db.refresh(user)
    return user


@router.post("/login", response_model=TokenResponse)
def login_user(
    payload: UserLoginRequest,
    request: Request,
    db: Session = Depends(get_db),
):
    """Authenticate user credentials and return a signed JWT Bearer token."""
    user = db.query(User).filter(User.email == payload.email.lower()).first()
    if not user or not verify_password(payload.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password.",
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is disabled.",
        )

    user.last_login_at = datetime.now(timezone.utc)
    db.add(
        AuditLog(
            organization_id=user.organization_id,
            actor_user_id=user.id,
            action="USER_LOGIN",
            target_type="User",
            target_id=str(user.id),
            ip_address=request.client.host if request.client else "unknown",
            details={"email": user.email},
        )
    )
    db.commit()

    token = create_access_token(
        subject=user.id,
        extra_claims={"org_id": user.organization_id, "role": user.role.value},
    )
    return TokenResponse(
        access_token=token,
        expires_in_minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES,
    )


@router.get("/me", response_model=UserResponse)
def read_current_user(current_user: User = Depends(get_current_user)):
    """Return the currently authenticated user's profile."""
    return current_user


@router.get("/admin-check")
def verify_admin_access(current_user: User = Depends(require_roles(UserRole.ADMIN))):
    """Protected endpoint verifying ADMIN role enforcement."""
    return {
        "status": "authorized",
        "user_email": current_user.email,
        "role": current_user.role.value,
    }
