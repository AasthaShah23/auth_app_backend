"""
Core dependencies for FastAPI route handlers:
- Database session injection (`get_db`)
- JWT authentication (`get_current_user`)
- Role-based authorization (`require_role`, `require_admin`)
"""

from collections.abc import Generator

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError
from sqlalchemy.orm import Session

from app.core.database import SessionLocal
from app.core.logging import get_logger
from app.core.security import decode_access_token
from app.features.auth.repository import get_user_by_id
from app.models.users import User

logger = get_logger(__name__)

# HTTP Bearer scheme (auto_error=False permits httpOnly cookies when Bearer header is omitted)
http_bearer = HTTPBearer(auto_error=False)


def get_db() -> Generator[Session, None, None]:

    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# Authentication dependency (Dual-resolution: httpOnly cookie first, then Bearer header)
def get_current_user(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(http_bearer),
    db: Session = Depends(get_db),
) -> User:
    # 1. Read token from httpOnly cookie
    token = request.cookies.get("access_token")

    # 2. Fallback to Authorization: Bearer header (for Swagger UI, Postman, API clients)
    if not token and credentials:
        token = credentials.credentials

    if not token:
        logger.warning("No authentication token provided via httpOnly cookie or Bearer header")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="You are not authenticated. Invalid or expired token.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        payload = decode_access_token(token)
        user_id_str: str = payload.get("sub")

        if not user_id_str:
            logger.warning("JWT missing 'sub' claim")
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not validate credentials....",
                headers={"WWW-Authenticate": "Bearer"},
            )
        user_id = int(user_id_str)
    except (JWTError, ValueError) as err:
        logger.warning("Failed to decode or parse JWT access token")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="You are not authenticated. Invalid or expired token.",
            headers={"WWW-Authenticate": "Bearer"},
        ) from err

    user = get_user_by_id(db, user_id=user_id)
    if not user:
        logger.warning("User id=%s from JWT not found in DB", user_id)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User no longer exists.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_active:
        logger.warning("Deactivated user id=%s attempted access", user_id)
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is deactivated.",
        )

    return user


# Role-based authorization dependency
def require_role(required_role: str):

    def role_checker(current_user: User = Depends(get_current_user)) -> User:
        if current_user.role != required_role:
            logger.warning(
                "Access denied — user_id=%s with role='%s' attempted to access route requiring role='%s'",
                current_user.id,
                current_user.role,
                required_role,
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access denied. Requires '{required_role}' role.",
            )
        return current_user

    return role_checker


# Convenient pre-configured dependency for admin-only routes
require_admin = require_role("admin")


# Email verification dependency for protected routes
def require_verified_user(current_user: User = Depends(get_current_user)) -> User:

    if not current_user.is_email_verified:
        logger.warning(
            "Access denied — unverified user_id=%s attempted to access protected route",
            current_user.id,
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Please verify your email address to view profile details.",
        )
    return current_user
