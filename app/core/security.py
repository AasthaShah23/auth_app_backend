import hashlib
import secrets
from datetime import UTC, datetime, timedelta

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from fastapi import Response
from jose import jwt

from app.core.config import settings
from app.core.logging import get_logger

logger = get_logger(__name__)

_ph = PasswordHasher()


# Password hashing
def hash_password(plain_password: str) -> str:
    return _ph.hash(plain_password)


# Password verify
def verify_password(plain_password: str, hashed_password: str) -> bool:
    try:
        return _ph.verify(hashed_password, plain_password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


# JWT — Access Token
def create_access_token(user_id: int, email: str, role: str) -> str:
    now = datetime.now(UTC)
    expire = now + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)

    payload = {
        "sub": str(user_id),
        "email": email,
        "role": role,
        "iat": now,
        "exp": expire,
    }

    token = jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    logger.debug("Access token created — user_id=%s  expires_at=%s", user_id, expire.isoformat())
    return token


# JWT — Decode Access Token
def decode_access_token(token: str) -> dict:
    payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
    return payload


# Opaque Token Generation & Hashing (Generic helpers for Refresh, Reset & Verification tokens)
def generate_secure_token(nbytes: int = 32) -> str:
    return secrets.token_hex(nbytes)


# Return the SHA-256 hash string of *raw_token* for database storage.
def hash_token(raw_token: str) -> str:
    return hashlib.sha256(raw_token.encode()).hexdigest()


# Semantic aliases for specific token contexts
generate_refresh_token = generate_secure_token
hash_refresh_token = hash_token

generate_reset_token = generate_secure_token
hash_reset_token = hash_token

generate_verification_token = generate_secure_token
hash_verification_token = hash_token


# httpOnly Cookie Management Helpers
def set_auth_cookies(
    response: Response,
    access_token: str,
    refresh_token: str,
) -> None:
    # Access token cookie (15 mins)
    response.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,
        max_age=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        samesite="lax",
        secure=False,  # Set to True in HTTPS production environments
        path="/",
    )
    # Refresh token cookie (7 days)
    response.set_cookie(
        key="refresh_token",
        value=refresh_token,
        httponly=True,
        max_age=settings.REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60 * 60,
        samesite="lax",
        secure=False,  # Set to True in HTTPS production environments
        path="/",
    )


def clear_auth_cookies(response: Response) -> None:
    response.delete_cookie(key="access_token", path="/")
    response.delete_cookie(key="refresh_token", path="/")
