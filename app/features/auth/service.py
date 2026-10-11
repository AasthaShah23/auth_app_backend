from datetime import UTC, datetime

from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.logging import get_logger
from app.core.security import (
    create_access_token,
    generate_secure_token,
    hash_password,
    hash_token,
    verify_password,
)
from app.features.auth.repository import (
    create_email_verification_token,
    create_password_reset_token,
    create_refresh_token,
    create_user,
    get_email_verification_token_by_hash,
    get_hash_refresh_token,
    get_password_reset_token_by_hash,
    get_user_by_email,
    get_user_by_id,
    mark_email_verification_token_used,
    mark_password_reset_token_used,
    mark_user_email_as_verified,
    revoke_all_user_refresh_tokens,
    revoke_refresh_token,
    update_user_password,
)
from app.features.auth.schema import (
    ForgotPasswordRequest,
    ForgotPasswordResponse,
    LoginRequest,
    LogoutResponse,
    RefreshTokenRequest,
    ResendVerificationRequest,
    ResendVerificationResponse,
    ResetPasswordRequest,
    ResetPasswordResponse,
    SignUpRequest,
    TokenResponse,
    UserResponse,
    VerifyEmailResponse,
)

logger = get_logger(__name__)


def signup_user(db: Session, payload: SignUpRequest) -> TokenResponse:
    """
    Register a new user account and return JWT tokens.

    Steps:
        1. Check the email is not already taken  → 409 if duplicate.
        2. Hash the plain-text password with Argon2.
        3. Persist the new user row.
        4. Generate a signed JWT access token (15 min).
        5. Generate a secure random refresh token (7 days).
        6. Store the SHA-256 hash of the refresh token in the DB.
        7. Return both tokens + public user profile.
    """
    # Duplicate email check
    existing_user = get_user_by_email(db, email=payload.email)
    if existing_user:
        logger.warning("Email already registered: email=%s", payload.email)
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An account with this email address already exists.",
        )

    hashed_pw = hash_password(payload.password)

    new_user = create_user(
        db,
        name=payload.name,
        email=payload.email,
        hashed_password=hashed_pw,
    )
    logger.info("User created successfully — user_id=%s  email=%s", new_user.id, new_user.email)

    # Generate JWT access token
    access_token = create_access_token(
        user_id=new_user.id,
        email=new_user.email,
        role=new_user.role,
    )

    # Generate + store refresh token
    raw_refresh_token = generate_secure_token()
    token_hash = hash_token(raw_refresh_token)

    create_refresh_token(db, user_id=new_user.id, token_hash=token_hash)
    logger.info("Tokens issued after signup — user_id=%s", new_user.id)

    # Generate + store email verification token (24 hrs)
    raw_verification_token = generate_secure_token()
    verification_hash = hash_token(raw_verification_token)
    create_email_verification_token(
        db, user_id=new_user.id, token_hash=verification_hash, expires_in_hours=24
    )

    # Mock Email Service: Log verification link
    mock_verification_link = f"{settings.FRONTEND_URL}/verify-email?token={raw_verification_token}"
    logger.info(
        "\n========================================================================\n"
        "MOCK EMAIL SENT TO: %s\n"
        "SUBJECT: Verify Your Email Address\n"
        "LINK: %s\n"
        "TOKEN (RAW): %s\n"
        "========================================================================",
        new_user.email,
        mock_verification_link,
        raw_verification_token,
    )

    # Return response
    return TokenResponse(
        access_token=access_token,
        refresh_token=raw_refresh_token,  # raw token → goes to client
        user=UserResponse.model_validate(new_user),
        message="Registration successful. A verification link has been sent to your email address.",
    )


def login_user(db: Session, payload: LoginRequest) -> TokenResponse:
    user = get_user_by_email(db, email=payload.email)

    if not user or not verify_password(payload.password, user.password):
        logger.warning("Login failed — invalid credentials for email=%s", payload.email)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password.",
        )

    if not user.is_active:
        logger.warning(
            "Login rejected — account deactivated for user_id=%s  email=%s",
            user.id,
            user.email,
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Your account has been deactivated. Please contact support.",
        )

    # Generate JWT access token
    access_token = create_access_token(
        user_id=user.id,
        email=user.email,
        role=user.role,
    )

    # Generate + store refresh token
    raw_refresh_token = generate_secure_token()
    token_hash = hash_token(raw_refresh_token)
    create_refresh_token(db, user_id=user.id, token_hash=token_hash)

    logger.info(
        "Login successful — user_id=%s  email=%s  role=%s",
        user.id,
        user.email,
        user.role,
    )

    # Return response
    return TokenResponse(
        access_token=access_token,
        refresh_token=raw_refresh_token,
        user=UserResponse.model_validate(user),
    )


def refresh_access_token(db: Session, payload: RefreshTokenRequest) -> TokenResponse:
    """
    Exchange a valid refresh token for a new access token and a new rotated refresh token.

    Steps:
        1. Hash the incoming raw refresh token.
        2. Query database for matching token record.
        3. Validate record exists, is not revoked, and is not expired.
        4. Validate user exists and is active.
        5. Revoke old refresh token (Token Rotation).
        6. Generate and store a new refresh token.
        7. Generate a new JWT access token.
        8. Return new tokens + user profile.
    """
    token_hash = hash_token(payload.refresh_token)
    token_record = get_hash_refresh_token(db, token_hash)

    if not token_record:
        logger.warning("Refresh failed — token hash not found in database")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token.",
        )

    if token_record.revoked_at is not None:
        logger.warning(
            "Refresh failed — token id=%s was already revoked at %s",
            token_record.id,
            token_record.revoked_at,
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token.",
        )

    now = datetime.now(UTC)
    expires_at = token_record.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=UTC)

    if expires_at < now:
        logger.warning("Refresh failed — token id=%s has expired", token_record.id)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token.",
        )

    user = get_user_by_id(db, token_record.user_id)
    if not user or not user.is_active:
        logger.warning(
            "Refresh failed — user_id=%s does not exist or is inactive",
            token_record.user_id,
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User account is inactive or no longer exists.",
        )

    # Token Rotation: Revoke old token, create new token
    revoke_refresh_token(db, token_record)

    new_raw_refresh_token = generate_secure_token()
    new_token_hash = hash_token(new_raw_refresh_token)
    create_refresh_token(db, user_id=user.id, token_hash=new_token_hash)

    new_access_token = create_access_token(
        user_id=user.id,
        email=user.email,
        role=user.role,
    )

    logger.info("Token refresh successful — user_id=%s  email=%s", user.id, user.email)

    return TokenResponse(
        access_token=new_access_token,
        refresh_token=new_raw_refresh_token,
        user=UserResponse.model_validate(user),
    )


def logout_user(db: Session, payload: RefreshTokenRequest) -> LogoutResponse:

    token_hash = hash_token(payload.refresh_token)
    token_record = get_hash_refresh_token(db, token_hash)

    if not token_record or token_record.revoked_at is not None:
        logger.warning("Logout attempted with invalid or already revoked refresh token")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or already revoked refresh token.",
        )

    # Invalidate token by setting revoked_at to current timestamp
    revoke_refresh_token(db, token_record)

    logger.info(
        "User logged out successfully — refresh token id=%s revoked for user_id=%s",
        token_record.id,
        token_record.user_id,
    )

    return LogoutResponse()


def process_forgot_password(db: Session, payload: ForgotPasswordRequest) -> ForgotPasswordResponse:

    user = get_user_by_email(db, email=payload.email)

    if user:
        raw_reset_token = generate_secure_token()
        token_hash = hash_token(raw_reset_token)

        create_password_reset_token(
            db, user_id=user.id, token_hash=token_hash, expires_in_minutes=15
        )

        # Mock Email Service: Log the password reset link
        mock_reset_link = f"http://localhost:3000/reset-password?token={raw_reset_token}"
        logger.info(
            "\n========================================================================\n"
            "MOCK EMAIL SENT TO: %s\n"
            "SUBJECT: Password Reset Request\n"
            "LINK: %s\n"
            "TOKEN (RAW): %s\n"
            "========================================================================",
            user.email,
            mock_reset_link,
            raw_reset_token,
        )

    return ForgotPasswordResponse()


def process_reset_password(db: Session, payload: ResetPasswordRequest) -> ResetPasswordResponse:
    """
    Process a password reset request using a valid reset token.

    Steps:
        1. Hash the incoming raw reset token.
        2. Query DB for matching reset token record.
        3. Validate record exists, is not used, and is not expired.
        4. Validate user exists and is active.
        5. Hash the new password with Argon2.
        6. Update the user's password in DB.
        7. Mark reset token as used (`used_at = now()`).
        8. Revoke all active refresh tokens for the user for security.
    """
    token_hash = hash_token(payload.token)
    reset_record = get_password_reset_token_by_hash(db, token_hash)

    if not reset_record:
        logger.warning("Password reset failed — token hash not found in DB")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired password reset token.",
        )

    if reset_record.used_at is not None:
        logger.warning("Password reset failed — token id=%s already used", reset_record.id)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired password reset token.",
        )

    now = datetime.now(UTC)
    expires_at = reset_record.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=UTC)

    if expires_at < now:
        logger.warning("Password reset failed — token id=%s expired", reset_record.id)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired password reset token.",
        )

    user = get_user_by_id(db, reset_record.user_id)
    if not user or not user.is_active:
        logger.warning(
            "Password reset failed — user_id=%s inactive or not found", reset_record.user_id
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User account is inactive or no longer exists.",
        )

    # Hash new password and update user
    new_hashed_password = hash_password(payload.new_password)
    update_user_password(db, user, new_hashed_password)

    # Invalidate reset token
    mark_password_reset_token_used(db, reset_record)

    # Security: Revoke all existing sessions / refresh tokens
    revoke_all_user_refresh_tokens(db, user.id)

    logger.info(
        "Password reset completed successfully for user_id=%s email=%s", user.id, user.email
    )
    return ResetPasswordResponse()


def process_verify_email(db: Session, token: str) -> VerifyEmailResponse:
    """
    Process email verification using token.

    Steps:
        1. Hash the incoming raw token.
        2. Query DB for matching verification token record.
        3. Validate token exists, is not used, and is not expired.
        4. Validate user exists and is active.
        5. Mark user email as verified (`is_email_verified = True`).
        6. Invalidate verification token (`used_at = now()`).
    """
    token_hash = hash_token(token)
    token_record = get_email_verification_token_by_hash(db, token_hash)

    if not token_record:
        logger.warning("Email verification failed — token hash not found in DB")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired verification token.",
        )

    if token_record.used_at is not None:
        logger.warning("Email verification failed — token id=%s already used", token_record.id)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired verification token.",
        )

    now = datetime.now(UTC)
    expires_at = token_record.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=UTC)

    if expires_at < now:
        logger.warning("Email verification failed — token id=%s expired", token_record.id)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired verification token.",
        )

    user = get_user_by_id(db, token_record.user_id)
    if not user or not user.is_active:
        logger.warning(
            "Email verification failed — user_id=%s inactive or not found", token_record.user_id
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User account is inactive or no longer exists.",
        )

    mark_user_email_as_verified(db, user)
    mark_email_verification_token_used(db, token_record)

    logger.info("Email verified successfully for user_id=%s email=%s", user.id, user.email)
    return VerifyEmailResponse()


# resend verification email
def process_resend_verification(
    db: Session, payload: ResendVerificationRequest
) -> ResendVerificationResponse:
    clean_email = payload.email.lower().strip()
    user = get_user_by_email(db, email=clean_email)

    if not user:
        logger.info(
            "Resend verification skipped — email %s is not registered in database", clean_email
        )
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No account found with that email address.",
        )

    if user.is_email_verified:
        logger.info(
            "Resend verification skipped — user_id=%s email=%s is ALREADY VERIFIED",
            user.id,
            user.email,
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email address is already verified.",
        )

    if not user.is_active:
        logger.warning(
            "Resend verification skipped — user_id=%s email=%s is deactivated", user.id, user.email
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Your account has been deactivated. Please contact support.",
        )

    raw_verification_token = generate_secure_token()
    verification_hash = hash_token(raw_verification_token)
    create_email_verification_token(
        db, user_id=user.id, token_hash=verification_hash, expires_in_hours=24
    )

    mock_verification_link = f"{settings.FRONTEND_URL}/verify-email?token={raw_verification_token}"
    logger.info(
        "\n========================================================================\n"
        "MOCK EMAIL SENT TO: %s\n"
        "SUBJECT: Resend Verification Email Link\n"
        "LINK: %s\n"
        "TOKEN (RAW): %s\n"
        "========================================================================",
        user.email,
        mock_verification_link,
        raw_verification_token,
    )

    return ResendVerificationResponse()
