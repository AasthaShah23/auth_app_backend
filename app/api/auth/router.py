from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy.orm import Session

from app.core.deps import get_db
from app.core.logging import get_logger
from app.core.rate_limiter import limiter
from app.core.security import clear_auth_cookies, set_auth_cookies
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
    VerifyEmailResponse,
)
from app.features.auth.service import (
    login_user,
    logout_user,
    process_forgot_password,
    process_resend_verification,
    process_reset_password,
    process_verify_email,
    refresh_access_token,
    signup_user,
)

logger = get_logger(__name__)

router = APIRouter(prefix="/auth", tags=["Auth"])


# POST /api/auth/signup
@router.post(
    "/signup",
    response_model=TokenResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new user account",
    description=(
        "Creates a new user with the `user` role. "
    ),
)
def signup(
    response: Response,
    payload: SignUpRequest,
    db: Session = Depends(get_db),
) -> TokenResponse:
    logger.info("Signup request received for email=%s", payload.email)
    token_response = signup_user(db, payload)
    set_auth_cookies(
        response,
        access_token=token_response.access_token,
        refresh_token=token_response.refresh_token,
    )
    logger.info(
        "Signup complete — user_id=%s  email=%s",
        token_response.user.id,
        token_response.user.email,
    )
    return token_response


# POST /api/auth/login
@router.post(
    "/login",
    response_model=TokenResponse,
    status_code=status.HTTP_200_OK,
    summary="Login with email and password",
    description=("Authenticates an existing user."),
)
@limiter.limit("5/minute")
def login(
    request: Request,
    response: Response,
    payload: LoginRequest,
    db: Session = Depends(get_db),
) -> TokenResponse:
    token_response = login_user(db, payload)
    set_auth_cookies(
        response,
        access_token=token_response.access_token,
        refresh_token=token_response.refresh_token,
    )
    return token_response


# POST /api/auth/refresh
@router.post(
    "/refresh",
    response_model=TokenResponse,
    status_code=status.HTTP_200_OK,
    summary="Refresh access token",
    description=(
        "Exchanges a valid refresh token for a new JWT access token and a rotated refresh token."
    ),
)
def refresh(
    request: Request,
    response: Response,
    payload: RefreshTokenRequest,
    db: Session = Depends(get_db),
) -> TokenResponse:
    raw_refresh_token = request.cookies.get("refresh_token")
    if not raw_refresh_token and payload and payload.refresh_token:
        raw_refresh_token = payload.refresh_token

    if not raw_refresh_token:
        logger.warning("Refresh failed — no refresh_token in httpOnly cookie or request body")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token.",
        )

    token_response = refresh_access_token(db, RefreshTokenRequest(refresh_token=raw_refresh_token))
    set_auth_cookies(
        response,
        access_token=token_response.access_token,
        refresh_token=token_response.refresh_token,
    )
    return token_response


# POST /api/auth/logout
@router.post(
    "/logout",
    response_model=LogoutResponse,
    status_code=status.HTTP_200_OK,
    summary="Logout user",
    description=("Revokes the provided refresh token by updating its `revoked_at` timestamp."),
)
def logout(
    request: Request,
    response: Response,
    payload: RefreshTokenRequest,
    db: Session = Depends(get_db),
) -> LogoutResponse:
    raw_refresh_token = request.cookies.get("refresh_token")
    if not raw_refresh_token and payload and payload.refresh_token:
        raw_refresh_token = payload.refresh_token

    if not raw_refresh_token:
        clear_auth_cookies(response)
        return LogoutResponse(message="Successfully logged out.")

    logout_res = logout_user(db, RefreshTokenRequest(refresh_token=raw_refresh_token))
    clear_auth_cookies(response)
    return logout_res


# POST /api/auth/forgot-password
@router.post(
    "/forgot-password",
    response_model=ForgotPasswordResponse,
    status_code=status.HTTP_200_OK,
    summary="Request password reset link",
    description=(
        "Generates a single-use 15-minute password reset token and logs the mock email link. "
        "Returns a generic response to prevent user email enumeration. Rate limited to 3 requests/min per IP."
    ),
)
@limiter.limit("3/minute")
def forgot_password(
    request: Request,
    payload: ForgotPasswordRequest,
    db: Session = Depends(get_db),
) -> ForgotPasswordResponse:
    logger.info("Forgot password request for email=%s", payload.email)
    return process_forgot_password(db, payload)


# POST /api/auth/reset-password
@router.post(
    "/reset-password",
    response_model=ResetPasswordResponse,
    status_code=status.HTTP_200_OK,
    summary="Reset password using token",
    description=(
        "Validates the reset token, updates the user's password using Argon2, "
        "invalidates the reset token, and revokes all existing sessions. Rate limited to 5 requests/min per IP."
    ),
)
@limiter.limit("5/minute")
def reset_password(
    request: Request,
    response: Response,
    payload: ResetPasswordRequest,
    db: Session = Depends(get_db),
) -> ResetPasswordResponse:
    logger.info("Reset password request submitted")
    reset_res = process_reset_password(db, payload)
    clear_auth_cookies(response)
    return reset_res


# GET /api/auth/verify-email
@router.get(
    "/verify-email",
    response_model=VerifyEmailResponse,
    status_code=status.HTTP_200_OK,
    summary="Verify email using query token",
    description=(
        "Validates the 24-hour verification token from the query parameter and sets user.is_email_verified = True."
    ),
)
def verify_email_get(
    token: str,
    db: Session = Depends(get_db),
) -> VerifyEmailResponse:
    logger.info("Email verification GET request received")
    return process_verify_email(db, token)


# POST /api/auth/resend-verification
@router.post(
    "/resend-verification",
    response_model=ResendVerificationResponse,
    status_code=status.HTTP_200_OK,
    summary="Resend email verification link",
    description=(
        "Generates a new 24-hour verification token and logs the mock verification link for unverified users."
    ),
)
@limiter.limit("3/minute")
def resend_verification(
    request: Request,
    payload: ResendVerificationRequest,
    db: Session = Depends(get_db),
) -> ResendVerificationResponse:
    logger.info("Resend verification request for email=%s", payload.email)
    return process_resend_verification(db, payload)
