import uuid

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.core.security import generate_secure_token, hash_token
from app.features.auth.repository import create_email_verification_token
from app.models.users import User


def test_signup_and_duplicate_email_conflict(client: TestClient):
    """Test user signup success and duplicate email conflict (409)."""
    email = f"user_signup_{uuid.uuid4().hex[:8]}@example.com"
    password = "Str0ng!Pass123"

    # 1. Signup success
    response = client.post(
        "/api/auth/signup",
        json={
            "name": "Signup Test User",
            "email": email,
            "password": password,
        },
    )
    assert response.status_code == 201
    data = response.json()
    assert "access_token" in data
    assert "refresh_token" in data
    assert data["user"]["email"] == email
    assert data["message"] == "Registration successful. A verification link has been sent to your email address."

    # 2. Duplicate email signup fails with 409 Conflict
    dup_response = client.post(
        "/api/auth/signup",
        json={
            "name": "Duplicate User",
            "email": email,
            "password": password,
        },
    )
    assert dup_response.status_code == 409
    assert dup_response.json()["detail"] == "An account with this email address already exists."


def test_login_success_and_invalid_password(client: TestClient):
    """Test login with valid credentials (200) and invalid password (401)."""
    email = f"user_login_{uuid.uuid4().hex[:8]}@example.com"
    password = "Str0ng!Pass123"

    # Create account first
    signup_res = client.post(
        "/api/auth/signup",
        json={"name": "Login User", "email": email, "password": password},
    )
    assert signup_res.status_code == 201

    # 1. Correct password login succeeds
    login_res = client.post(
        "/api/auth/login",
        json={"email": email, "password": password},
    )
    assert login_res.status_code == 200
    assert "access_token" in login_res.json()

    # 2. Invalid password login fails with 401
    bad_login_res = client.post(
        "/api/auth/login",
        json={"email": email, "password": "WrongPassword!999"},
    )
    assert bad_login_res.status_code == 401
    assert bad_login_res.json()["detail"] == "Invalid email or password."


def test_email_verification_and_profile_access_protection(client: TestClient, db_session: Session):
    """Test profile route 403 when unverified, resend link, verify email, and 200 when verified."""
    email = f"user_verify_{uuid.uuid4().hex[:8]}@example.com"
    password = "Str0ng!Pass123"

    # Signup
    signup_res = client.post(
        "/api/auth/signup",
        json={"name": "Verification User", "email": email, "password": password},
    )
    assert signup_res.status_code == 201
    access_token = signup_res.json()["access_token"]

    # 1. Unverified access to profile me fails with 403 Forbidden
    profile_res = client.get(
        "/api/profile/me",
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert profile_res.status_code == 403
    assert (
        profile_res.json()["detail"] == "Please verify your email address to view profile details."
    )

    # 2. Resend verification link
    resend_res = client.post("/api/auth/resend-verification", json={"email": email})
    assert resend_res.status_code == 200

    # 3. Fetch user and token from DB to simulate user clicking link
    user = db_session.query(User).filter(User.email == email).first()
    assert user is not None
    assert user.is_email_verified is False

    raw_token = generate_secure_token()
    token_hash = hash_token(raw_token)
    create_email_verification_token(db_session, user_id=user.id, token_hash=token_hash)

    # 4. Verify email using valid token
    verify_res = client.get(f"/api/auth/verify-email?token={raw_token}")
    assert verify_res.status_code == 200
    assert "successfully verified" in verify_res.json()["message"]

    # 5. Access profile me after verification succeeds with 200 OK
    profile_verified_res = client.get(
        "/api/profile/me",
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert profile_verified_res.status_code == 200
    assert profile_verified_res.json()["email"] == email
    assert profile_verified_res.json()["is_email_verified"] is True


def test_forgot_and_reset_password_flow(client: TestClient, db_session: Session):
    """Test forgot-password, reset-password, old password rejection, new password login, and single-use token."""
    email = f"user_reset_{uuid.uuid4().hex[:8]}@example.com"
    old_password = "Old!Password123"
    new_password = "N3w!Password999"

    # Signup
    signup_res = client.post(
        "/api/auth/signup",
        json={"name": "Reset User", "email": email, "password": old_password},
    )
    assert signup_res.status_code == 201

    # 1. Forgot password request
    forgot_res = client.post("/api/auth/forgot-password", json={"email": email})
    assert forgot_res.status_code == 200

    # Create active reset token in DB for test
    user = db_session.query(User).filter(User.email == email).first()
    assert user is not None

    raw_reset_token = generate_secure_token()
    reset_hash = hash_token(raw_reset_token)

    from app.features.auth.repository import create_password_reset_token

    create_password_reset_token(
        db_session, user_id=user.id, token_hash=reset_hash, expires_in_minutes=15
    )

    # 2. Reset password using token
    reset_res = client.post(
        "/api/auth/reset-password",
        json={"token": raw_reset_token, "new_password": new_password},
    )
    assert reset_res.status_code == 200

    # 3. Old password login fails
    old_login_res = client.post(
        "/api/auth/login",
        json={"email": email, "password": old_password},
    )
    assert old_login_res.status_code == 401

    # 4. New password login succeeds
    new_login_res = client.post(
        "/api/auth/login",
        json={"email": email, "password": new_password},
    )
    assert new_login_res.status_code == 200
    assert "access_token" in new_login_res.json()

    # 5. Reusing reset token fails with 400
    reuse_res = client.post(
        "/api/auth/reset-password",
        json={"token": raw_reset_token, "new_password": "AnotherPass!123"},
    )
    assert reuse_res.status_code == 400
    assert reuse_res.json()["detail"] == "Invalid or expired password reset token."


def test_httponly_cookie_auth_and_logout(client: TestClient, db_session: Session):
    """Test login sets httpOnly cookies, cookies authenticate requests without Bearer header, and logout clears cookies."""
    email = f"user_cookie_{uuid.uuid4().hex[:8]}@example.com"
    password = "Str0ng!Pass123"

    # 1. Signup sets httpOnly cookies
    signup_res = client.post(
        "/api/auth/signup",
        json={"name": "Cookie User", "email": email, "password": password},
    )
    assert signup_res.status_code == 201
    assert "access_token" in signup_res.cookies
    assert "refresh_token" in signup_res.cookies

    # Mark user email verified in DB for profile test
    user = db_session.query(User).filter(User.email == email).first()
    assert user is not None
    user.is_email_verified = True
    db_session.commit()

    # 2. Login sets httpOnly cookies
    login_res = client.post(
        "/api/auth/login",
        json={"email": email, "password": password},
    )
    assert login_res.status_code == 200
    assert "access_token" in login_res.cookies
    assert "refresh_token" in login_res.cookies

    # 3. Access protected route using httpOnly cookie (NO Authorization header!)
    profile_res = client.get("/api/profile/me", cookies=login_res.cookies)
    assert profile_res.status_code == 200
    assert profile_res.json()["email"] == email

    # 4. Refresh tokens using httpOnly cookie
    refresh_res = client.post("/api/auth/refresh", cookies=login_res.cookies)
    assert refresh_res.status_code == 200
    assert "access_token" in refresh_res.cookies

    # 5. Logout clears cookies
    logout_res = client.post("/api/auth/logout", cookies=refresh_res.cookies)
    assert logout_res.status_code == 200
    assert "access_token" not in logout_res.cookies or logout_res.cookies.get("access_token") in (
        "",
        None,
    )
