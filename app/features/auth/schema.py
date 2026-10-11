import re

from pydantic import BaseModel, EmailStr, Field, field_validator


# Request schemas
class SignUpRequest(BaseModel):
    name: str = Field(
        ...,
        min_length=2,
        max_length=100,
        examples=["Jane Doe"],
        description="Full display name of the user.",
    )
    email: EmailStr = Field(
        ...,
        examples=["jane@example.com"],
        description="Unique email address used for login.",
    )
    password: str = Field(
        ...,
        min_length=8,
        max_length=128,
        examples=["Str0ng!Pass"],
        description="Plain-text password (will be hashed before storage).",
    )

    @field_validator("password")
    @classmethod
    def validate_password_strength(cls, v: str) -> str:
        if not re.search(r"[A-Z]", v):
            raise ValueError("Password must contain at least one uppercase letter")
        if not re.search(r"[a-z]", v):
            raise ValueError("Password must contain at least one lowercase letter")
        if not re.search(r"\d", v):
            raise ValueError("Password must contain at least one digit")
        if not re.search(r"[!@#$%^&*(),.?\":{}|<>\-_=+\\|/[\]~`]", v):
            raise ValueError("Password must contain at least one special character")
        return v


# Request schema for the login route
class LoginRequest(BaseModel):
    email: EmailStr = Field(
        ...,
        examples=["jane@example.com"],
        description="Registered email address.",
    )
    password: str = Field(
        ...,
        min_length=8,
        max_length=128,
        examples=["Str0ng!Pass"],
        description="Account password.",
    )


# Request schema for token refresh
class RefreshTokenRequest(BaseModel):
    refresh_token: str | None = Field(
        default=None,
        description="Opaque refresh token received from login or signup.",
    )


# Request schema for forgot password
class ForgotPasswordRequest(BaseModel):
    email: EmailStr = Field(
        ...,
        examples=["jane@example.com"],
        description="Registered account email address.",
    )


# Request schema for reset password
class ResetPasswordRequest(BaseModel):
    token: str = Field(
        ...,
        description="Password reset token received from the forgot-password email link.",
    )
    new_password: str = Field(
        ...,
        min_length=8,
        max_length=128,
        examples=["Str0ng!NewPass"],
        description="New plain-text password.",
    )

    @field_validator("new_password")
    @classmethod
    def validate_password_strength(cls, v: str) -> str:
        if not re.search(r"[A-Z]", v):
            raise ValueError("Password must contain at least one uppercase letter")
        if not re.search(r"[a-z]", v):
            raise ValueError("Password must contain at least one lowercase letter")
        if not re.search(r"\d", v):
            raise ValueError("Password must contain at least one digit")
        if not re.search(r"[!@#$%^&*(),.?\":{}|<>\-_=+\\|/[\]~`]", v):
            raise ValueError("Password must contain at least one special character")
        return v


# Response schemas
class UserResponse(BaseModel):
    id: int
    name: str
    email: EmailStr
    role: str

    model_config = {"from_attributes": True}


# Response schema for the signup/login/refresh route
class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    user: UserResponse
    message: str | None = None



# Response schema for the logout route
class LogoutResponse(BaseModel):
    message: str = "Successfully logged out."


# Response schema for forgot password route
class ForgotPasswordResponse(BaseModel):
    message: str = "A password reset link has been sent to your email address."


# Response schema for reset password route
class ResetPasswordResponse(BaseModel):
    message: str = (
        "Password has been successfully reset. You can now log in with your new password."
    )


# Request & Response schemas for Email Verification
class VerifyEmailRequest(BaseModel):
    token: str = Field(
        ...,
        description="Email verification token received from the verification email link.",
    )


class VerifyEmailResponse(BaseModel):
    message: str = "Email has been successfully verified."


class ResendVerificationRequest(BaseModel):
    email: EmailStr = Field(
        ...,
        examples=["jane@example.com"],
        description="Registered email address to resend verification link to.",
    )


class ResendVerificationResponse(BaseModel):
    message: str = "A verification link has been sent to your email address."
