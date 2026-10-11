import pytest
from pydantic import ValidationError

from app.core.security import generate_secure_token, hash_token
from app.features.auth.schema import SignUpRequest


def test_password_strength_validation_pass():
    """Test valid strong password passes Pydantic validation."""
    payload = SignUpRequest(
        name="Valid User",
        email="valid@example.com",
        password="Str0ng!Pass123",
    )
    assert payload.password == "Str0ng!Pass123"


def test_password_strength_validation_fail_missing_uppercase():
    """Test password missing uppercase letter fails validation."""
    with pytest.raises(ValidationError) as exc_info:
        SignUpRequest(
            name="Weak User",
            email="weak@example.com",
            password="weak!password123",
        )
    assert "Password must contain at least one uppercase letter" in str(exc_info.value)


def test_password_strength_validation_fail_missing_special_char():
    """Test password missing special character fails validation."""
    with pytest.raises(ValidationError) as exc_info:
        SignUpRequest(
            name="Weak User",
            email="weak@example.com",
            password="WeakPassword123",
        )
    assert "Password must contain at least one special character" in str(exc_info.value)


def test_secure_token_generation_and_hashing():
    """Test token generator produces unique hex strings and sha256 hashing works deterministically."""
    token1 = generate_secure_token()
    token2 = generate_secure_token()

    assert len(token1) == 64  # 32 bytes = 64 hex chars
    assert len(token2) == 64
    assert token1 != token2

    hash1 = hash_token(token1)
    hash2 = hash_token(token1)

    assert hash1 == hash2  # Deterministic hashing
    assert len(hash1) == 64  # SHA-256 = 64 hex chars
