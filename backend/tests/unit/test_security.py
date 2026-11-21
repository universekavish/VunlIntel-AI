"""Unit tests for password hashing and access-token validation."""

from uuid import uuid4

import pytest
from jwt.exceptions import InvalidTokenError
from pydantic import SecretStr, ValidationError

from app.core.config import LOCAL_DEVELOPMENT_SECRET, Settings
from app.core.security.passwords import hash_password, verify_password
from app.core.security.tokens import create_access_token, decode_access_token
from app.db.models import User


@pytest.fixture
def settings() -> Settings:
    return Settings(
        database_url="sqlite://",
        jwt_secret=SecretStr("unit-test-signing-key-with-at-least-32-bytes"),
        jwt_issuer="unit-test-issuer",
        jwt_audience="unit-test-audience",
        environment="test",
    )


def test_passwords_are_argon2_hashed_and_verified() -> None:
    plain_password = "Correct horse battery staple 73!"
    stored_hash = hash_password(plain_password)

    assert stored_hash != plain_password
    assert stored_hash.startswith("$argon2")
    assert verify_password(plain_password, stored_hash)
    assert not verify_password("incorrect password", stored_hash)
    assert not verify_password(plain_password, None)


def test_access_token_has_expected_identity_and_expiration(settings: Settings) -> None:
    user = User(
        id=uuid4(),
        organization_id=uuid4(),
        email="analyst@example.test",
        display_name="Analyst",
        password_hash="not-used-in-this-test",
        role="analyst",
        is_active=True,
    )

    token, expires_in = create_access_token(user, settings)
    claims = decode_access_token(token, settings)

    assert expires_in == settings.access_token_ttl_minutes * 60
    assert claims["sub"] == str(user.id)
    assert claims["org_id"] == str(user.organization_id)
    assert claims["role"] == "analyst"
    assert claims["token_type"] == "access"


def test_access_token_rejects_wrong_signing_secret(settings: Settings) -> None:
    user = User(
        id=uuid4(),
        organization_id=uuid4(),
        email="viewer@example.test",
        display_name="Viewer",
        password_hash="not-used-in-this-test",
        role="viewer",
        is_active=True,
    )
    token, _ = create_access_token(user, settings)
    other_settings = settings.model_copy(
        update={"jwt_secret": SecretStr("another-test-signing-key-of-32-bytes")}
    )

    with pytest.raises(InvalidTokenError):
        decode_access_token(token, other_settings)


def test_settings_reject_local_signing_secret_outside_development() -> None:
    with pytest.raises(ValidationError):
        Settings(
            database_url="sqlite://",
            jwt_secret=SecretStr(LOCAL_DEVELOPMENT_SECRET),
            environment="production",
        )


def test_settings_reject_out_of_range_token_lifetime() -> None:
    with pytest.raises(ValidationError):
        Settings(
            database_url="sqlite://",
            jwt_secret=SecretStr("unit-test-signing-key-with-at-least-32-bytes"),
            access_token_ttl_minutes=0,
            environment="test",
        )
