"""Signed short-lived access-token creation and validation."""

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import jwt
from jwt.exceptions import InvalidTokenError

from app.core.config import Settings, get_settings
from app.db.models import User

ALGORITHM = "HS256"


def create_access_token(user: User, settings: Settings | None = None) -> tuple[str, int]:
    """Issue a signed bearer token with the current identity and role claims."""
    current_settings = settings or get_settings()
    ttl_seconds = current_settings.access_token_ttl_minutes * 60
    now = datetime.now(UTC)
    claims = {
        "sub": str(user.id),
        "org_id": str(user.organization_id),
        "role": user.role,
        "token_type": "access",
        "jti": str(uuid4()),
        "iat": now,
        "exp": now + timedelta(seconds=ttl_seconds),
        "iss": current_settings.jwt_issuer,
        "aud": current_settings.jwt_audience,
    }
    token = jwt.encode(
        claims,
        current_settings.jwt_secret.get_secret_value(),
        algorithm=ALGORITHM,
    )
    return token, ttl_seconds


def decode_access_token(
    token: str,
    settings: Settings | None = None,
) -> dict[str, object]:
    """Validate token signature and standard claims, raising on invalid tokens."""
    current_settings = settings or get_settings()
    claims = jwt.decode(
        token,
        current_settings.jwt_secret.get_secret_value(),
        algorithms=[ALGORITHM],
        audience=current_settings.jwt_audience,
        issuer=current_settings.jwt_issuer,
        options={"require": ["sub", "exp", "iat", "jti", "iss", "aud"]},
    )
    if claims.get("token_type") != "access":
        raise InvalidTokenError("Unexpected token type")
    return claims
