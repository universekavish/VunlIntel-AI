"""Pydantic contracts for registration and authentication."""

from typing import Annotated

from pydantic import BaseModel, EmailStr, Field, StringConstraints, field_validator

from app.schemas.identity import OrganizationRead, UserRead

Password = Annotated[str, StringConstraints(min_length=12, max_length=128)]
DisplayName = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=120)]
OrganizationName = Annotated[
    str, StringConstraints(strip_whitespace=True, min_length=2, max_length=120)
]


class RegisterRequest(BaseModel):
    """Input for registering an organization and its initial owner."""

    organization_name: OrganizationName
    display_name: DisplayName
    email: EmailStr
    password: Password

    @field_validator("email")
    @classmethod
    def normalize_email(cls, value: EmailStr) -> str:
        return str(value).strip().casefold()


class LoginRequest(BaseModel):
    """Input for an organization user's login."""

    email: EmailStr
    password: Annotated[str, Field(min_length=1, max_length=128)]

    @field_validator("email")
    @classmethod
    def normalize_email(cls, value: EmailStr) -> str:
        return str(value).strip().casefold()


class AuthResponse(BaseModel):
    """Access-token response returned after registration or login."""

    access_token: str
    token_type: str = "bearer"
    expires_in: int
    user: UserRead
    organization: OrganizationRead
