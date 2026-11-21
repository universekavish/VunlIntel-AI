"""Contracts for organization membership management."""

from pydantic import BaseModel, EmailStr, field_validator

from app.schemas.auth import DisplayName, Password
from app.schemas.identity import UserRead
from app.schemas.roles import AssignableRole, UserRole


class MemberCreate(BaseModel):
    """Input for adding a user directly to the authenticated organization."""

    display_name: DisplayName
    email: EmailStr
    password: Password
    role: AssignableRole = UserRole.VIEWER

    @field_validator("email")
    @classmethod
    def normalize_email(cls, value: EmailStr) -> str:
        return str(value).strip().casefold()


class MemberRoleUpdate(BaseModel):
    """Input for an organization owner changing a member's role."""

    role: AssignableRole


class MemberList(BaseModel):
    """Organization members returned by the administrative listing endpoint."""

    members: list[UserRead]
