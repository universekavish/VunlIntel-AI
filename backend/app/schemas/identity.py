"""Safe public response schemas for persisted identities."""

from uuid import UUID

from pydantic import BaseModel, ConfigDict, EmailStr

from app.schemas.roles import UserRole


class UserRead(BaseModel):
    """Public user representation that never includes credential material."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    organization_id: UUID
    email: EmailStr
    display_name: str
    role: UserRole
    is_active: bool


class OrganizationRead(BaseModel):
    """Public organization representation."""

    model_config = ConfigDict(from_attributes=True)

    id: UUID
    name: str
    slug: str
