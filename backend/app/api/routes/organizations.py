"""Tenant-scoped organization and membership endpoints."""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Response, status

from app.api.dependencies import CurrentUser, DatabaseSession, require_roles
from app.db.models import User
from app.schemas.identity import OrganizationRead, UserRead
from app.schemas.organizations import (
    MemberCreate,
    MemberList,
    MemberRoleUpdate,
)
from app.schemas.roles import UserRole
from app.services.organizations import (
    create_member,
    current_organization,
    deactivate_member,
    organization_members,
    update_member_role,
)

router = APIRouter(prefix="/organizations/current", tags=["organizations"])
OwnerOrAdmin = Annotated[
    User,
    Depends(require_roles(UserRole.OWNER, UserRole.ADMIN)),
]
Owner = Annotated[User, Depends(require_roles(UserRole.OWNER))]


@router.get("", response_model=OrganizationRead)
def get_current_organization(
    user: CurrentUser,
    session: DatabaseSession,
) -> OrganizationRead:
    """Return the tenant selected by the authenticated database identity."""
    organization = current_organization(session, user.organization_id)
    return OrganizationRead.model_validate(organization)


@router.get("/members", response_model=MemberList)
def list_members(
    user: OwnerOrAdmin,
    session: DatabaseSession,
) -> MemberList:
    """List only users belonging to the authenticated tenant."""
    return MemberList(
        members=[
            UserRead.model_validate(member)
            for member in organization_members(session, user.organization_id)
        ]
    )


@router.post(
    "/members",
    response_model=UserRead,
    status_code=status.HTTP_201_CREATED,
)
def add_member(
    payload: MemberCreate,
    user: OwnerOrAdmin,
    session: DatabaseSession,
) -> UserRead:
    """Create a member scoped to the authenticated user's organization."""
    member = create_member(
        session,
        actor=user,
        display_name=payload.display_name,
        email=str(payload.email),
        password=payload.password,
        role=payload.role,
    )
    return UserRead.model_validate(member)


@router.patch("/members/{member_id}/role", response_model=UserRead)
def change_member_role(
    member_id: UUID,
    payload: MemberRoleUpdate,
    user: Owner,
    session: DatabaseSession,
) -> UserRead:
    """Change a non-owner's role; ownership cannot be transferred via this endpoint."""
    member = update_member_role(
        session,
        actor=user,
        member_id=member_id,
        role=payload.role,
    )
    return UserRead.model_validate(member)


@router.delete(
    "/members/{member_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    response_class=Response,
)
def remove_member(
    member_id: UUID,
    user: OwnerOrAdmin,
    session: DatabaseSession,
) -> Response:
    """Deactivate an in-tenant member without deleting their audit history."""
    deactivate_member(session, actor=user, member_id=member_id)
    return Response(status_code=status.HTTP_204_NO_CONTENT)
