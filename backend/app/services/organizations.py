"""Tenant-scoped organization and membership policies."""

from uuid import UUID, uuid4

from sqlalchemy.orm import Session

from app.core.exceptions import (
    PermissionDeniedError,
    ResourceConflictError,
    ResourceNotFoundError,
)
from app.core.security.passwords import hash_password
from app.db.models import Organization, User
from app.repositories.audit import add_audit_event
from app.repositories.organizations import get_organization
from app.repositories.users import (
    add_user,
    find_user_by_email,
    get_organization_member,
    list_organization_members,
)
from app.schemas.roles import AssignableRole, UserRole
from app.services.transactions import commit_or_raise_conflict


def current_organization(session: Session, organization_id: UUID) -> Organization:
    """Return the authenticated user's organization."""
    organization = get_organization(session, organization_id)
    if organization is None:
        raise ResourceNotFoundError("Organization not found")
    return organization


def organization_members(session: Session, organization_id: UUID) -> list[User]:
    """Return users belonging to one organization only."""
    return list_organization_members(session, organization_id)


def create_member(
    session: Session,
    *,
    actor: User,
    display_name: str,
    email: str,
    password: str,
    role: AssignableRole,
) -> User:
    """Create a member according to the acting owner's or administrator's role."""
    actor_role = UserRole(actor.role)
    if actor_role not in {UserRole.OWNER, UserRole.ADMIN}:
        raise PermissionDeniedError("Only organization owners and administrators can add users")
    if actor_role is UserRole.ADMIN and role is UserRole.ADMIN:
        raise PermissionDeniedError("Administrators cannot create other administrators")
    if find_user_by_email(session, email):
        raise ResourceConflictError("An account already exists for this email")

    member = User(
        id=uuid4(),
        organization_id=actor.organization_id,
        email=email,
        display_name=display_name,
        password_hash=hash_password(password),
        role=role.value,
        is_active=True,
    )
    add_user(session, member)
    add_audit_event(
        session,
        organization_id=actor.organization_id,
        actor_user_id=actor.id,
        subject_user_id=member.id,
        action="organization.member_created",
        details={"role": role.value},
    )
    commit_or_raise_conflict(session, "An account already exists for this email")
    return member


def update_member_role(
    session: Session,
    *,
    actor: User,
    member_id: UUID,
    role: AssignableRole,
) -> User:
    """Allow only an owner to change a non-owner's role within the same tenant."""
    if actor.role != UserRole.OWNER.value:
        raise PermissionDeniedError("Only the organization owner can change member roles")
    if member_id == actor.id:
        raise PermissionDeniedError("The owner cannot change their own role")
    member = get_organization_member(session, actor.organization_id, member_id)
    if member is None:
        raise ResourceNotFoundError("Organization member not found")
    if member.role == UserRole.OWNER.value:
        raise PermissionDeniedError("The owner role cannot be changed through member management")

    previous_role = member.role
    member.role = role.value
    add_audit_event(
        session,
        organization_id=actor.organization_id,
        actor_user_id=actor.id,
        subject_user_id=member.id,
        action="organization.member_role_changed",
        details={"old_role": previous_role, "new_role": role.value},
    )
    session.commit()
    return member


def deactivate_member(session: Session, *, actor: User, member_id: UUID) -> None:
    """Deactivate an in-tenant member while preserving owner and administrator boundaries."""
    actor_role = UserRole(actor.role)
    if actor_role not in {UserRole.OWNER, UserRole.ADMIN}:
        raise PermissionDeniedError(
            "Only organization owners and administrators can deactivate users"
        )
    if member_id == actor.id:
        raise PermissionDeniedError("Users cannot deactivate their own account")
    member = get_organization_member(session, actor.organization_id, member_id)
    if member is None:
        raise ResourceNotFoundError("Organization member not found")
    if member.role == UserRole.OWNER.value:
        raise PermissionDeniedError("The organization owner cannot be deactivated")
    if actor_role is UserRole.ADMIN and member.role == UserRole.ADMIN.value:
        raise PermissionDeniedError("Administrators cannot deactivate other administrators")

    member.is_active = False
    add_audit_event(
        session,
        organization_id=actor.organization_id,
        actor_user_id=actor.id,
        subject_user_id=member.id,
        action="organization.member_deactivated",
    )
    session.commit()
