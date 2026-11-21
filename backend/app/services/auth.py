"""Organization registration and user authentication workflows."""

import re
import unicodedata
from uuid import uuid4

from sqlalchemy.orm import Session

from app.core.exceptions import InvalidCredentialsError, ResourceConflictError
from app.core.security.passwords import hash_password, verify_password
from app.db.models import Organization, User
from app.repositories.audit import add_audit_event
from app.repositories.organizations import add_organization, find_organization_by_slug
from app.repositories.users import add_user, find_user_by_email
from app.schemas.roles import UserRole
from app.services.transactions import commit_or_raise_conflict


def organization_slug(name: str) -> str:
    """Create a stable ASCII slug from an organization name."""
    normalized = unicodedata.normalize("NFKD", name).encode("ascii", "ignore").decode()
    slug = re.sub(r"[^a-z0-9]+", "-", normalized.casefold()).strip("-")
    return slug or f"organization-{uuid4().hex[:8]}"


def register_organization(
    session: Session,
    *,
    organization_name: str,
    display_name: str,
    email: str,
    password: str,
) -> tuple[Organization, User]:
    """Create a new tenant and its initial owner atomically."""
    slug = organization_slug(organization_name)
    if find_organization_by_slug(session, slug) or find_user_by_email(session, email):
        raise ResourceConflictError("An organization or account already exists for these details")

    organization = Organization(id=uuid4(), name=organization_name, slug=slug)
    add_organization(session, organization)

    owner = User(
        id=uuid4(),
        organization_id=organization.id,
        email=email,
        display_name=display_name,
        password_hash=hash_password(password),
        role=UserRole.OWNER.value,
        is_active=True,
    )
    add_user(session, owner)
    add_audit_event(
        session,
        organization_id=organization.id,
        actor_user_id=owner.id,
        subject_user_id=owner.id,
        action="organization.registered",
    )
    commit_or_raise_conflict(
        session,
        "An organization or account already exists for these details",
    )
    return organization, owner


def authenticate_user(session: Session, *, email: str, password: str) -> User:
    """Authenticate an active user without disclosing whether an email is registered."""
    user = find_user_by_email(session, email)
    valid_password = verify_password(password, user.password_hash if user else None)
    if not valid_password or not user or not user.is_active:
        raise InvalidCredentialsError("Invalid email or password")

    add_audit_event(
        session,
        organization_id=user.organization_id,
        actor_user_id=user.id,
        action="auth.login_succeeded",
        subject_user_id=user.id,
    )
    session.commit()
    return user
