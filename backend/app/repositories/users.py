"""Tenant-scoped user persistence queries."""

from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models import User


def find_user_by_email(session: Session, email: str) -> User | None:
    """Find a user by their normalized sign-in email."""
    return session.scalar(select(User).where(User.email == email))


def get_user(session: Session, user_id: UUID) -> User | None:
    """Fetch a user by primary key."""
    return session.get(User, user_id)


def get_organization_member(
    session: Session,
    organization_id: UUID,
    user_id: UUID,
) -> User | None:
    """Fetch a member only when the requested user belongs to the given tenant."""
    return session.scalar(
        select(User).where(
            User.id == user_id,
            User.organization_id == organization_id,
        )
    )


def list_organization_members(session: Session, organization_id: UUID) -> list[User]:
    """List users from exactly one organization."""
    statement = (
        select(User)
        .where(User.organization_id == organization_id)
        .order_by(User.created_at, User.email)
    )
    return list(session.scalars(statement))


def add_user(session: Session, user: User) -> None:
    """Stage a user for the current transaction."""
    session.add(user)
