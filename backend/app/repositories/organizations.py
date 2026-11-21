"""Organization persistence queries."""

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models import Organization


def get_organization(session: Session, organization_id: object) -> Organization | None:
    """Fetch an organization by its primary key."""
    return session.get(Organization, organization_id)


def find_organization_by_slug(session: Session, slug: str) -> Organization | None:
    """Find an organization by its unique URL slug."""
    return session.scalar(select(Organization).where(Organization.slug == slug))


def add_organization(session: Session, organization: Organization) -> None:
    """Stage an organization for the current transaction."""
    session.add(organization)
