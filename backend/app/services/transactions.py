"""Shared database transaction helpers for application services."""

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.exceptions import ResourceConflictError


def commit_or_raise_conflict(session: Session, message: str) -> None:
    """Commit a unit of work and translate unique-key races to a safe conflict."""
    try:
        session.commit()
    except IntegrityError as exc:
        session.rollback()
        original = exc.orig
        sqlstate = getattr(original, "sqlstate", None) or getattr(original, "pgcode", None)
        is_unique_violation = sqlstate == "23505" or "UNIQUE constraint failed" in str(original)
        if not is_unique_violation:
            raise
        raise ResourceConflictError(message) from exc
