"""Audit event persistence."""

from typing import Any
from uuid import UUID

from sqlalchemy.orm import Session

from app.db.models import AuditEvent


def add_audit_event(
    session: Session,
    *,
    organization_id: UUID,
    actor_user_id: UUID | None,
    action: str,
    subject_user_id: UUID | None = None,
    details: dict[str, Any] | None = None,
) -> None:
    """Stage a security audit event in the active transaction."""
    session.add(
        AuditEvent(
            organization_id=organization_id,
            actor_user_id=actor_user_id,
            action=action,
            subject_user_id=subject_user_id,
            details=details or {},
        )
    )
