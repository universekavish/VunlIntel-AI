"""Report assembly and SQL audit persistence nodes."""

from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from sqlalchemy.orm import Session

from app.db.models import Investigation, InvestigationAudit
from app.workflows.state import InvestigationState


def report_persistence(
    state: InvestigationState,
    *,
    session: Session,
) -> InvestigationState:
    """Persist a structured investigation report and append workflow audit events."""
    investigation_id = UUID(state["investigation_id"])
    investigation = session.get(Investigation, investigation_id)
    if investigation is None:
        return {
            "status": "failed",
            "error": "Investigation record not found",
        }
    report: dict[str, Any] = {
        "investigation_id": state["investigation_id"],
        "entity_ids": state.get("entities") or [],
        "risk": state.get("risk"),
        "analysis": state.get("analysis"),
        "recommendations": state.get("recommendations") or [],
        "validated_evidence": state.get("validated_evidence") or [],
        "unsupported_claims": ((state.get("analysis") or {}).get("unsupported_claims") or []),
        "approval": state.get("approval"),
    }
    investigation.report = report
    investigation.state = dict(state)
    investigation.approval = state.get("approval")
    investigation.updated_at = datetime.now(UTC)
    final_status = state.get("status")
    if final_status not in {"approved", "rejected"}:
        final_status = "completed" if state.get("approval_status") == "approved" else "completed"
    investigation.status = final_status
    investigation.error_summary = state.get("error")
    for audit in state.get("audit_events") or []:
        session.add(
            InvestigationAudit(
                investigation_id=investigation.id,
                organization_id=investigation.organization_id,
                actor_user_id=investigation.initiated_by,
                event=str(audit["event"]),
                details=audit.get("details") or {},
            )
        )
    session.commit()
    return {
        "report": report,
        "status": final_status,
        "audit_events": [
            {
                "event": "report_persisted",
                "details": {"investigation_id": state["investigation_id"]},
            }
        ],
    }
