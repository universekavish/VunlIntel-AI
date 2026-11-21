"""Application service for investigation creation and approval resumption."""

from datetime import UTC, datetime
from uuid import UUID, uuid4

from langgraph.types import Command
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.exceptions import ResourceNotFoundError
from app.db.models import Investigation, InvestigationAudit, User
from app.rag.service import build_vectorstore
from app.repositories.assets import get_asset
from app.workflows.checkpoints import postgres_checkpointer
from app.workflows.graph import build_investigation_graph


def add_investigation_audit(
    session: Session,
    *,
    investigation: Investigation,
    actor: User,
    event: str,
    details: dict,
) -> None:
    session.add(
        InvestigationAudit(
            investigation_id=investigation.id,
            organization_id=investigation.organization_id,
            actor_user_id=actor.id,
            event=event,
            details=details,
        )
    )


def create_investigation(
    session: Session,
    *,
    organization_id: UUID,
    actor: User,
    asset_id: UUID | None,
    cve_id: str | None,
    query: str,
) -> tuple[Investigation, dict]:
    if asset_id is not None:
        asset = get_asset(session, organization_id, asset_id)
        if asset is None:
            raise ResourceNotFoundError("Asset not found")
    thread_id = str(uuid4())
    investigation = Investigation(
        id=uuid4(),
        organization_id=organization_id,
        asset_id=asset_id,
        initiated_by=actor.id,
        cve_id=cve_id.upper() if cve_id else None,
        status="running",
        state={
            "investigation_id": "",
            "organization_id": str(organization_id),
            "initiated_by": str(actor.id),
            "asset_id": str(asset_id) if asset_id else None,
            "cve_id": cve_id.upper() if cve_id else None,
            "query": query,
            "audit_events": [],
            "retrieval_attempts": {},
            "retrieval_errors": [],
            "status": "running",
        },
        langgraph_thread_id=thread_id,
        checkpoint_namespace="",
    )
    investigation.state["investigation_id"] = str(investigation.id)
    session.add(investigation)
    session.commit()
    add_investigation_audit(
        session,
        investigation=investigation,
        actor=actor,
        event="investigation_created",
        details={"cve_id": cve_id, "asset_id": str(asset_id) if asset_id else None},
    )
    session.commit()

    store = build_vectorstore()
    with postgres_checkpointer() as checkpointer:
        graph = build_investigation_graph(
            session=session,
            store=store,
            organization_id=organization_id,
            checkpointer=checkpointer,
        )
        result = graph.invoke(
            investigation.state,
            config={"configurable": {"thread_id": thread_id}},
        )
    investigation.status = result.get("status") or "running"
    if investigation.status == "running":
        investigation.status = "waiting_approval"
    investigation.state = dict(result)
    investigation.updated_at = datetime.now(UTC)
    session.commit()
    return investigation, result


def resume_investigation(
    session: Session,
    *,
    investigation: Investigation,
    actor: User,
    approved: bool,
    reviewer: str,
    rationale: str,
) -> dict:
    decision = {
        "approved": approved,
        "reviewer": reviewer,
        "rationale": rationale,
    }
    store = build_vectorstore()
    with postgres_checkpointer() as checkpointer:
        graph = build_investigation_graph(
            session=session,
            store=store,
            organization_id=investigation.organization_id,
            checkpointer=checkpointer,
        )
        result = graph.invoke(
            Command(resume=decision),
            config={
                "configurable": {
                    "thread_id": investigation.langgraph_thread_id,
                }
            },
        )
    investigation.status = "approved" if approved else "rejected"
    investigation.approval = decision
    investigation.state = dict(result)
    investigation.report = result.get("report")
    investigation.updated_at = datetime.now(UTC)
    add_investigation_audit(
        session,
        investigation=investigation,
        actor=actor,
        event="human_approval_decided",
        details=decision,
    )
    session.commit()
    return result


def get_investigation(
    session: Session,
    *,
    organization_id: UUID,
    investigation_id: UUID,
) -> Investigation | None:
    return session.scalar(
        select(Investigation).where(
            Investigation.id == investigation_id,
            Investigation.organization_id == organization_id,
        )
    )


def list_investigations(
    session: Session,
    *,
    organization_id: UUID,
) -> list[Investigation]:
    return list(
        session.scalars(
            select(Investigation)
            .where(Investigation.organization_id == organization_id)
            .order_by(Investigation.updated_at.desc())
        )
    )
