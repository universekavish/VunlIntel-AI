"""Tenant-isolated LangGraph investigation APIs."""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException

from app.api.dependencies import DatabaseSession, require_roles
from app.db.models import User
from app.schemas.investigations import (
    ApprovalRequest,
    InvestigationCreate,
    InvestigationRead,
)
from app.schemas.roles import UserRole
from app.workflows.service import (
    create_investigation,
    get_investigation,
    list_investigations,
    resume_investigation,
)

router = APIRouter(prefix="/investigations", tags=["investigations"])
AnalystOrHigher = Annotated[
    User,
    Depends(require_roles(UserRole.OWNER, UserRole.ADMIN, UserRole.ANALYST)),
]
ViewerOrHigher = Annotated[
    User,
    Depends(
        require_roles(
            UserRole.OWNER,
            UserRole.ADMIN,
            UserRole.ANALYST,
            UserRole.VIEWER,
        )
    ),
]


@router.post("", response_model=InvestigationRead)
def start_investigation(
    payload: InvestigationCreate,
    user: AnalystOrHigher,
    session: DatabaseSession,
) -> InvestigationRead:
    investigation, _ = create_investigation(
        session,
        organization_id=user.organization_id,
        actor=user,
        asset_id=payload.asset_id,
        cve_id=payload.cve_id,
        query=payload.query,
    )
    return InvestigationRead.model_validate(investigation)


@router.get("", response_model=list[InvestigationRead])
def investigations(
    user: ViewerOrHigher,
    session: DatabaseSession,
) -> list[InvestigationRead]:
    rows = list_investigations(
        session,
        organization_id=user.organization_id,
    )
    return [InvestigationRead.model_validate(row) for row in rows]


@router.get("/{investigation_id}", response_model=InvestigationRead)
def investigation(
    investigation_id: UUID,
    user: ViewerOrHigher,
    session: DatabaseSession,
) -> InvestigationRead:
    row = get_investigation(
        session,
        organization_id=user.organization_id,
        investigation_id=investigation_id,
    )
    if row is None:
        raise HTTPException(status_code=404, detail="Investigation not found")
    return InvestigationRead.model_validate(row)


@router.post("/{investigation_id}/approve", response_model=InvestigationRead)
def approve_investigation(
    investigation_id: UUID,
    payload: ApprovalRequest,
    user: AnalystOrHigher,
    session: DatabaseSession,
) -> InvestigationRead:
    row = get_investigation(
        session,
        organization_id=user.organization_id,
        investigation_id=investigation_id,
    )
    if row is None:
        raise HTTPException(status_code=404, detail="Investigation not found")
    if row.status not in {"waiting_approval", "running"}:
        raise HTTPException(status_code=409, detail="Investigation is not awaiting approval")
    resume_investigation(
        session,
        investigation=row,
        actor=user,
        approved=payload.approved,
        reviewer=payload.reviewer,
        rationale=payload.rationale,
    )
    return InvestigationRead.model_validate(row)
