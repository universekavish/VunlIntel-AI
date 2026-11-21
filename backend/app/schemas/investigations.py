"""Pydantic contracts for persisted LangGraph investigations."""

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, Field


class InvestigationCreate(BaseModel):
    asset_id: UUID | None = None
    cve_id: str | None = Field(default=None, max_length=32)
    query: str = Field(default="", max_length=2000)


class ApprovalRequest(BaseModel):
    approved: bool
    reviewer: str = Field(min_length=1, max_length=120)
    rationale: str = Field(max_length=5000, default="")


class InvestigationRead(BaseModel):
    id: UUID
    organization_id: UUID
    asset_id: UUID | None
    initiated_by: UUID
    cve_id: str | None
    status: Literal[
        "running",
        "waiting_approval",
        "approved",
        "rejected",
        "completed",
        "failed",
    ]
    state: dict[str, object]
    report: dict[str, object] | None
    approval: dict[str, object] | None
    error_summary: str | None
    langgraph_thread_id: str
    created_at: datetime
    updated_at: datetime
