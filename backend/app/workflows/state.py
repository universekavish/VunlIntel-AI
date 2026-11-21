"""Typed state contracts for the investigation LangGraph workflow."""

from operator import add
from typing import Annotated, Any, Literal, TypedDict


class EvidenceRecord(TypedDict):
    source: str
    source_id: str
    document_type: str
    citation: str
    text: str
    score: float
    validated: bool
    reason: str


class Recommendation(TypedDict):
    action: str
    rationale: str
    evidence_citations: list[str]
    patch_allowed: bool
    requires_human_approval: bool


class AnalysisReport(TypedDict):
    summary: str
    entity_ids: list[str]
    evidence_citations: list[str]
    recommendations: list[Recommendation]
    unsupported_claims: list[str]
    confidence: float


class InvestigationState(TypedDict, total=False):
    investigation_id: str
    organization_id: str
    initiated_by: str
    asset_id: str | None
    cve_id: str | None
    query: str
    entities: list[str]
    vulnerability_records: list[dict[str, Any]]
    threat_records: list[dict[str, Any]]
    evidence: list[EvidenceRecord]
    validated_evidence: list[EvidenceRecord]
    risk: dict[str, Any] | None
    analysis: AnalysisReport | None
    recommendations: list[Recommendation]
    approval: dict[str, Any] | None
    approval_status: Literal["pending", "approved", "rejected"] | None
    report: dict[str, Any] | None
    audit_events: Annotated[list[dict[str, Any]], add]
    retrieval_attempts: dict[str, int]
    retrieval_errors: list[str]
    status: Literal[
        "running",
        "waiting_approval",
        "approved",
        "rejected",
        "completed",
        "failed",
    ]
    error: str | None
