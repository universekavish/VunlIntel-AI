"""Pydantic contracts for RAG indexing and evidence retrieval."""

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, Field


class RagSearchRequest(BaseModel):
    query: str = Field(min_length=1, max_length=2000)
    limit: int = Field(default=5, ge=1, le=50)
    hybrid: bool = True
    rerank: bool = False
    source_types: list[str] | None = None
    document_types: list[str] | None = None
    source_ids: list[str] | None = None


class RagEvidenceRead(BaseModel):
    source: str
    source_id: str
    document_type: str
    text: str
    citation: str
    score: float
    metadata: dict[str, object]
    citation_valid: bool


class RagSearchResponse(BaseModel):
    evidence: list[RagEvidenceRead]
    query: str
    organization_id: UUID


class RagIndexResponse(BaseModel):
    id: UUID
    organization_id: UUID
    status: str
    documents_found: int
    chunks_embedded: int
    chunks_skipped: int
    errors: int
    collection_name: str
    started_at: datetime
    completed_at: datetime | None
    error_summary: str | None
