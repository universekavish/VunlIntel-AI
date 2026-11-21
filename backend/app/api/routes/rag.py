"""Tenant-isolated RAG indexing and retrieval endpoints."""

from typing import Annotated

from fastapi import APIRouter, Depends

from app.api.dependencies import DatabaseSession, require_roles
from app.db.models import User
from app.rag.indexing import run_incremental_index, validate_citation
from app.rag.service import build_vectorstore, retrieve
from app.schemas.rag import (
    RagEvidenceRead,
    RagIndexResponse,
    RagSearchRequest,
    RagSearchResponse,
)
from app.schemas.roles import UserRole

router = APIRouter(prefix="/rag", tags=["rag"])
OwnerAdminAnalyst = Annotated[
    User,
    Depends(
        require_roles(
            UserRole.OWNER,
            UserRole.ADMIN,
            UserRole.ANALYST,
        )
    ),
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


@router.post("/index", response_model=RagIndexResponse)
def index_knowledge(
    user: OwnerAdminAnalyst,
    session: DatabaseSession,
) -> RagIndexResponse:
    """Incrementally embed normalized and vendor-advisory records."""
    store = build_vectorstore()
    collection = store.ensure_collection(user.organization_id)
    run = run_incremental_index(
        session,
        organization_id=user.organization_id,
        collection_name=collection,
        vectorstore=store,
    )
    return RagIndexResponse.model_validate(run)


@router.post("/search", response_model=RagSearchResponse)
def search_knowledge(
    payload: RagSearchRequest,
    user: ViewerOrHigher,
    session: DatabaseSession,
) -> RagSearchResponse:
    """Search evidence from the current tenant's isolated vector collection."""
    store = build_vectorstore()
    evidence = retrieve(
        store,
        organization_id=user.organization_id,
        query=payload.query,
        limit=payload.limit,
        hybrid=payload.hybrid,
        rerank=payload.rerank,
        source_types=payload.source_types,
        document_types=payload.document_types,
        source_ids=payload.source_ids,
    )
    validated = []
    for item in evidence:
        if not validate_citation(session, item):
            continue
        validated.append(
            RagEvidenceRead(
                source=item.source,
                source_id=item.source_id,
                document_type=item.document_type,
                text=item.text,
                citation=item.citation,
                score=item.score,
                metadata=item.metadata,
                citation_valid=True,
            )
        )
    return RagSearchResponse(
        evidence=validated,
        query=payload.query,
        organization_id=user.organization_id,
    )
