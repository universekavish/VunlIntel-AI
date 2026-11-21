"""RAG provider construction and tenant-isolated retrieval service."""

from uuid import UUID

from app.core.config import get_settings
from app.rag.embeddings import (
    DeterministicHashEmbedding,
    SentenceTransformerEmbedding,
)
from app.rag.vectorstore import QdrantKnowledgeStore, RetrievedEvidence


def build_vectorstore() -> QdrantKnowledgeStore:
    settings = get_settings()
    if settings.rag_embedding_provider.casefold() == "deterministic":
        embeddings = DeterministicHashEmbedding(settings.rag_embedding_dimensions)
    else:
        embeddings = SentenceTransformerEmbedding(
            settings.rag_embedding_model,
            settings.rag_embedding_dimensions,
        )
    return QdrantKnowledgeStore(
        url=settings.qdrant_url,
        base_collection=settings.rag_vectorstore_collection,
        embeddings=embeddings,
    )


def build_test_vectorstore(dimensions: int = 384) -> QdrantKnowledgeStore:
    """Build an offline test/vectorstore instance with no downloaded model."""
    embeddings = DeterministicHashEmbedding(dimensions)
    return QdrantKnowledgeStore(
        url="http://qdrant:6333",
        base_collection="vulnintel-test",
        embeddings=embeddings,
    )


def retrieve(
    store: QdrantKnowledgeStore,
    *,
    organization_id: UUID,
    query: str,
    limit: int = 5,
    hybrid: bool = True,
    rerank: bool = False,
    source_types: list[str] | None = None,
    document_types: list[str] | None = None,
    source_ids: list[str] | None = None,
) -> list[RetrievedEvidence]:
    """Retrieve evidence while always applying the organization boundary."""
    return store.search(
        organization_id=organization_id,
        query=query,
        limit=limit,
        hybrid=hybrid,
        rerank=rerank,
        source_types=source_types,
        document_types=document_types,
        source_ids=source_ids,
    )
