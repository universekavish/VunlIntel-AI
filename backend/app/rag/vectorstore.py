"""Qdrant collection and hybrid retrieval management."""

import re
from dataclasses import dataclass
from typing import Any
from uuid import UUID

from qdrant_client import QdrantClient
from qdrant_client.http import models

from app.rag.embeddings import EmbeddingProvider


@dataclass(frozen=True, slots=True)
class RetrievedEvidence:
    source: str
    source_id: str
    document_type: str
    text: str
    citation: str
    score: float
    metadata: dict[str, Any]


def organization_collection(base_name: str, organization_id: UUID) -> str:
    """Return an organization-specific collection name for defense in depth."""
    safe = re.sub(r"[^a-zA-Z0-9_]", "_", base_name).strip("_").lower()
    return f"{safe or 'vulnintel'}_org_{organization_id.hex}"


def _lexical_score(query: str, text: str) -> float:
    query_terms = {term for term in re.findall(r"[a-z0-9]+", query.casefold()) if len(term) > 1}
    text_terms = {term for term in re.findall(r"[a-z0-9]+", text.casefold()) if len(term) > 1}
    if not query_terms:
        return 0.0
    return len(query_terms & text_terms) / len(query_terms)


class QdrantKnowledgeStore:
    """Dense and hybrid retrieval against organization-isolated Qdrant collections."""

    def __init__(
        self,
        *,
        url: str,
        base_collection: str,
        embeddings: EmbeddingProvider,
    ) -> None:
        self.client = QdrantClient(
            url=url,
            check_compatibility=False,
        )
        self.base_collection = base_collection
        self.embeddings = embeddings

    def collection_name(self, organization_id: UUID) -> str:
        return organization_collection(self.base_collection, organization_id)

    def ensure_collection(self, organization_id: UUID) -> str:
        collection = self.collection_name(organization_id)
        if not self.client.collection_exists(collection):
            self.client.create_collection(
                collection_name=collection,
                vectors_config=models.VectorParams(
                    size=self.embeddings.dimensions,
                    distance=models.Distance.COSINE,
                ),
            )
        for field in ("source", "document_type", "source_id", "organization_id"):
            self.client.create_payload_index(
                collection_name=collection,
                field_name=field,
                field_schema=models.PayloadSchemaType.KEYWORD,
            )
        return collection

    def upsert_documents(
        self,
        *,
        organization_id: UUID,
        documents: list[dict[str, Any]],
    ) -> int:
        if not documents:
            return 0
        collection = self.ensure_collection(organization_id)
        texts = [document["text"] for document in documents]
        vectors = self.embeddings.embed_documents(texts)
        points = [
            models.PointStruct(
                id=document["point_id"],
                vector=vector,
                payload={
                    **document["metadata"],
                    "organization_id": str(organization_id),
                    "source": document["source"],
                    "source_id": document["source_id"],
                    "document_type": document["document_type"],
                    "text": document["text"],
                },
            )
            for document, vector in zip(documents, vectors, strict=True)
        ]
        self.client.upsert(collection_name=collection, points=points)
        return len(points)

    def search(
        self,
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
        collection = self.ensure_collection(organization_id)
        must: list[Any] = [
            models.FieldCondition(
                key="organization_id",
                match=models.MatchValue(value=str(organization_id)),
            )
        ]
        if source_types:
            must.append(
                models.FieldCondition(
                    key="source",
                    match=models.MatchAny(any=source_types),
                )
            )
        if document_types:
            must.append(
                models.FieldCondition(
                    key="document_type",
                    match=models.MatchAny(any=document_types),
                )
            )
        if source_ids:
            must.append(
                models.FieldCondition(
                    key="source_id",
                    match=models.MatchAny(any=source_ids),
                )
            )
        query_filter = models.Filter(must=must)
        query_vector = self.embeddings.embed_query(query)
        response = self.client.query_points(
            collection_name=collection,
            query=query_vector,
            query_filter=query_filter,
            limit=max(limit * 3 if hybrid or rerank else limit, limit),
            with_payload=True,
        )
        evidence: list[RetrievedEvidence] = []
        seen: set[tuple[str, str, str]] = set()
        for point in response.points:
            payload = point.payload or {}
            text = str(payload.get("text") or "")
            source = str(payload.get("source") or "")
            source_id = str(payload.get("source_id") or "")
            document_type = str(payload.get("document_type") or "")
            key = (source, source_id, text)
            if key in seen:
                continue
            seen.add(key)
            dense_score = float(point.score or 0.0)
            lexical = _lexical_score(query, text)
            combined = (0.65 * dense_score + 0.35 * lexical) if hybrid else dense_score
            if rerank:
                combined = (0.35 * combined) + (0.65 * lexical)
            evidence.append(
                RetrievedEvidence(
                    source=source,
                    source_id=source_id,
                    document_type=document_type,
                    text=text,
                    citation=str(payload.get("citation") or f"{source}:{source_id}"),
                    score=round(combined, 6),
                    metadata={
                        key: value
                        for key, value in payload.items()
                        if key not in {"text", "organization_id"}
                    },
                )
            )
        evidence.sort(key=lambda item: item.score, reverse=True)
        return evidence[:limit]
