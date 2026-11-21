"""Incremental RAG document indexing and evidence validation."""

import hashlib
from datetime import UTC, datetime
from uuid import NAMESPACE_URL, UUID, uuid4, uuid5

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models import (
    CveRecord,
    CweRecord,
    KevRecord,
    OsvRecord,
    RagDocument,
    RagIndexRun,
    SourceRecord,
)
from app.rag.documents import (
    PreparedChunk,
    advisory_document,
    cve_document,
    cwe_document,
    kev_document,
    osv_document,
)
from app.rag.vectorstore import RetrievedEvidence


def collect_documents(session: Session) -> list[PreparedChunk]:
    """Prepare only normalized and vendor-advisory source records."""
    prepared: list[PreparedChunk] = []
    for row in session.scalars(select(CveRecord)):
        prepared.extend(
            cve_document(
                row.cve_id,
                row.description,
                {
                    "cvss": row.cvss,
                    "cwe_ids": row.cwe_ids,
                    "references": row.references,
                },
            )
        )
    for row in session.scalars(select(KevRecord)):
        prepared.extend(
            kev_document(
                {
                    "cve_id": row.cve_id,
                    "vendor_project": row.vendor_project,
                    "product": row.product,
                    "name": row.name,
                    "known_ransomware": row.known_ransomware,
                    "notes": row.notes,
                }
            )
        )
    for row in session.scalars(select(CweRecord)):
        prepared.extend(
            cwe_document(
                {
                    "cwe_id": row.cwe_id,
                    "name": row.name,
                    "weakness_abstract": row.weakness_abstract,
                    "description": row.description,
                }
            )
        )
    for row in session.scalars(select(OsvRecord)):
        prepared.extend(
            osv_document(
                {
                    "osv_id": row.osv_id,
                    "aliases": row.aliases,
                    "summary": row.summary,
                    "details": row.details,
                    "references": row.references,
                }
            )
        )
    for row in session.scalars(
        select(SourceRecord).where(SourceRecord.record_type.like("%advisory%"))
    ):
        prepared.extend(
            advisory_document(
                source_id=row.source_id,
                payload=row.payload,
            )
        )
    return deduplicate_chunks(prepared)


def deduplicate_chunks(chunks: list[PreparedChunk]) -> list[PreparedChunk]:
    unique: dict[tuple[str, str, str], PreparedChunk] = {}
    for chunk in chunks:
        digest = hashlib.sha256(chunk.text.encode("utf-8")).hexdigest()
        key = (chunk.source, chunk.source_id, digest)
        unique.setdefault(key, chunk)
    return list(unique.values())


def validate_citation(session: Session, evidence: RetrievedEvidence) -> bool:
    """Require every citation to map to a persisted source or normalized record."""
    if evidence.citation != f"{evidence.source}:{evidence.source_id}":
        return False
    if evidence.source == "nvd":
        return session.get(CveRecord, evidence.source_id) is not None
    if evidence.source == "cisa_kev":
        return session.get(KevRecord, evidence.source_id) is not None
    if evidence.source == "mitre_cwe":
        return session.get(CweRecord, evidence.source_id) is not None
    if evidence.source == "osv":
        return session.get(OsvRecord, evidence.source_id) is not None
    if evidence.source == "vendor_advisory":
        row = session.scalar(
            select(SourceRecord).where(
                SourceRecord.source == "vendor_advisory",
                SourceRecord.source_id == evidence.source_id,
            )
        )
        return row is not None
    return False


def run_incremental_index(
    session: Session,
    *,
    organization_id: UUID,
    collection_name: str,
    vectorstore,
) -> RagIndexRun:
    """Index changed documents once, retaining source and chunk traceability."""
    run = RagIndexRun(
        id=uuid4(),
        organization_id=organization_id,
        status="running",
        documents_found=0,
        chunks_embedded=0,
        chunks_skipped=0,
        errors=0,
        collection_name=collection_name,
    )
    session.add(run)
    session.commit()
    chunks = collect_documents(session)
    run.documents_found = len(chunks)
    points: list[dict] = []
    try:
        for chunk in chunks:
            digest = hashlib.sha256(chunk.text.encode("utf-8")).hexdigest()
            existing = session.scalar(
                select(RagDocument).where(
                    RagDocument.organization_id == organization_id,
                    RagDocument.source == chunk.source,
                    RagDocument.source_id == chunk.source_id,
                    RagDocument.chunk_index == chunk.chunk_index,
                )
            )
            if existing is not None and existing.content_sha256 == digest:
                run.chunks_skipped += 1
                continue
            point_id = str(
                uuid5(
                    NAMESPACE_URL,
                    f"{organization_id}:{chunk.source}:{chunk.source_id}:{chunk.chunk_index}",
                )
            )
            points.append(
                {
                    "point_id": point_id,
                    "source": chunk.source,
                    "source_id": chunk.source_id,
                    "document_type": chunk.document_type,
                    "text": chunk.text,
                    "metadata": chunk.metadata,
                }
            )
            if existing is None:
                session.add(
                    RagDocument(
                        id=uuid4(),
                        organization_id=organization_id,
                        source=chunk.source,
                        source_id=chunk.source_id,
                        document_type=chunk.document_type,
                        chunk_index=chunk.chunk_index,
                        content_sha256=digest,
                        text=chunk.text,
                        metadata_json=chunk.metadata,
                        qdrant_point_id=point_id,
                    )
                )
            else:
                existing.content_sha256 = digest
                existing.text = chunk.text
                existing.metadata_json = chunk.metadata
                existing.qdrant_point_id = point_id
                existing.embedded_at = datetime.now(UTC)
        run.chunks_embedded = vectorstore.upsert_documents(
            organization_id=organization_id,
            documents=points,
        )
        session.commit()
        run.status = "completed"
        run.completed_at = datetime.now(UTC)
        session.commit()
    except Exception as exc:
        session.rollback()
        run.status = "failed"
        run.completed_at = datetime.now(UTC)
        run.errors = max(1, run.errors)
        run.error_summary = str(exc)[:2000]
        session.add(run)
        session.commit()
        raise
    return run
