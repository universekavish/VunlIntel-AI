"""Unit tests for RAG document preparation and LangChain integration."""

import pytest
from langchain_core.documents import Document

from app.rag.documents import (
    PreparedChunk,
    advisory_document,
    cve_document,
    cwe_document,
    kev_document,
    langchain_document,
    osv_document,
)
from app.rag.embeddings import DeterministicHashEmbedding
from app.rag.indexing import deduplicate_chunks
from app.rag.vectorstore import organization_collection


@pytest.mark.parametrize(
    ("citation_prefix", "chunks"),
    [
        (
            "nvd",
            cve_document(
                "CVE-2026-0001",
                "Test description",
                {"cvss": {}, "cwe_ids": ["CWE-79"], "references": []},
            ),
        ),
        (
            "cisa_kev",
            kev_document(
                {"cve_id": "CVE-2026-0001", "name": "Test KEV", "known_ransomware": "Unknown"}
            ),
        ),
        (
            "mitre_cwe",
            cwe_document(
                {"cwe_id": "CWE-79", "name": "XSS", "description": "Improper input neutralization"}
            ),
        ),
        (
            "osv",
            osv_document(
                {"osv_id": "OSV-2026-0001", "aliases": ["CVE-2026-0001"], "summary": "Test OSV"}
            ),
        ),
        (
            "vendor_advisory",
            advisory_document(
                source_id="ADV-2026-1",
                payload={"title": "Vendor advisory", "details": "Test remediation"},
            ),
        ),
    ],
)
def test_all_supported_document_types_have_citation_metadata(
    citation_prefix: str,
    chunks: list[PreparedChunk],
) -> None:
    assert chunks
    assert all(item.metadata["citation"].startswith(citation_prefix) for item in chunks)


def test_langchain_document_contract_is_used() -> None:
    chunks = cve_document("CVE-2026-0002", "LangChain document", {})

    document = langchain_document(chunks[0])

    assert isinstance(document, Document)
    assert document.page_content
    assert document.metadata["source"] == "nvd"
    assert document.metadata["cve_id"] == "CVE-2026-0002"


def test_document_deduplication_removes_identical_chunks() -> None:
    chunks = cve_document("CVE-2026-0003", "Repeated", {})

    deduplicated = deduplicate_chunks([*chunks, *chunks])

    assert len(deduplicated) == len(chunks)


def test_hash_embeddings_are_normalized_and_deterministic() -> None:
    embeddings = DeterministicHashEmbedding(384)

    first = embeddings.embed_query("CVE remote code execution")
    second = embeddings.embed_query("CVE remote code execution")

    assert len(first) == 384
    assert first == second
    assert abs(sum(value * value for value in first) - 1.0) < 1e-6


def test_organization_collection_names_isolate_tenants() -> None:
    from uuid import UUID

    one = organization_collection("vulnintel", UUID("11111111-1111-1111-1111-111111111111"))
    two = organization_collection("vulnintel", UUID("22222222-2222-2222-2222-222222222222"))

    assert one != two
    assert one.endswith("org_11111111111111111111111111111111")
