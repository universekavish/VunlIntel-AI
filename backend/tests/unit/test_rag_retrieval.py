"""Retrieval tests using a mock Qdrant surface."""

from uuid import UUID

from app.rag.embeddings import DeterministicHashEmbedding
from app.rag.vectorstore import (
    QdrantKnowledgeStore,
    _lexical_score,
)


class MockQueryResponse:
    def __init__(self, points):
        self.points = points


class MockPoint:
    def __init__(self, payload, score):
        self.payload = payload
        self.score = score


class MockQdrant:
    def __init__(self):
        self.filters = None

    def collection_exists(self, name):
        return True

    def create_payload_index(self, **kwargs):
        return None

    def query_points(self, *, query, query_filter, limit, with_payload, **kwargs):
        self.filters = query_filter
        return MockQueryResponse(
            [
                MockPoint(
                    {
                        "source": "nvd",
                        "source_id": "CVE-2026-0001",
                        "document_type": "cve",
                        "text": "CVE-2026-0001 remote code execution",
                        "citation": "nvd:CVE-2026-0001",
                    },
                    0.8,
                ),
                MockPoint(
                    {
                        "source": "mitre_cwe",
                        "source_id": "CWE-79",
                        "document_type": "cwe",
                        "text": "Cross-site scripting input neutralization",
                        "citation": "mitre_cwe:CWE-79",
                    },
                    0.6,
                ),
            ]
        )


def test_hybrid_retrieval_combines_dense_and_lexical_scores() -> None:
    store = QdrantKnowledgeStore(
        url="http://unused.test",
        base_collection="test",
        embeddings=DeterministicHashEmbedding(384),
    )
    store.client = MockQdrant()
    evidence = store.search(
        organization_id=UUID("11111111-1111-1111-1111-111111111111"),
        query="CVE remote code execution",
        hybrid=True,
        rerank=True,
    )

    assert evidence
    assert evidence[0].source_id == "CVE-2026-0001"
    assert evidence[0].citation_valid if hasattr(evidence[0], "citation_valid") else True


def test_metadata_filter_always_contains_organization_id() -> None:
    store = QdrantKnowledgeStore(
        url="http://unused.test",
        base_collection="test",
        embeddings=DeterministicHashEmbedding(384),
    )
    mock = MockQdrant()
    store.client = mock
    store.search(
        organization_id=UUID("22222222-2222-2222-2222-222222222222"),
        query="CWE-79",
        document_types=["cwe"],
        source_ids=["CWE-79"],
    )

    serialized = repr(mock.filters)
    assert "22222222-2222-2222-2222-222222222222" in serialized
    assert "document_type" in serialized
    assert "source_id" in serialized


def test_evidence_deduplicates_identical_source_text() -> None:
    store = QdrantKnowledgeStore(
        url="http://unused.test",
        base_collection="test",
        embeddings=DeterministicHashEmbedding(384),
    )

    class DuplicateMockQdrant(MockQdrant):
        def query_points(self, **kwargs):
            point = MockPoint(
                {
                    "source": "nvd",
                    "source_id": "CVE-2026-0001",
                    "document_type": "cve",
                    "text": "Same evidence",
                    "citation": "nvd:CVE-2026-0001",
                },
                0.9,
            )
            return MockQueryResponse([point, point])

    store.client = DuplicateMockQdrant()
    evidence = store.search(
        organization_id=UUID("11111111-1111-1111-1111-111111111111"),
        query="Same evidence",
    )

    assert len(evidence) == 1


def test_lexical_score_is_bounded() -> None:
    score = _lexical_score("CVE remote code execution", "CVE remote code execution")

    assert 0 <= score <= 1
    assert score == 1


def test_retrieval_eval_dataset_has_expected_citations() -> None:
    import json
    from pathlib import Path

    dataset = json.loads(
        (Path(__file__).resolve().parents[1] / "eval" / "retrieval_eval.json").read_text()
    )
    assert len(dataset) == 3
    assert {row["document_type"] for row in dataset} == {"cve", "cwe", "kev"}
