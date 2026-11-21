"""LangGraph unit tests for routing, bounded retries, interrupt, and failure."""

from uuid import uuid4

from langgraph.checkpoint.memory import MemorySaver
from langgraph.types import Command

from app.db.models import CveRecord, Investigation, Organization, User
from app.rag.vectorstore import RetrievedEvidence
from app.workflows.graph import build_investigation_graph
from app.workflows.nodes import input_validation


class RecoveringStore:
    def __init__(self) -> None:
        self.attempts = 0

    def search(self, **kwargs):
        self.attempts += 1
        if self.attempts <= 2:
            raise TimeoutError("Qdrant temporary timeout")
        return [
            RetrievedEvidence(
                source="nvd",
                source_id="CVE-2026-0001",
                document_type="cve",
                text="A persisted CVE description.",
                citation="nvd:CVE-2026-0001",
                score=0.9,
                metadata={"cve_id": "CVE-2026-0001"},
            )
        ]


class PermanentFailureStore:
    def search(self, **kwargs):
        raise TimeoutError("Qdrant unavailable")


def test_input_validation_rejects_missing_input() -> None:
    state = input_validation({"query": "", "cve_id": None})

    assert state["status"] == "failed"
    assert "required" in state["error"]


def test_input_validation_normalizes_only_schema_shape() -> None:
    state = input_validation({"query": "Investigate CVE-2026-0001", "cve_id": "CVE-2026-0001"})

    assert state["status"] == "running"
    assert state["error"] is None


def test_graph_recovers_after_bounded_retrieval_retries(
    api_client,
) -> None:
    _, session_factory = api_client
    with session_factory() as session:
        organization = Organization(id=uuid4(), name="Graph Org", slug="graph-org")
        session.add(organization)
        session.flush()
        actor = User(
            id=uuid4(),
            organization_id=organization.id,
            email="graph-owner@example.test",
            display_name="Graph Owner",
            password_hash="unused",
            role="owner",
            is_active=True,
        )
        session.add(actor)
        session.flush()
        cve = CveRecord(
            cve_id="CVE-2026-0001",
            description="Persisted evidence",
            cvss={"baseScore": 9.8},
            cwe_ids=["CWE-79"],
            references=["https://example.test/CVE-2026-0001"],
            affected=[],
            source_ids=["nvd"],
        )
        session.add(cve)
        investigation = Investigation(
            id=uuid4(),
            organization_id=organization.id,
            initiated_by=actor.id,
            cve_id="CVE-2026-0001",
            status="running",
            state={},
            langgraph_thread_id="graph-recovery-test",
        )
        session.add(investigation)
        session.commit()

        store = RecoveringStore()
        graph = build_investigation_graph(
            session=session,
            store=store,
            organization_id=organization.id,
            checkpointer=MemorySaver(),
        )
        initial = {
            "investigation_id": str(investigation.id),
            "organization_id": str(organization.id),
            "initiated_by": str(actor.id),
            "asset_id": None,
            "cve_id": "CVE-2026-0001",
            "query": "Investigate CVE-2026-0001",
            "audit_events": [],
            "retrieval_attempts": {},
            "retrieval_errors": [],
            "status": "running",
        }
        result = graph.invoke(
            initial,
            config={"configurable": {"thread_id": "graph-recovery-test"}},
        )

        assert store.attempts == 3
        assert result["validated_evidence"]
        assert result["retrieval_errors"] == []


def test_graph_interrupts_for_explicit_human_approval(
    api_client,
) -> None:
    _, session_factory = api_client
    with session_factory() as session:
        organization = Organization(id=uuid4(), name="Approval Org", slug="approval-org")
        session.add(organization)
        session.flush()
        actor = User(
            id=uuid4(),
            organization_id=organization.id,
            email="approval-owner@example.test",
            display_name="Approval Owner",
            password_hash="unused",
            role="owner",
            is_active=True,
        )
        session.add(actor)
        session.flush()
        cve = CveRecord(
            cve_id="CVE-2026-0002",
            description="Approved evidence",
            cvss={},
            cwe_ids=[],
            references=[],
            affected=[],
            source_ids=["nvd"],
        )
        session.add(cve)
        investigation = Investigation(
            id=uuid4(),
            organization_id=organization.id,
            initiated_by=actor.id,
            cve_id="CVE-2026-0002",
            status="running",
            state={},
            langgraph_thread_id="graph-approval-test",
        )
        session.add(investigation)
        session.commit()

        store = RecoveringStore()
        graph = build_investigation_graph(
            session=session,
            store=store,
            organization_id=organization.id,
            checkpointer=MemorySaver(),
        )
        initial = {
            "investigation_id": str(investigation.id),
            "organization_id": str(organization.id),
            "initiated_by": str(actor.id),
            "asset_id": None,
            "cve_id": "CVE-2026-0002",
            "query": "Investigate CVE-2026-0002",
            "audit_events": [],
            "retrieval_attempts": {},
            "retrieval_errors": [],
            "status": "running",
        }
        config = {"configurable": {"thread_id": "graph-approval-test"}}
        interrupted = graph.invoke(initial, config=config)

        assert interrupted.get("__interrupt__")

        resumed = graph.invoke(
            Command(resume={"approved": True, "reviewer": "security-owner"}),
            config=config,
        )
        assert resumed["status"] == "approved"
        assert resumed["approval"]["approved"] is True
        assert resumed["report"]["approval"]["approved"] is True


def test_graph_stops_after_bounded_permanent_retrieval_failure(
    api_client,
) -> None:
    _, session_factory = api_client
    with session_factory() as session:
        organization = Organization(id=uuid4(), name="Failure Org", slug="failure-org")
        session.add(organization)
        session.flush()
        actor = User(
            id=uuid4(),
            organization_id=organization.id,
            email="failure-owner@example.test",
            display_name="Failure Owner",
            password_hash="unused",
            role="owner",
            is_active=True,
        )
        session.add(actor)
        session.flush()
        investigation = Investigation(
            id=uuid4(),
            organization_id=organization.id,
            initiated_by=actor.id,
            status="running",
            state={},
            langgraph_thread_id="graph-failure-test",
        )
        session.add(investigation)
        session.commit()
        graph = build_investigation_graph(
            session=session,
            store=PermanentFailureStore(),
            organization_id=organization.id,
            checkpointer=MemorySaver(),
        )
        result = graph.invoke(
            {
                "investigation_id": str(investigation.id),
                "organization_id": str(organization.id),
                "initiated_by": str(actor.id),
                "asset_id": None,
                "cve_id": "CVE-2026-0003",
                "query": "Investigate CVE-2026-0003",
                "audit_events": [],
                "retrieval_attempts": {},
                "retrieval_errors": [],
                "status": "running",
            },
            config={"configurable": {"thread_id": "graph-failure-test"}},
        )

        assert result["status"] == "completed"
        assert result["retrieval_attempts"]["qdrant"] == 3
