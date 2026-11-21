"""LangGraph investigation graph, routing, and checkpoint integration."""

from typing import Literal

from langgraph.graph import END, StateGraph
from sqlalchemy.orm import Session

from app.workflows.llm_nodes import (
    human_approval,
    llm_analysis,
    recommendation_validation,
)
from app.workflows.nodes import (
    deterministic_risk_assessment,
    entity_extraction,
    evidence_validation,
    input_validation,
    qdrant_retrieval,
    threat_intelligence_retrieval,
    vulnerability_retrieval,
)
from app.workflows.report import report_persistence
from app.workflows.state import InvestigationState


def build_investigation_graph(
    *,
    session: Session,
    store,
    organization_id,
    checkpointer=None,
):
    """Compile a bounded, typed investigation graph for one tenant."""
    graph = StateGraph(InvestigationState)

    graph.add_node("input_validation", input_validation)
    graph.add_node("entity_extraction", entity_extraction)
    graph.add_node(
        "vulnerability_retrieval",
        lambda state: vulnerability_retrieval(state, session=session),
    )
    graph.add_node(
        "threat_intelligence_retrieval",
        lambda state: threat_intelligence_retrieval(state, session=session),
    )
    graph.add_node(
        "qdrant_retrieval",
        lambda state: qdrant_retrieval(
            state,
            store=store,
            organization_id=organization_id,
        ),
    )
    graph.add_node(
        "evidence_validation",
        lambda state: evidence_validation(state, session=session),
    )
    graph.add_node(
        "deterministic_risk_assessment",
        lambda state: deterministic_risk_assessment(state, session=session),
    )
    graph.add_node("llm_analysis", llm_analysis)
    graph.add_node("recommendation_validation", recommendation_validation)
    graph.add_node("human_approval", human_approval)
    graph.add_node(
        "report_persistence",
        lambda state: report_persistence(state, session=session),
    )

    graph.set_entry_point("input_validation")

    def route_after_input(
        state: InvestigationState,
    ) -> Literal["entity_extraction", "report_persistence"]:
        return "entity_extraction" if state.get("status") == "running" else "report_persistence"

    graph.add_conditional_edges(
        "input_validation",
        route_after_input,
        {
            "entity_extraction": "entity_extraction",
            "report_persistence": "report_persistence",
        },
    )
    graph.add_edge("entity_extraction", "vulnerability_retrieval")
    graph.add_edge("vulnerability_retrieval", "threat_intelligence_retrieval")
    graph.add_edge("threat_intelligence_retrieval", "qdrant_retrieval")

    def route_after_retrieval(
        state: InvestigationState,
    ) -> Literal["evidence_validation", "qdrant_retrieval", "report_persistence"]:
        evidence = state.get("evidence") or []
        if evidence:
            return "evidence_validation"
        attempts = (state.get("retrieval_attempts") or {}).get("qdrant", 0)
        if attempts < 3:
            return "qdrant_retrieval"
        return "report_persistence"

    graph.add_conditional_edges(
        "qdrant_retrieval",
        route_after_retrieval,
        {
            "evidence_validation": "evidence_validation",
            "qdrant_retrieval": "qdrant_retrieval",
            "report_persistence": "report_persistence",
        },
    )
    graph.add_edge("evidence_validation", "deterministic_risk_assessment")
    graph.add_edge("deterministic_risk_assessment", "llm_analysis")
    graph.add_edge("llm_analysis", "recommendation_validation")
    graph.add_edge("recommendation_validation", "human_approval")

    def route_after_approval(
        state: InvestigationState,
    ) -> Literal["report_persistence", "report_persistence"]:
        if state.get("approval_status") in {"approved", "rejected"}:
            return "report_persistence"
        return "report_persistence"

    graph.add_conditional_edges(
        "human_approval",
        route_after_approval,
        {"report_persistence": "report_persistence"},
    )
    graph.add_edge("report_persistence", END)

    return graph.compile(checkpointer=checkpointer)
