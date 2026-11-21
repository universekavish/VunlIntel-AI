"""Modular investigation workflow nodes."""

from typing import Any
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models import (
    Asset,
    CveRecord,
    EpssRecord,
    KevRecord,
    OsvRecord,
)
from app.rag.indexing import validate_citation
from app.rag.vectorstore import RetrievedEvidence
from app.services.risk import RiskInputs, calculate_risk
from app.workflows.state import (
    EvidenceRecord,
    InvestigationState,
)


def input_validation(state: InvestigationState) -> InvestigationState:
    query = str(state.get("query") or "").strip()
    cve_id = state.get("cve_id")
    if len(query) > 2000:
        return {"status": "failed", "error": "Investigation query exceeds 2000 characters"}
    if not query and not cve_id:
        return {"status": "failed", "error": "A query or CVE identifier is required"}
    if cve_id:
        normalized = cve_id.strip().upper()
        if not normalized.startswith("CVE-"):
            return {"status": "failed", "error": "CVE identifiers must start with CVE-"}
    return {
        "status": "running",
        "error": None,
        "audit_events": [{"event": "input_validated", "details": {"query": query}}],
    }


def entity_extraction(state: InvestigationState) -> InvestigationState:
    import re

    text = f"{state.get('query') or ''} {state.get('cve_id') or ''}"
    entities = sorted(set(re.findall(r"(?i)\bCVE-\d{4}-\d{4,7}\b", text)))
    return {
        "entities": entities,
        "audit_events": [{"event": "entities_extracted", "details": {"entities": entities}}],
    }


def vulnerability_retrieval(
    state: InvestigationState,
    *,
    session: Session,
) -> InvestigationState:
    records: list[dict[str, Any]] = []
    identifiers = set(state.get("entities") or [])
    if state.get("cve_id"):
        identifiers.add(str(state["cve_id"]).upper())
    for identifier in sorted(identifiers):
        cve = session.get(CveRecord, identifier)
        if cve is not None:
            records.append(
                {
                    "source": "nvd",
                    "source_id": cve.cve_id,
                    "description": cve.description,
                    "cvss": cve.cvss,
                    "cwe_ids": cve.cwe_ids,
                    "references": cve.references,
                }
            )
        osv = [
            row for row in session.scalars(select(OsvRecord)) if identifier in (row.aliases or [])
        ]
        for row in osv:
            records.append(
                {
                    "source": "osv",
                    "source_id": row.osv_id,
                    "summary": row.summary,
                    "details": row.details,
                    "aliases": row.aliases,
                }
            )
    return {
        "vulnerability_records": records,
        "audit_events": [
            {
                "event": "vulnerability_retrieved",
                "details": {"count": len(records)},
            }
        ],
    }


def threat_intelligence_retrieval(
    state: InvestigationState,
    *,
    session: Session,
) -> InvestigationState:
    records: list[dict[str, Any]] = []
    identifiers = set(state.get("entities") or [])
    if state.get("cve_id"):
        identifiers.add(str(state["cve_id"]).upper())
    for identifier in sorted(identifiers):
        kev = session.get(KevRecord, identifier)
        epss = session.get(EpssRecord, identifier)
        if kev is not None:
            records.append(
                {
                    "source": "cisa_kev",
                    "source_id": kev.cve_id,
                    "known_ransomware": kev.known_ransomware,
                    "notes": kev.notes,
                }
            )
        if epss is not None:
            records.append(
                {
                    "source": "epss",
                    "source_id": epss.cve_id,
                    "epss": epss.epss,
                    "percentile": epss.percentile,
                }
            )
    return {
        "threat_records": records,
        "audit_events": [
            {
                "event": "threat_intelligence_retrieved",
                "details": {"count": len(records)},
            }
        ],
    }


def qdrant_retrieval(
    state: InvestigationState,
    *,
    store,
    organization_id: UUID,
) -> InvestigationState:
    attempts = dict(state.get("retrieval_attempts") or {})
    attempts["qdrant"] = attempts.get("qdrant", 0) + 1
    query = state.get("query") or " ".join(state.get("entities") or [])
    evidence: list[EvidenceRecord] = []
    try:
        for item in store.search(
            organization_id=organization_id,
            query=query,
            limit=8,
            hybrid=True,
            rerank=True,
        ):
            evidence.append(
                {
                    "source": item.source,
                    "source_id": item.source_id,
                    "document_type": item.document_type,
                    "citation": item.citation,
                    "text": item.text,
                    "score": item.score,
                    "validated": False,
                    "reason": "not validated",
                }
            )
        return {
            "evidence": evidence,
            "retrieval_attempts": attempts,
            "retrieval_errors": [],
            "audit_events": [
                {
                    "event": "qdrant_retrieval",
                    "details": {"count": len(evidence), "attempt": attempts["qdrant"]},
                }
            ],
        }
    except Exception as exc:
        return {
            "retrieval_attempts": attempts,
            "retrieval_errors": [str(exc)],
            "evidence": [],
        }


def evidence_validation(
    state: InvestigationState,
    *,
    session: Session,
) -> InvestigationState:
    validated: list[EvidenceRecord] = []
    for item in state.get("evidence") or []:
        evidence = RetrievedEvidence(
            source=item["source"],
            source_id=item["source_id"],
            document_type=item["document_type"],
            text=item["text"],
            citation=item["citation"],
            score=item["score"],
            metadata={},
        )
        valid = validate_citation(session, evidence)
        copy = dict(item)
        copy["validated"] = valid
        copy["reason"] = "citation resolves to persisted source" if valid else "unresolved citation"
        if valid:
            validated.append(copy)
    return {
        "validated_evidence": validated,
        "audit_events": [
            {
                "event": "evidence_validated",
                "details": {"count": len(validated)},
            }
        ],
    }


def deterministic_risk_assessment(
    state: InvestigationState,
    *,
    session: Session,
) -> InvestigationState:
    asset = None
    if state.get("asset_id") and state.get("organization_id"):
        asset = session.scalar(
            select(Asset).where(
                Asset.id == UUID(state["asset_id"]),
                Asset.organization_id == UUID(state["organization_id"]),
            )
        )
    cve_id = state.get("cve_id")
    cvss = None
    epss = None
    kev = None
    if cve_id:
        cve = session.get(CveRecord, cve_id)
        if cve:
            cvss_data = cve.cvss
            if isinstance(cvss_data, dict):
                nested = cvss_data.get("cvssData")
                if isinstance(nested, dict):
                    cvss = nested.get("baseScore")
        epss_row = session.get(EpssRecord, cve_id)
        if epss_row:
            epss = epss_row.epss
        kev = session.get(KevRecord, cve_id) is not None
    result = calculate_risk(
        RiskInputs(
            cvss=float(cvss) if isinstance(cvss, (int, float)) else None,
            epss=float(epss) if isinstance(epss, (int, float)) else None,
            kev=kev,
            asset_criticality=asset.criticality if asset else None,
            internet_exposure=asset.internet_exposed if asset else None,
            ransomware=asset.ransomware_indicator if asset else None,
        )
    )
    risk = {
        "score": result.score,
        "risk_band": result.risk_band,
        "confidence": result.confidence,
        "missing_signals": list(result.missing_signals),
        "factors": [
            {
                "name": item.name,
                "weight": item.weight,
                "effective_weight": item.effective_weight,
                "normalized_value": item.normalized_value,
                "contribution": item.contribution,
                "status": item.status,
                "explanation": item.explanation,
            }
            for item in result.factors
        ],
        "explanation": result.explanation,
    }
    return {
        "risk": risk,
        "audit_events": [
            {
                "event": "deterministic_risk_assessed",
                "details": {"score": result.score, "band": result.risk_band},
            }
        ],
    }
