"""Persist and calculate deterministic contextual vulnerability risk."""

from datetime import UTC, datetime
from uuid import UUID, uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models import (
    Asset,
    CveRecord,
    EpssRecord,
    KevRecord,
    RiskHistory,
)
from app.schemas.risk import RiskCalculateRequest
from app.services.risk import (
    DEFAULT_THRESHOLDS,
    DEFAULT_WEIGHTS,
    RiskInputs,
    RiskResult,
    RiskThresholds,
    RiskWeights,
    calculate_risk,
)


def _cvss_score(cve: CveRecord) -> float | None:
    cvss = cve.cvss
    if not isinstance(cvss, dict):
        return None
    nested = cvss.get("cvssData")
    if isinstance(nested, dict):
        value = nested.get("baseScore")
        if isinstance(value, (int, float)):
            return float(value)
    value = cvss.get("baseScore")
    if isinstance(value, (int, float)):
        return float(value)
    return None


def calculate_and_store_risk(
    session: Session,
    *,
    asset: Asset,
    request: RiskCalculateRequest,
) -> RiskResult:
    """Resolve factual source signals, calculate pure risk, and persist immutable history."""
    cvss = request.cvss
    epss = request.epss
    kev = request.kev
    vulnerability_id = request.vulnerability_id

    cve = session.get(CveRecord, vulnerability_id) if vulnerability_id else None
    if cve is not None:
        if cvss is None:
            cvss = _cvss_score(cve)
        epss_row = session.get(EpssRecord, vulnerability_id)
        if epss is None and epss_row is not None:
            epss = epss_row.epss
        kev_row = session.get(KevRecord, vulnerability_id)
        if kev is None:
            kev = kev_row is not None

    weights = DEFAULT_WEIGHTS
    if request.weights is not None:
        weights = RiskWeights(
            cvss=request.weights.cvss,
            epss=request.weights.epss,
            kev=request.weights.kev,
            asset_criticality=request.weights.asset_criticality,
            internet_exposure=request.weights.internet_exposure,
            ransomware=request.weights.ransomware,
        )
    thresholds = DEFAULT_THRESHOLDS
    if request.thresholds is not None:
        thresholds = RiskThresholds(
            low=request.thresholds.low,
            medium=request.thresholds.medium,
            high=request.thresholds.high,
        )

    result = calculate_risk(
        RiskInputs(
            cvss=cvss,
            epss=epss,
            kev=kev,
            asset_criticality=asset.criticality,
            internet_exposure=(
                request.internet_exposure
                if request.internet_exposure is not None
                else asset.internet_exposed
            ),
            ransomware=(
                request.ransomware if request.ransomware is not None else asset.ransomware_indicator
            ),
        ),
        weights=weights,
        thresholds=thresholds,
    )
    history = RiskHistory(
        id=uuid4(),
        organization_id=asset.organization_id,
        asset_id=asset.id,
        vulnerability_id=vulnerability_id,
        score=result.score,
        risk_band=result.risk_band,
        factors=[
            {
                "name": factor.name,
                "weight": factor.weight,
                "effective_weight": factor.effective_weight,
                "raw_value": factor.raw_value,
                "normalized_value": factor.normalized_value,
                "contribution": factor.contribution,
                "status": factor.status,
                "explanation": factor.explanation,
            }
            for factor in result.factors
        ],
        missing_signals=list(result.missing_signals),
        explanation=result.explanation,
        thresholds={
            "low": result.thresholds.low,
            "medium": result.thresholds.medium,
            "high": result.thresholds.high,
        },
        confidence=result.confidence,
        calculated_at=datetime.now(UTC),
    )
    session.add(history)
    session.commit()
    return result


def list_risk_history(
    session: Session,
    *,
    organization_id: UUID,
    asset_id: UUID,
) -> list[RiskHistory]:
    return list(
        session.scalars(
            select(RiskHistory)
            .where(
                RiskHistory.organization_id == organization_id,
                RiskHistory.asset_id == asset_id,
            )
            .order_by(RiskHistory.calculated_at.desc())
        )
    )
