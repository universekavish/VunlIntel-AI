"""Tenant-scoped asset inventory and SBOM/CSV import routes."""

import json
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, UploadFile, status
from sqlalchemy import select

from app.api.dependencies import DatabaseSession, require_roles
from app.db.models import User, VulnerabilityMatch
from app.ingestion.csv_assets import parse_asset_csv
from app.ingestion.sbom import parse_cyclonedx, parse_spdx
from app.repositories.assets import get_asset, list_assets
from app.schemas.assets import (
    AssetCreate,
    AssetRead,
    AssetUpdate,
    ImportResult,
)
from app.schemas.risk import (
    RiskCalculateRequest,
    RiskFactorRead,
    RiskResultRead,
)
from app.schemas.roles import UserRole
from app.services.assets import (
    create_asset,
    deactivate_asset,
    update_asset,
)
from app.services.risk_history import calculate_and_store_risk, list_risk_history

router = APIRouter(prefix="/assets", tags=["assets"])
AnalystOrHigher = Annotated[
    User,
    Depends(require_roles(UserRole.OWNER, UserRole.ADMIN, UserRole.ANALYST)),
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


@router.get("", response_model=list[AssetRead])
def assets(
    user: ViewerOrHigher,
    session: DatabaseSession,
) -> list[AssetRead]:
    return [AssetRead.model_validate(asset) for asset in list_assets(session, user.organization_id)]


@router.post("", response_model=AssetRead, status_code=status.HTTP_201_CREATED)
def create(
    payload: AssetCreate,
    user: AnalystOrHigher,
    session: DatabaseSession,
) -> AssetRead:
    asset = create_asset(
        session,
        organization_id=user.organization_id,
        payload=payload,
    )
    return AssetRead.model_validate(asset)


@router.get("/{asset_id}", response_model=AssetRead)
def get_asset_route(
    asset_id: UUID,
    user: ViewerOrHigher,
    session: DatabaseSession,
) -> AssetRead:
    asset = get_asset(session, user.organization_id, asset_id)
    if asset is None:
        raise HTTPException(status_code=404, detail="Asset not found")
    return AssetRead.model_validate(asset)


@router.patch("/{asset_id}", response_model=AssetRead)
def patch_asset(
    asset_id: UUID,
    payload: AssetUpdate,
    user: AnalystOrHigher,
    session: DatabaseSession,
) -> AssetRead:
    asset = update_asset(
        session,
        organization_id=user.organization_id,
        asset_id=asset_id,
        payload=payload,
    )
    return AssetRead.model_validate(asset)


@router.delete("/{asset_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_asset(
    asset_id: UUID,
    user: AnalystOrHigher,
    session: DatabaseSession,
) -> None:
    deactivate_asset(
        session,
        organization_id=user.organization_id,
        asset_id=asset_id,
    )


@router.post("/{asset_id}/matches")
def run_matches(
    asset_id: UUID,
    user: AnalystOrHigher,
    session: DatabaseSession,
) -> list[dict[str, object]]:
    asset = get_asset(session, user.organization_id, asset_id)
    if asset is None:
        raise HTTPException(status_code=404, detail="Asset not found")
    from app.services.vulnerability_matching import match_asset

    matches = match_asset(session, asset=asset)
    return [
        {
            "vulnerability_id": match.vulnerability_id,
            "source": match.source,
            "outcome": match.outcome,
            "confidence": match.confidence,
            "evidence": match.evidence,
        }
        for match in matches
    ]


@router.get("/{asset_id}/matches")
def list_matches(
    asset_id: UUID,
    user: ViewerOrHigher,
    session: DatabaseSession,
) -> list[dict[str, object]]:
    asset = get_asset(session, user.organization_id, asset_id)
    if asset is None:
        raise HTTPException(status_code=404, detail="Asset not found")
    rows = list(
        session.scalars(
            select(VulnerabilityMatch)
            .where(VulnerabilityMatch.asset_id == asset.id)
            .order_by(VulnerabilityMatch.vulnerability_id)
        )
    )
    return [
        {
            "vulnerability_id": row.vulnerability_id,
            "source": row.source,
            "outcome": row.outcome,
            "confidence": row.confidence,
            "evidence": row.evidence,
        }
        for row in rows
    ]


def _risk_result_response(
    *,
    asset_id: UUID,
    result,
    vulnerability_id: str | None = None,
    history_id: UUID | None = None,
    calculated_at=None,
) -> RiskResultRead:
    return RiskResultRead(
        id=history_id,
        asset_id=asset_id,
        vulnerability_id=vulnerability_id,
        score=result.score,
        risk_band=result.risk_band,
        confidence=result.confidence,
        missing_signals=list(result.missing_signals),
        factors=[
            RiskFactorRead(
                name=factor.name,
                weight=factor.weight,
                effective_weight=factor.effective_weight,
                raw_value=factor.raw_value,
                normalized_value=factor.normalized_value,
                contribution=factor.contribution,
                status=factor.status,
                explanation=factor.explanation,
            )
            for factor in result.factors
        ],
        explanation=result.explanation,
        thresholds={
            "low": result.thresholds.low,
            "medium": result.thresholds.medium,
            "high": result.thresholds.high,
        },
        calculated_at=calculated_at,
    )


@router.post("/{asset_id}/risk", response_model=RiskResultRead)
def calculate_risk(
    asset_id: UUID,
    payload: RiskCalculateRequest,
    user: AnalystOrHigher,
    session: DatabaseSession,
) -> RiskResultRead:
    """Calculate and persist deterministic contextual risk; LLM inputs are not accepted."""
    asset = get_asset(session, user.organization_id, asset_id)
    if asset is None:
        raise HTTPException(status_code=404, detail="Asset not found")
    result = calculate_and_store_risk(
        session,
        asset=asset,
        request=payload,
    )
    return _risk_result_response(
        asset_id=asset.id,
        result=result,
        vulnerability_id=payload.vulnerability_id,
        calculated_at=None,
    )


@router.get("/{asset_id}/risk/history", response_model=list[RiskResultRead])
def risk_history(
    asset_id: UUID,
    user: ViewerOrHigher,
    session: DatabaseSession,
) -> list[RiskResultRead]:
    asset = get_asset(session, user.organization_id, asset_id)
    if asset is None:
        raise HTTPException(status_code=404, detail="Asset not found")
    rows = list_risk_history(
        session,
        organization_id=user.organization_id,
        asset_id=asset.id,
    )
    responses: list[RiskResultRead] = []
    for row in rows:
        responses.append(
            RiskResultRead(
                id=row.id,
                asset_id=row.asset_id,
                vulnerability_id=row.vulnerability_id,
                score=row.score,
                risk_band=row.risk_band,
                confidence=row.confidence,
                missing_signals=row.missing_signals,
                factors=[RiskFactorRead.model_validate(factor) for factor in row.factors],
                explanation=row.explanation,
                thresholds=row.thresholds,
                calculated_at=row.calculated_at,
            )
        )
    return responses


@router.post("/imports/csv", response_model=ImportResult)
async def import_csv(
    file: UploadFile,
    user: AnalystOrHigher,
    session: DatabaseSession,
) -> ImportResult:
    if file.content_type not in {None, "text/csv", "application/csv", "application/vnd.ms-excel"}:
        raise HTTPException(status_code=415, detail="CSV upload must use a text/csv media type")
    content = await file.read(5 * 1024 * 1024 + 1)
    if len(content) > 5 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="CSV exceeds the 5 MiB limit")
    try:
        assets, invalid = parse_asset_csv(content)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    created = 0
    updated = 0
    software_created = 0
    software_skipped = 0
    for payload in assets:
        existing = None
        if payload.external_id:
            from app.repositories.assets import find_asset_external

            existing = find_asset_external(session, user.organization_id, payload.external_id)
        if existing:
            existing.name = payload.name
            existing.asset_type = payload.asset_type
            existing.hostname = payload.hostname
            existing.environment = payload.environment
            existing.criticality = payload.criticality.value
            existing.internet_exposed = payload.internet_exposed
            existing.ransomware_indicator = payload.ransomware_indicator
            existing.active = True
            asset = existing
            updated += 1
        else:
            asset = create_asset(
                session,
                organization_id=user.organization_id,
                payload=payload,
                source="csv",
            )
            created += 1
            software_created += len(payload.software)
        if existing:
            from app.services.assets import upsert_asset_software

            for software in payload.software:
                _, added = upsert_asset_software(
                    session,
                    asset=asset,
                    software=software,
                    source="csv",
                )
                software_created += int(added)
                software_skipped += int(not added)
            session.commit()
    return ImportResult(
        import_format="csv",
        assets_created=created,
        assets_updated=updated,
        software_created=software_created,
        software_skipped=software_skipped,
        invalid_rows=invalid,
    )


@router.post("/imports/sbom", response_model=ImportResult)
async def import_sbom(
    file: UploadFile,
    format: str,
    user: AnalystOrHigher,
    session: DatabaseSession,
) -> ImportResult:
    if file.content_type not in {None, "application/json", "application/sbom+json"}:
        raise HTTPException(status_code=415, detail="SBOM upload must use application/json")
    content = await file.read(10 * 1024 * 1024 + 1)
    if len(content) > 10 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="SBOM exceeds the 10 MiB limit")
    try:
        payload = json.loads(content)
        if format.casefold() == "cyclonedx":
            components = parse_cyclonedx(payload)
            import_format = "cyclonedx"
        elif format.casefold() == "spdx":
            components = parse_spdx(payload)
            import_format = "spdx"
        else:
            raise HTTPException(status_code=422, detail="format must be cyclonedx or spdx")
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=422, detail="SBOM must contain valid JSON") from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc

    create_asset(
        session,
        organization_id=user.organization_id,
        payload=AssetCreate(
            name=(payload.get("name") if isinstance(payload, dict) else None)
            or file.filename
            or f"{import_format} import",
            asset_type="sbom",
            external_id=(payload.get("serialNumber") if isinstance(payload, dict) else None),
            software=[
                {
                    "name": item.name,
                    "ecosystem": item.ecosystem,
                    "version": item.version,
                    "cpe": item.cpe,
                    "purl": item.purl,
                }
                for item in components
            ],
        ),
        source=format,
    )
    return ImportResult(
        import_format=import_format,
        assets_created=1,
        assets_updated=0,
        software_created=len(components),
        software_skipped=0,
        invalid_rows=[],
    )
