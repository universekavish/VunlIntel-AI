"""Asset CRUD and deterministic software inventory workflows."""

from datetime import UTC, datetime
from uuid import UUID, uuid4

from sqlalchemy.orm import Session

from app.core.exceptions import ResourceConflictError, ResourceNotFoundError
from app.db.models import Asset, AssetSoftware, SoftwareProduct
from app.repositories.assets import (
    find_asset_external,
    get_asset,
    get_asset_software,
    get_product,
)
from app.schemas.assets import AssetCreate, AssetUpdate, SoftwareCreate
from app.services.product_identity import canonical_product_name, normalize_ecosystem


def create_asset(
    session: Session,
    *,
    organization_id: UUID,
    payload: AssetCreate,
    source: str = "api",
) -> Asset:
    if payload.external_id:
        existing = find_asset_external(session, organization_id, payload.external_id)
        if existing:
            raise ResourceConflictError("An asset already uses this external identifier")
    asset = Asset(
        id=uuid4(),
        organization_id=organization_id,
        name=payload.name,
        asset_type=payload.asset_type,
        hostname=payload.hostname,
        environment=payload.environment,
        criticality=payload.criticality.value,
        external_id=payload.external_id,
        active=True,
        internet_exposed=payload.internet_exposed,
        ransomware_indicator=payload.ransomware_indicator,
    )
    session.add(asset)
    session.flush()
    for software in payload.software:
        upsert_asset_software(
            session,
            asset=asset,
            software=software,
            source=source,
        )
    session.commit()
    return asset


def update_asset(
    session: Session,
    *,
    organization_id: UUID,
    asset_id: UUID,
    payload: AssetUpdate,
) -> Asset:
    asset = get_asset(session, organization_id, asset_id)
    if asset is None:
        raise ResourceNotFoundError("Asset not found")
    for field, value in payload.model_dump(exclude_unset=True).items():
        setattr(asset, field, value.value if hasattr(value, "value") else value)
    asset.updated_at = datetime.now(UTC)
    session.commit()
    return asset


def deactivate_asset(session: Session, *, organization_id: UUID, asset_id: UUID) -> None:
    asset = get_asset(session, organization_id, asset_id)
    if asset is None:
        raise ResourceNotFoundError("Asset not found")
    asset.active = False
    asset.updated_at = datetime.now(UTC)
    session.commit()


def upsert_asset_software(
    session: Session,
    *,
    asset: Asset,
    software: SoftwareCreate,
    source: str,
) -> tuple[AssetSoftware, bool]:
    ecosystem = normalize_ecosystem(software.ecosystem)
    canonical = canonical_product_name(ecosystem, software.name)
    product = get_product(session, ecosystem, canonical)
    created = False
    if product is None:
        product = SoftwareProduct(
            id=uuid4(),
            ecosystem=ecosystem,
            canonical_name=canonical,
            display_name=software.name.strip(),
            cpe=software.cpe,
            purl=software.purl,
        )
        session.add(product)
        session.flush()
        created = True
    else:
        if software.cpe and not product.cpe:
            product.cpe = software.cpe
        if software.purl and not product.purl:
            product.purl = software.purl
    installed = get_asset_software(session, asset.id, product.id, software.version)
    if installed is None:
        installed = AssetSoftware(
            id=uuid4(),
            asset_id=asset.id,
            product_id=product.id,
            version=software.version,
            cpe=software.cpe,
            purl=software.purl,
            source=source,
        )
        session.add(installed)
        session.flush()
        created = True
    return installed, created
