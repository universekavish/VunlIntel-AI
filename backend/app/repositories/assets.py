"""Tenant-scoped asset persistence."""

from uuid import UUID

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models import Asset, AssetSoftware, SoftwareProduct


def get_asset(session: Session, organization_id: UUID, asset_id: UUID) -> Asset | None:
    return session.scalar(
        select(Asset).where(
            Asset.id == asset_id,
            Asset.organization_id == organization_id,
        )
    )


def list_assets(session: Session, organization_id: UUID) -> list[Asset]:
    return list(
        session.scalars(
            select(Asset).where(Asset.organization_id == organization_id).order_by(Asset.name)
        )
    )


def find_asset_external(session: Session, organization_id: UUID, external_id: str) -> Asset | None:
    return session.scalar(
        select(Asset).where(
            Asset.organization_id == organization_id,
            Asset.external_id == external_id,
        )
    )


def get_product(
    session: Session,
    ecosystem: str,
    canonical_name: str,
) -> SoftwareProduct | None:
    return session.scalar(
        select(SoftwareProduct).where(
            SoftwareProduct.ecosystem == ecosystem,
            SoftwareProduct.canonical_name == canonical_name,
        )
    )


def get_asset_software(
    session: Session,
    asset_id: UUID,
    product_id: UUID,
    version: str,
) -> AssetSoftware | None:
    return session.scalar(
        select(AssetSoftware).where(
            AssetSoftware.asset_id == asset_id,
            AssetSoftware.product_id == product_id,
            AssetSoftware.version == version,
        )
    )
