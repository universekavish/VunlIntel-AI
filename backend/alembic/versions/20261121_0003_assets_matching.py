"""Add tenant asset inventory, normalized software, and vulnerability matches.

Revision ID: 20261121_0003
Revises: 20261121_0002
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "20261121_0003"
down_revision: str | None = "20261121_0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "assets",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("asset_type", sa.String(length=64), nullable=False),
        sa.Column("hostname", sa.String(length=255), nullable=True),
        sa.Column("environment", sa.String(length=64), nullable=True),
        sa.Column("criticality", sa.String(length=16), nullable=False),
        sa.Column("external_id", sa.String(length=255), nullable=True),
        sa.Column("active", sa.Boolean(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.CheckConstraint(
            "criticality IN ('low', 'medium', 'high', 'critical')",
            name="ck_assets_criticality",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "organization_id",
            "external_id",
            name="uq_assets_org_external",
        ),
    )
    op.create_index("ix_assets_org_name", "assets", ["organization_id", "name"])

    op.create_table(
        "software_products",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("ecosystem", sa.String(length=64), nullable=False),
        sa.Column("canonical_name", sa.String(length=255), nullable=False),
        sa.Column("display_name", sa.String(length=255), nullable=False),
        sa.Column("cpe", sa.String(length=1024), nullable=True),
        sa.Column("purl", sa.String(length=1024), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "ecosystem",
            "canonical_name",
            name="uq_software_product_ecosystem_name",
        ),
    )
    op.create_index(
        "ix_software_products_ecosystem_name",
        "software_products",
        ["ecosystem", "canonical_name"],
    )

    op.create_table(
        "asset_software",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("asset_id", sa.Uuid(), nullable=False),
        sa.Column("product_id", sa.Uuid(), nullable=False),
        sa.Column("version", sa.String(length=255), nullable=False),
        sa.Column("cpe", sa.String(length=1024), nullable=True),
        sa.Column("purl", sa.String(length=1024), nullable=True),
        sa.Column("source", sa.String(length=32), nullable=False),
        sa.Column(
            "detected_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(["asset_id"], ["assets.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(
            ["product_id"],
            ["software_products.id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "asset_id",
            "product_id",
            "version",
            name="uq_asset_software_version",
        ),
    )
    op.create_index("ix_asset_software_asset", "asset_software", ["asset_id"])

    op.create_table(
        "vulnerability_matches",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("asset_id", sa.Uuid(), nullable=False),
        sa.Column("software_id", sa.Uuid(), nullable=False),
        sa.Column("vulnerability_id", sa.String(length=255), nullable=False),
        sa.Column("source", sa.String(length=32), nullable=False),
        sa.Column("outcome", sa.String(length=32), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column("evidence", sa.JSON(), nullable=False),
        sa.Column(
            "matched_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.CheckConstraint(
            "outcome IN ('confirmed', 'potential', 'not_affected', 'needs_review')",
            name="ck_vulnerability_match_outcome",
        ),
        sa.ForeignKeyConstraint(["asset_id"], ["assets.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(
            ["software_id"],
            ["asset_software.id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "asset_id",
            "software_id",
            "vulnerability_id",
            "source",
            name="uq_vulnerability_match",
        ),
    )
    op.create_index(
        "ix_matches_asset_status",
        "vulnerability_matches",
        ["asset_id", "outcome"],
    )


def downgrade() -> None:
    op.drop_index("ix_matches_asset_status", table_name="vulnerability_matches")
    op.drop_table("vulnerability_matches")
    op.drop_index("ix_asset_software_asset", table_name="asset_software")
    op.drop_table("asset_software")
    op.drop_index(
        "ix_software_products_ecosystem_name",
        table_name="software_products",
    )
    op.drop_table("software_products")
    op.drop_index("ix_assets_org_name", table_name="assets")
    op.drop_table("assets")
