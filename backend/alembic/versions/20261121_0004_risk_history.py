"""Add asset exposure fields and deterministic risk history.

Revision ID: 20261121_0004
Revises: 20261121_0003
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "20261121_0004"
down_revision: str | None = "20261121_0003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "assets",
        sa.Column("internet_exposed", sa.Boolean(), nullable=True),
    )
    op.add_column(
        "assets",
        sa.Column("ransomware_indicator", sa.Boolean(), nullable=True),
    )
    op.create_table(
        "risk_history",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("asset_id", sa.Uuid(), nullable=False),
        sa.Column("vulnerability_id", sa.String(length=255), nullable=True),
        sa.Column("score", sa.Float(), nullable=False),
        sa.Column("risk_band", sa.String(length=16), nullable=False),
        sa.Column("factors", sa.JSON(), nullable=False),
        sa.Column("missing_signals", sa.JSON(), nullable=False),
        sa.Column("explanation", sa.String(length=5000), nullable=False),
        sa.Column("thresholds", sa.JSON(), nullable=False),
        sa.Column("confidence", sa.Float(), nullable=False),
        sa.Column(
            "calculated_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.CheckConstraint(
            "risk_band IN ('low', 'medium', 'high', 'critical')",
            name="ck_risk_history_band",
        ),
        sa.CheckConstraint(
            "score >= 0 AND score <= 100",
            name="ck_risk_history_score",
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["asset_id"],
            ["assets.id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_risk_history_asset_calculated",
        "risk_history",
        ["asset_id", "calculated_at"],
    )


def downgrade() -> None:
    op.drop_index(
        "ix_risk_history_asset_calculated",
        table_name="risk_history",
    )
    op.drop_table("risk_history")
    op.drop_column("assets", "ransomware_indicator")
    op.drop_column("assets", "internet_exposed")
