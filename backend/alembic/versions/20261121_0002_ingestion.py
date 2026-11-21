"""Create ingestion run, source traceability, and normalized data tables.

Revision ID: 20261121_0002
Revises: 20261121_0001
Create Date: 2026-11-21
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "20261121_0002"
down_revision: str | None = "20261121_0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "ingestion_runs",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("source", sa.String(length=32), nullable=False),
        sa.Column("mode", sa.String(length=16), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column(
            "started_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("fetched_count", sa.Integer(), nullable=False),
        sa.Column("stored_count", sa.Integer(), nullable=False),
        sa.Column("skipped_count", sa.Integer(), nullable=False),
        sa.Column("error_count", sa.Integer(), nullable=False),
        sa.Column("source_timestamp", sa.DateTime(timezone=True), nullable=True),
        sa.Column("cursor", sa.String(length=255), nullable=True),
        sa.Column("error_summary", sa.String(length=2000), nullable=True),
        sa.Column("details", sa.JSON(), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_ingestion_runs_source_started", "ingestion_runs", ["source", "started_at"])

    op.create_table(
        "source_records",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("source", sa.String(length=32), nullable=False),
        sa.Column("source_id", sa.String(length=255), nullable=False),
        sa.Column("record_type", sa.String(length=64), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("content_sha256", sa.String(length=64), nullable=False),
        sa.Column("source_modified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "ingested_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("source", "source_id", name="uq_source_records_source_id"),
    )
    op.create_index(
        "ix_source_records_source_modified", "source_records", ["source", "source_modified_at"]
    )

    op.create_table(
        "cve_records",
        sa.Column("cve_id", sa.String(length=32), nullable=False),
        sa.Column("description", sa.String(length=10000), nullable=True),
        sa.Column("published_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("modified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("cvss", sa.JSON(), nullable=False),
        sa.Column("cwe_ids", sa.JSON(), nullable=False),
        sa.Column("references", sa.JSON(), nullable=False),
        sa.Column("affected", sa.JSON(), nullable=False),
        sa.Column("source_ids", sa.JSON(), nullable=False),
        sa.Column(
            "ingested_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.PrimaryKeyConstraint("cve_id"),
    )
    op.create_table(
        "kev_records",
        sa.Column("cve_id", sa.String(length=32), nullable=False),
        sa.Column("vendor_project", sa.String(length=255), nullable=True),
        sa.Column("product", sa.String(length=255), nullable=True),
        sa.Column("name", sa.String(length=500), nullable=True),
        sa.Column("date_added", sa.DateTime(timezone=True), nullable=True),
        sa.Column("due_date", sa.DateTime(timezone=True), nullable=True),
        sa.Column("known_ransomware", sa.String(length=32), nullable=True),
        sa.Column("cwes", sa.JSON(), nullable=False),
        sa.Column("notes", sa.String(length=5000), nullable=True),
        sa.Column(
            "ingested_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.PrimaryKeyConstraint("cve_id"),
    )
    op.create_table(
        "epss_records",
        sa.Column("cve_id", sa.String(length=32), nullable=False),
        sa.Column("epss", sa.Float(), nullable=False),
        sa.Column("percentile", sa.Float(), nullable=False),
        sa.Column("score_date", sa.DateTime(timezone=True), nullable=False),
        sa.Column(
            "ingested_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.PrimaryKeyConstraint("cve_id"),
    )
    op.create_table(
        "osv_records",
        sa.Column("osv_id", sa.String(length=255), nullable=False),
        sa.Column("aliases", sa.JSON(), nullable=False),
        sa.Column("summary", sa.String(length=5000), nullable=True),
        sa.Column("details", sa.String(length=20000), nullable=True),
        sa.Column("published_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("modified_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("affected", sa.JSON(), nullable=False),
        sa.Column("references", sa.JSON(), nullable=False),
        sa.Column("severity", sa.JSON(), nullable=False),
        sa.Column(
            "ingested_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.PrimaryKeyConstraint("osv_id"),
    )
    op.create_table(
        "cwe_records",
        sa.Column("cwe_id", sa.String(length=16), nullable=False),
        sa.Column("name", sa.String(length=500), nullable=True),
        sa.Column("description", sa.String(length=10000), nullable=True),
        sa.Column("weakness_abstract", sa.String(length=32), nullable=True),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("related_cwes", sa.JSON(), nullable=False),
        sa.Column(
            "ingested_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False
        ),
        sa.PrimaryKeyConstraint("cwe_id"),
    )


def downgrade() -> None:
    op.drop_table("cwe_records")
    op.drop_table("osv_records")
    op.drop_table("epss_records")
    op.drop_table("kev_records")
    op.drop_table("cve_records")
    op.drop_index("ix_source_records_source_modified", table_name="source_records")
    op.drop_table("source_records")
    op.drop_index("ix_ingestion_runs_source_started", table_name="ingestion_runs")
    op.drop_table("ingestion_runs")
