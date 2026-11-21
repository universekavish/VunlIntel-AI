"""Add RAG document, evidence, and index-run persistence.

Revision ID: 20261121_0005
Revises: 20261121_0004
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "20261121_0005"
down_revision: str | None = "20261121_0004"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "rag_documents",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("source", sa.String(length=32), nullable=False),
        sa.Column("source_id", sa.String(length=255), nullable=False),
        sa.Column("document_type", sa.String(length=32), nullable=False),
        sa.Column("chunk_index", sa.Integer(), nullable=False),
        sa.Column("content_sha256", sa.String(length=64), nullable=False),
        sa.Column("text", sa.String(length=20000), nullable=False),
        sa.Column("metadata_json", sa.JSON(), nullable=False),
        sa.Column("qdrant_point_id", sa.String(length=64), nullable=False),
        sa.Column(
            "embedded_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "organization_id",
            "source",
            "source_id",
            "chunk_index",
            name="uq_rag_document_chunk",
        ),
    )
    op.create_index(
        "ix_rag_documents_org_source",
        "rag_documents",
        ["organization_id", "source"],
    )
    op.create_table(
        "rag_index_runs",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("organization_id", sa.Uuid(), nullable=False),
        sa.Column("status", sa.String(length=16), nullable=False),
        sa.Column("documents_found", sa.Integer(), nullable=False),
        sa.Column("chunks_embedded", sa.Integer(), nullable=False),
        sa.Column("chunks_skipped", sa.Integer(), nullable=False),
        sa.Column("errors", sa.Integer(), nullable=False),
        sa.Column("collection_name", sa.String(length=255), nullable=False),
        sa.Column(
            "started_at",
            sa.DateTime(timezone=True),
            server_default=sa.func.now(),
            nullable=False,
        ),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("error_summary", sa.String(length=2000), nullable=True),
        sa.ForeignKeyConstraint(
            ["organization_id"],
            ["organizations.id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(
        "ix_rag_index_runs_org_started",
        "rag_index_runs",
        ["organization_id", "started_at"],
    )


def downgrade() -> None:
    op.drop_index("ix_rag_index_runs_org_started", table_name="rag_index_runs")
    op.drop_table("rag_index_runs")
    op.drop_index("ix_rag_documents_org_source", table_name="rag_documents")
    op.drop_table("rag_documents")
