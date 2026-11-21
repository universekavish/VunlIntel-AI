"""Database migration integration tests."""

from pathlib import Path

from alembic.config import Config
from sqlalchemy import create_engine, inspect

from alembic import command

BACKEND_ROOT = Path(__file__).resolve().parents[2]


def test_identity_migration_up_and_down(tmp_path: Path) -> None:
    database_url = f"sqlite:///{tmp_path / 'migration.db'}"
    migration_config = Config(str(BACKEND_ROOT / "alembic.ini"))
    migration_config.attributes["database_url"] = database_url

    command.upgrade(migration_config, "head")
    command.check(migration_config)
    engine = create_engine(database_url)
    assert {
        "organizations",
        "users",
        "audit_events",
        "ingestion_runs",
        "source_records",
        "cve_records",
        "kev_records",
        "epss_records",
        "osv_records",
        "cwe_records",
        "assets",
        "software_products",
        "asset_software",
        "vulnerability_matches",
        "risk_history",
        "rag_documents",
        "rag_index_runs",
        "investigations",
        "investigation_audit",
    } <= set(inspect(engine).get_table_names())

    command.downgrade(migration_config, "base")
    assert not {
        "organizations",
        "users",
        "audit_events",
        "ingestion_runs",
        "source_records",
        "cve_records",
        "kev_records",
        "epss_records",
        "osv_records",
        "cwe_records",
        "assets",
        "software_products",
        "asset_software",
        "vulnerability_matches",
        "risk_history",
        "rag_documents",
        "rag_index_runs",
        "investigations",
        "investigation_audit",
    } & set(inspect(engine).get_table_names())
    engine.dispose()
