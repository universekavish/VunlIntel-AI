"""Integration tests for idempotent ingestion upserts."""

from sqlalchemy import select

from app.db.models import CveRecord, SourceRecord
from app.ingestion.repository import upsert_normalized, upsert_source
from app.ingestion.types import SourceRecord as AdapterRecord


def test_source_and_normalized_upserts_are_idempotent(
    api_client: tuple,
) -> None:
    _, session_factory = api_client
    record = AdapterRecord(
        source_id="CVE-2024-12345",
        record_type="nvd_cve",
        payload={
            "cve": {
                "id": "CVE-2024-12345",
                "published": "2024-01-01T00:00:00Z",
                "lastModified": "2024-01-02T00:00:00Z",
                "descriptions": [{"lang": "en", "value": "Real-source schema fixture"}],
                "weaknesses": [{"description": [{"lang": "en", "value": "CWE-79"}]}],
                "references": [],
                "metrics": {},
            }
        },
    )
    with session_factory() as session:
        first_source = upsert_source(session, source="nvd", record=record)
        first_normalized = upsert_normalized(session, source="nvd", record=record)
        session.commit()

        second_source = upsert_source(session, source="nvd", record=record)
        second_normalized = upsert_normalized(session, source="nvd", record=record)
        session.commit()

        source_count = len(list(session.scalars(select(SourceRecord))))
        cve_count = len(list(session.scalars(select(CveRecord))))

    assert first_source is True
    assert first_normalized is True
    assert second_source is False
    assert second_normalized is True
    assert source_count == 1
    assert cve_count == 1
