"""Source-independent ingestion run orchestration."""

from datetime import datetime
from typing import Protocol

from sqlalchemy.orm import Session

from app.ingestion.repository import finish_run, start_run, upsert_normalized, upsert_source
from app.ingestion.types import FetchPage


class IngestionClient(Protocol):
    source_name: str

    async def fetch_initial(self) -> FetchPage: ...

    async def fetch_incremental(self, *, since: datetime | None) -> FetchPage: ...


async def synchronize(
    session: Session,
    *,
    client: IngestionClient,
    mode: str = "incremental",
    since: datetime | None = None,
) -> object:
    """Run one ingestion workflow with bounded accounting and rollback on failure."""
    if mode not in {"initial", "incremental"}:
        raise ValueError("Ingestion mode must be 'initial' or 'incremental'")
    run = start_run(session, source=client.source_name, mode=mode)
    fetched = 0
    stored = 0
    skipped = 0
    errors = 0
    source_timestamp = since
    cursor: str | None = None
    try:
        page = (
            await client.fetch_initial()
            if mode == "initial"
            else await client.fetch_incremental(since=since)
        )
        fetched = len(page.records)
        seen: set[tuple[str, str]] = set()
        for record in page.records:
            key = (record.record_type, record.source_id)
            if key in seen:
                skipped += 1
                continue
            seen.add(key)
            try:
                source_changed = upsert_source(
                    session,
                    source=client.source_name,
                    record=record,
                )
                normalized_changed = upsert_normalized(
                    session,
                    source=client.source_name,
                    record=record,
                )
                if source_changed or normalized_changed:
                    stored += 1
                else:
                    skipped += 1
            except Exception:
                session.rollback()
                errors += 1
        session.commit()
        if page.source_timestamp is not None:
            source_timestamp = page.source_timestamp
        cursor = page.cursor
        status = "completed" if errors == 0 else "completed_with_errors"
        error_summary = f"{errors} record(s) failed validation or normalization" if errors else None
    except Exception as exc:
        session.rollback()
        finish_run(
            session,
            run,
            status="failed",
            fetched_count=fetched,
            stored_count=stored,
            skipped_count=skipped,
            error_count=max(1, errors),
            source_timestamp=source_timestamp,
            cursor=cursor,
            error_summary=str(exc)[:2000],
        )
        raise
    return finish_run(
        session,
        run,
        status=status,
        fetched_count=fetched,
        stored_count=stored,
        skipped_count=skipped,
        error_count=errors,
        source_timestamp=source_timestamp,
        cursor=cursor,
        error_summary=error_summary,
    )
