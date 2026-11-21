"""Administrative ingestion run inspection and execution endpoints."""

from datetime import datetime
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select

from app.api.dependencies import DatabaseSession, require_roles
from app.core.config import get_settings
from app.db.models import IngestionRun, User
from app.ingestion.cisa_kev import CisaKevClient
from app.ingestion.cwe import CweClient
from app.ingestion.epss import EpssClient
from app.ingestion.nvd import NvdClient
from app.ingestion.osv import OsvClient
from app.ingestion.service import synchronize
from app.schemas.roles import UserRole

router = APIRouter(prefix="/ingestion", tags=["ingestion"])
OwnerOnly = Annotated[User, Depends(require_roles(UserRole.OWNER))]


@router.get("/runs")
async def list_runs(
    user: OwnerOnly,
    session: DatabaseSession,
) -> list[dict[str, object]]:
    """Return recent ingestion lifecycle records for operators."""
    runs = list(
        session.scalars(select(IngestionRun).order_by(IngestionRun.started_at.desc()).limit(100))
    )
    return [
        {
            "id": str(run.id),
            "source": run.source,
            "mode": run.mode,
            "status": run.status,
            "started_at": run.started_at.isoformat(),
            "completed_at": run.completed_at.isoformat() if run.completed_at else None,
            "fetched_count": run.fetched_count,
            "stored_count": run.stored_count,
            "skipped_count": run.skipped_count,
            "error_count": run.error_count,
            "source_timestamp": (
                run.source_timestamp.isoformat() if run.source_timestamp else None
            ),
            "cursor": run.cursor,
            "error_summary": run.error_summary,
        }
        for run in runs
    ]


@router.post("/sync/{source}", status_code=status.HTTP_202_ACCEPTED)
async def sync_source(
    source: str,
    user: OwnerOnly,
    session: DatabaseSession,
    mode: str = "incremental",
    since: datetime | None = None,
    cve_ids: str | None = None,
) -> dict[str, object]:
    """Synchronize one official source in-process for initial or incremental runs."""
    settings = get_settings()
    key = settings.nvd_api_key.get_secret_value() if settings.nvd_api_key else None
    client = None
    try:
        if source == "nvd":
            client = NvdClient(api_url=settings.nvd_api_url, api_key=key)
        elif source == "cisa_kev":
            client = CisaKevClient(settings.cisa_kev_url)
        elif source == "epss":
            client = EpssClient(
                api_url=settings.epss_api_url,
                daily_url=settings.epss_daily_url,
            )
        elif source == "mitre_cwe":
            client = CweClient(settings.cwe_download_url)
        elif source == "osv":
            if not cve_ids:
                raise HTTPException(
                    status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                    detail="OSV synchronization requires a comma-separated cve_ids parameter",
                )
            client = OsvClient(settings.osv_api_url)
            identifiers = sorted({item.strip() for item in cve_ids.split(",") if item.strip()})
            run = await synchronize_osv(session, client=client, identifiers=identifiers)
            return {"run_id": str(run.id), "status": run.status}
        else:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="Unknown ingestion source"
            )
        run = await synchronize(session, client=client, mode=mode, since=since)
        return {"run_id": str(run.id), "status": run.status}
    finally:
        if client is not None:
            await client.close()


async def synchronize_osv(
    session: DatabaseSession,
    *,
    client: OsvClient,
    identifiers: list[str],
) -> object:
    """Use OSV's identifier query batch with the shared run accounting."""
    from app.ingestion.repository import finish_run, start_run, upsert_normalized, upsert_source

    run = start_run(session, source="osv", mode="initial")
    page = await client.fetch_ids(identifiers)
    stored = 0
    skipped = 0
    for record in page.records:
        source_changed = upsert_source(session, source="osv", record=record)
        normalized_changed = upsert_normalized(session, source="osv", record=record)
        if source_changed or normalized_changed:
            stored += 1
        else:
            skipped += 1
    session.commit()
    return finish_run(
        session,
        run,
        status="completed",
        fetched_count=len(page.records),
        stored_count=stored,
        skipped_count=skipped,
        error_count=0,
        source_timestamp=page.source_timestamp,
        cursor=page.cursor,
    )
