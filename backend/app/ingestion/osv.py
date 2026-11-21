"""Official OSV.dev API client."""

from datetime import datetime

import httpx

from app.ingestion.http import request_with_retry
from app.ingestion.types import FetchPage, SourceRecord


class OsvClient:
    """Fetch OSV records through official query and vulnerability endpoints."""

    source_name = "osv"

    def __init__(self, api_url: str, timeout_seconds: float = 60) -> None:
        self.api_url = api_url.rstrip("/")
        self.client = httpx.AsyncClient(
            headers={"User-Agent": "VulnIntel-AI/1.0"},
            timeout=timeout_seconds,
        )

    async def close(self) -> None:
        await self.client.aclose()

    async def fetch_ids(self, identifiers: list[str]) -> FetchPage:
        """Query OSV by CVE/GHSA identifiers using bounded batches."""
        records: list[SourceRecord] = []
        latest: datetime | None = None
        for start in range(0, len(identifiers), 100):
            batch = identifiers[start : start + 100]
            response = await request_with_retry(
                self.client,
                "POST",
                f"{self.api_url}/v1/querybatch",
                json={"queries": [{"id": identifier} for identifier in batch]},
            )
            payload = response.json()
            for result in payload.get("results", []):
                vulns = result.get("vulns", []) if isinstance(result, dict) else []
                for summary in vulns:
                    osv_id = summary.get("id") if isinstance(summary, dict) else None
                    if not isinstance(osv_id, str):
                        continue
                    detail_response = await request_with_retry(
                        self.client,
                        "GET",
                        f"{self.api_url}/v1/vulns/{osv_id}",
                    )
                    detail = detail_response.json()
                    modified = detail.get("modified")
                    modified_at = None
                    if isinstance(modified, str):
                        try:
                            modified_at = datetime.fromisoformat(modified.replace("Z", "+00:00"))
                        except ValueError:
                            modified_at = None
                    records.append(
                        SourceRecord(
                            source_id=osv_id,
                            record_type="osv_vulnerability",
                            payload=detail,
                            source_modified_at=modified_at,
                        )
                    )
                    if modified_at is not None and (latest is None or modified_at > latest):
                        latest = modified_at
        return FetchPage(records=tuple(records), cursor=str(len(records)), source_timestamp=latest)

    async def fetch_initial(self) -> FetchPage:
        return FetchPage(records=())

    async def fetch_incremental(self, *, since: datetime | None) -> FetchPage:
        return FetchPage(records=(), cursor=None, source_timestamp=since)
