"""Official CISA Known Exploited Vulnerabilities catalog download."""

from datetime import datetime

import httpx

from app.ingestion.http import request_with_retry
from app.ingestion.types import FetchPage, SourceRecord


class CisaKevClient:
    """Download and validate the official CISA KEV JSON catalog."""

    source_name = "cisa_kev"

    def __init__(self, download_url: str, timeout_seconds: float = 60) -> None:
        self.download_url = download_url
        self.client = httpx.AsyncClient(
            headers={"User-Agent": "VulnIntel-AI/1.0"},
            timeout=timeout_seconds,
        )

    async def close(self) -> None:
        await self.client.aclose()

    async def _fetch(self) -> FetchPage:
        response = await request_with_retry(self.client, "GET", self.download_url)
        payload = response.json()
        if not isinstance(payload, dict) or not isinstance(payload.get("vulnerabilities"), list):
            raise ValueError("CISA KEV response did not contain a vulnerabilities list")
        records: list[SourceRecord] = []
        latest: datetime | None = None
        release = payload.get("dateReleased")
        if isinstance(release, str):
            try:
                latest = datetime.fromisoformat(release.replace("Z", "+00:00"))
            except ValueError:
                latest = None
        for item in payload["vulnerabilities"]:
            cve_id = item.get("cveID") if isinstance(item, dict) else None
            if not isinstance(cve_id, str):
                continue
            records.append(
                SourceRecord(
                    source_id=cve_id,
                    record_type="cisa_kev",
                    payload=item,
                    source_modified_at=latest,
                )
            )
        return FetchPage(
            records=tuple(records), cursor=payload.get("catalogVersion"), source_timestamp=latest
        )

    async def fetch_initial(self) -> FetchPage:
        return await self._fetch()

    async def fetch_incremental(self, *, since: datetime | None) -> FetchPage:
        return await self._fetch()
