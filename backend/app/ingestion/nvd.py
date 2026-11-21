"""Official NVD CVE API 2.0 client."""

from datetime import datetime

import httpx

from app.ingestion.http import request_with_retry
from app.ingestion.types import FetchPage, SourceRecord


class NvdClient:
    """Page through the official NVD REST API without rewriting source records."""

    source_name = "nvd"

    def __init__(
        self,
        *,
        api_url: str,
        api_key: str | None = None,
        timeout_seconds: float = 30,
    ) -> None:
        self.api_url = api_url
        headers = {"User-Agent": "VulnIntel-AI/1.0"}
        if api_key:
            headers["apiKey"] = api_key
        self.client = httpx.AsyncClient(headers=headers, timeout=timeout_seconds)

    async def close(self) -> None:
        await self.client.aclose()

    async def _fetch_range(
        self,
        *,
        start_index: int,
        modified_since: datetime | None,
    ) -> FetchPage:
        page_records: list[SourceRecord] = []
        index = start_index
        latest: datetime | None = None
        page_size = 2000
        while True:
            params: dict[str, str | int] = {
                "startIndex": index,
                "resultsPerPage": page_size,
            }
            if modified_since is not None:
                params["lastModStartDate"] = modified_since.isoformat(timespec="milliseconds")
                params["lastModEndDate"] = datetime.now().isoformat(timespec="milliseconds")
            response = await request_with_retry(
                self.client,
                "GET",
                self.api_url,
                params=params,
            )
            response.raise_for_status()
            payload = response.json()
            for item in payload.get("vulnerabilities", []):
                cve = item.get("cve")
                cve_id = cve.get("id") if isinstance(cve, dict) else None
                if not cve_id:
                    continue
                last_modified = cve.get("lastModified")
                modified = None
                if isinstance(last_modified, str):
                    try:
                        modified = datetime.fromisoformat(last_modified.replace("Z", "+00:00"))
                    except ValueError:
                        modified = None
                page_records.append(
                    SourceRecord(
                        source_id=cve_id,
                        record_type="nvd_cve",
                        payload=item,
                        source_modified_at=modified,
                    )
                )
                if modified is not None and (latest is None or modified > latest):
                    latest = modified
            total = int(payload.get("totalResults", len(page_records)))
            index += len(payload.get("vulnerabilities", []))
            if index >= total or not payload.get("vulnerabilities"):
                break
        return FetchPage(
            records=tuple(page_records),
            cursor=str(index),
            source_timestamp=latest,
        )

    async def fetch_initial(self) -> FetchPage:
        return await self._fetch_range(start_index=0, modified_since=None)

    async def fetch_incremental(self, *, since: datetime | None) -> FetchPage:
        return await self._fetch_range(start_index=0, modified_since=since)
