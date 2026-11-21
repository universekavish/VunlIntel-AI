"""FIRST EPSS API and official daily CSV dataset client."""

import csv
import gzip
from datetime import UTC, datetime

import httpx

from app.ingestion.http import request_with_retry
from app.ingestion.types import FetchPage, SourceRecord


class EpssClient:
    """Read official FIRST EPSS API scores or the daily CSV/GZIP dataset."""

    source_name = "epss"

    def __init__(
        self,
        *,
        api_url: str,
        daily_url: str,
        timeout_seconds: float = 60,
    ) -> None:
        self.api_url = api_url
        self.daily_url = daily_url
        self.client = httpx.AsyncClient(
            headers={"User-Agent": "VulnIntel-AI/1.0"},
            timeout=timeout_seconds,
        )

    async def close(self) -> None:
        await self.client.aclose()

    async def fetch_initial(self) -> FetchPage:
        response = await request_with_retry(self.client, "GET", self.daily_url)
        decompressed = gzip.decompress(response.content)
        text = decompressed.decode("utf-8")
        lines = [line for line in text.splitlines() if not line.startswith("#")]
        reader = csv.DictReader(lines)
        records: list[SourceRecord] = []
        for row in reader:
            cve_id = row.get("cve")
            if not cve_id:
                continue
            payload = {
                "cve": cve_id,
                "epss": float(row["epss"]),
                "percentile": float(row["percentile"]),
            }
            records.append(
                SourceRecord(
                    source_id=cve_id,
                    record_type="epss_score",
                    payload=payload,
                    source_modified_at=datetime.now(UTC),
                )
            )
        return FetchPage(records=tuple(records), source_timestamp=datetime.now(UTC))

    async def fetch_incremental(self, *, since: datetime | None) -> FetchPage:
        return await self.fetch_initial()

    async def fetch_api_scores(self, cve_ids: list[str]) -> FetchPage:
        """Fetch point-in-time scores for a bounded list of CVEs through the API."""
        records: list[SourceRecord] = []
        for start in range(0, len(cve_ids), 100):
            batch = cve_ids[start : start + 100]
            response = await request_with_retry(
                self.client,
                "GET",
                self.api_url,
                params={"cve": ",".join(batch), "epss": "true", "percentile": "true"},
            )
            payload = response.json()
            for item in payload.get("data", []):
                cve_id = item.get("cve")
                if not cve_id:
                    continue
                records.append(
                    SourceRecord(
                        source_id=cve_id,
                        record_type="epss_score",
                        payload=item,
                        source_modified_at=datetime.now(UTC),
                    )
                )
        return FetchPage(records=tuple(records), source_timestamp=datetime.now(UTC))
