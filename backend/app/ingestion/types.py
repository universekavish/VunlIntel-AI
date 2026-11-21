"""Shared types for independent vulnerability-source ingestion adapters."""

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Protocol


@dataclass(frozen=True, slots=True)
class SourceRecord:
    """One validated source record ready for traceable persistence."""

    source_id: str
    record_type: str
    payload: dict[str, Any]
    source_modified_at: datetime | None = None


@dataclass(frozen=True, slots=True)
class FetchPage:
    """One page or downloaded chunk returned by a source client."""

    records: tuple[SourceRecord, ...]
    cursor: str | None = None
    source_timestamp: datetime | None = None


class SourceClient(Protocol):
    """Typed interface every independent source adapter implements."""

    source_name: str

    async def fetch_initial(self) -> FetchPage:
        """Fetch the complete initial dataset or a first pagination page."""

    async def fetch_incremental(
        self,
        *,
        since: datetime | None,
    ) -> FetchPage:
        """Fetch records changed since the supplied source timestamp."""
