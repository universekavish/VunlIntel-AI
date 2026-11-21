"""Idempotent persistence for source records and normalized ingestion entities."""

import hashlib
import json
from datetime import datetime
from typing import Any
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models import (
    CveRecord,
    CweRecord,
    EpssRecord,
    IngestionRun,
    KevRecord,
    OsvRecord,
    SourceRecord,
)
from app.ingestion.types import SourceRecord as AdapterRecord


def start_run(
    session: Session,
    *,
    source: str,
    mode: str,
) -> IngestionRun:
    """Create a running ingestion record before fetching source data."""
    run = IngestionRun(id=uuid4(), source=source, mode=mode, status="running")
    session.add(run)
    session.commit()
    return run


def finish_run(
    session: Session,
    run: IngestionRun,
    *,
    status: str,
    fetched_count: int,
    stored_count: int,
    skipped_count: int,
    error_count: int,
    source_timestamp: datetime | None,
    cursor: str | None,
    error_summary: str | None = None,
) -> IngestionRun:
    """Finalize lifecycle counters for an ingestion run."""
    run.status = status
    run.completed_at = datetime.now()
    run.fetched_count = fetched_count
    run.stored_count = stored_count
    run.skipped_count = skipped_count
    run.error_count = error_count
    run.source_timestamp = source_timestamp
    run.cursor = cursor
    run.error_summary = error_summary
    session.commit()
    return run


def upsert_source(
    session: Session,
    *,
    source: str,
    record: AdapterRecord,
) -> bool:
    """Persist an original payload once, updating it only if content changed."""
    canonical = json.dumps(
        record.payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    existing = session.scalar(
        select(SourceRecord).where(
            SourceRecord.source == source,
            SourceRecord.source_id == record.source_id,
        )
    )
    if existing is None:
        session.add(
            SourceRecord(
                id=uuid4(),
                source=source,
                source_id=record.source_id,
                record_type=record.record_type,
                payload=record.payload,
                content_sha256=digest,
                source_modified_at=record.source_modified_at,
            )
        )
        return True
    if existing.content_sha256 != digest:
        existing.payload = record.payload
        existing.content_sha256 = digest
        existing.record_type = record.record_type
        existing.source_modified_at = record.source_modified_at
        return True
    return False


def _parse_datetime(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def upsert_normalized(
    session: Session,
    *,
    source: str,
    record: AdapterRecord,
) -> bool:
    """Translate one validated source record into its normalized table."""
    payload = record.payload
    changed = True
    if source == "nvd":
        cve = payload.get("cve")
        cve = cve if isinstance(cve, dict) else {}
        cve_id = cve.get("id")
        if not isinstance(cve_id, str):
            return False
        descriptions = cve.get("descriptions", [])
        description = next(
            (
                item.get("value")
                for item in descriptions
                if isinstance(item, dict) and item.get("lang") == "en"
            ),
            None,
        )
        cwe_ids: list[str] = []
        for weakness in cve.get("weaknesses", []):
            if not isinstance(weakness, dict):
                continue
            for entry in weakness.get("description", []):
                value = entry.get("value") if isinstance(entry, dict) else None
                if isinstance(value, str):
                    cwe_ids.append(value)
        references = [
            item["url"]
            for item in cve.get("references", [])
            if isinstance(item, dict) and isinstance(item.get("url"), str)
        ]
        cvss: dict[str, Any] = {}
        metrics = cve.get("metrics", {})
        if isinstance(metrics, dict):
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                values = metrics.get(key)
                if isinstance(values, list) and values:
                    cvss = values[0]
                    break
        affected: list[dict[str, Any]] = []
        for node in cve.get("configurations", []):
            if not isinstance(node, dict):
                continue
            for candidate in node.get("nodes", []):
                if not isinstance(candidate, dict):
                    continue
                for match in candidate.get("cpeMatch", []):
                    if not isinstance(match, dict):
                        continue
                    cpe = match.get("criteria")
                    if isinstance(cpe, str):
                        affected.append(
                            {
                                "cpe": cpe,
                                "vulnerable": match.get("vulnerable", True),
                                "versionStartIncluding": match.get("versionStartIncluding"),
                                "versionStartExcluding": match.get("versionStartExcluding"),
                                "versionEndIncluding": match.get("versionEndIncluding"),
                                "versionEndExcluding": match.get("versionEndExcluding"),
                            }
                        )
        normalized = CveRecord(
            cve_id=cve_id,
            description=description,
            published_at=_parse_datetime(cve.get("published")),
            modified_at=_parse_datetime(cve.get("lastModified")),
            cvss=cvss,
            cwe_ids=sorted(set(cwe_ids)),
            references=sorted(set(references)),
            affected=affected,
            source_ids=["nvd"],
        )
        session.merge(normalized)
    elif source == "cisa_kev":
        cve_id = payload.get("cveID")
        if not isinstance(cve_id, str):
            return False
        normalized = KevRecord(
            cve_id=cve_id,
            vendor_project=payload.get("vendorProject"),
            product=payload.get("product"),
            name=payload.get("vulnerabilityName"),
            date_added=_parse_datetime(payload.get("dateAdded")),
            due_date=_parse_datetime(payload.get("dueDate")),
            known_ransomware=payload.get("knownRansomwareCampaignUse"),
            cwes=sorted(set(payload.get("cwes", [])))
            if isinstance(payload.get("cwes"), list)
            else [],
            notes=payload.get("notes"),
        )
        session.merge(normalized)
    elif source == "epss":
        cve_id = payload.get("cve")
        if not isinstance(cve_id, str):
            return False
        epss = payload.get("epss")
        percentile = payload.get("percentile")
        try:
            epss_value = float(epss)
            percentile_value = float(percentile)
        except (TypeError, ValueError):
            return False
        normalized = EpssRecord(
            cve_id=cve_id,
            epss=epss_value,
            percentile=percentile_value,
            score_date=record.source_modified_at or datetime.now(),
        )
        session.merge(normalized)
    elif source == "osv":
        osv_id = payload.get("id")
        if not isinstance(osv_id, str):
            return False
        normalized = OsvRecord(
            osv_id=osv_id,
            aliases=sorted(set(payload.get("aliases", [])))
            if isinstance(payload.get("aliases"), list)
            else [],
            summary=payload.get("summary"),
            details=payload.get("details"),
            published_at=_parse_datetime(payload.get("published")),
            modified_at=_parse_datetime(payload.get("modified")),
            affected=payload.get("affected", [])
            if isinstance(payload.get("affected"), list)
            else [],
            references=[
                item["url"]
                for item in payload.get("references", [])
                if isinstance(item, dict) and isinstance(item.get("url"), str)
            ],
            severity=payload.get("severity", [])
            if isinstance(payload.get("severity"), list)
            else [],
        )
        session.merge(normalized)
    elif source == "mitre_cwe":
        cwe_id = payload.get("CWE_ID")
        if not isinstance(cwe_id, str):
            return False
        normalized = CweRecord(
            cwe_id=f"CWE-{cwe_id}",
            name=payload.get("Name"),
            description=payload.get("Description"),
            weakness_abstract=payload.get("Abstraction"),
            status=payload.get("Status") or "Unknown",
            related_cwes=payload.get("Related_Weaknesses", []),
        )
        session.merge(normalized)
    else:
        return False
    return changed
