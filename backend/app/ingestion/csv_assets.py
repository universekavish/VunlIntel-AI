"""Strict CSV asset inventory import parser."""

import csv
import io

from app.schemas.assets import AssetCreate, SoftwareCreate

MAX_CSV_BYTES = 5 * 1024 * 1024
REQUIRED_HEADERS = {"name", "asset_type"}


def parse_asset_csv(content: bytes) -> tuple[list[AssetCreate], list[dict[str, str]]]:
    """Parse a bounded CSV import and return valid assets plus row-level errors."""
    if len(content) > MAX_CSV_BYTES:
        raise ValueError("CSV import exceeds the 5 MiB size limit")
    try:
        text = content.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise ValueError("CSV must be UTF-8 encoded") from exc
    reader = csv.DictReader(io.StringIO(text))
    if reader.fieldnames is None:
        raise ValueError("CSV header row is required")
    headers = {header.strip() for header in reader.fieldnames if header}
    missing = REQUIRED_HEADERS - headers
    if missing:
        raise ValueError(f"CSV missing required headers: {', '.join(sorted(missing))}")
    assets: dict[str, AssetCreate] = {}
    invalid: list[dict[str, str]] = []
    for line_number, row in enumerate(reader, start=2):
        try:
            name = (row.get("name") or "").strip()
            asset_type = (row.get("asset_type") or "").strip()
            if not name or not asset_type:
                raise ValueError("name and asset_type are required")
            external_id = (row.get("external_id") or "").strip() or None
            software_name = (row.get("software_name") or "").strip()
            software: list[SoftwareCreate] = []
            if software_name:
                software_version = (row.get("software_version") or "").strip()
                ecosystem = (row.get("ecosystem") or "unknown").strip() or "unknown"
                if not software_version:
                    raise ValueError("software_version is required when software_name is set")
                software.append(
                    SoftwareCreate(
                        name=software_name,
                        ecosystem=ecosystem,
                        version=software_version,
                        cpe=(row.get("cpe") or "").strip() or None,
                        purl=(row.get("purl") or "").strip() or None,
                    )
                )
            key = external_id or f"name:{name}|type:{asset_type}"
            existing = assets.get(key)
            if existing:
                existing.software.extend(software)
            else:
                assets[key] = AssetCreate(
                    name=name,
                    asset_type=asset_type,
                    hostname=(row.get("hostname") or "").strip() or None,
                    environment=(row.get("environment") or "").strip() or None,
                    criticality=(row.get("criticality") or "medium").strip().lower(),
                    external_id=external_id,
                    software=software,
                )
        except (ValueError, KeyError) as exc:
            invalid.append({"row": str(line_number), "error": str(exc)})
    return list(assets.values()), invalid
