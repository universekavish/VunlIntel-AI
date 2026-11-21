"""MITRE CWE XML download and normalization client."""

import io
from datetime import UTC, datetime
from xml.etree import ElementTree
from zipfile import ZipFile

import httpx

from app.ingestion.http import request_with_retry
from app.ingestion.types import FetchPage, SourceRecord


class CweClient:
    """Download and parse the official MITRE CWE XML ZIP release."""

    source_name = "mitre_cwe"

    def __init__(self, download_url: str, timeout_seconds: float = 120) -> None:
        self.download_url = download_url
        self.client = httpx.AsyncClient(
            headers={"User-Agent": "VulnIntel-AI/1.0"},
            timeout=timeout_seconds,
        )

    async def close(self) -> None:
        await self.client.aclose()

    async def _fetch(self) -> FetchPage:
        response = await request_with_retry(self.client, "GET", self.download_url)
        records: list[SourceRecord] = []
        with ZipFile(io.BytesIO(response.content)) as archive:
            xml_names = [name for name in archive.namelist() if name.lower().endswith(".xml")]
            if not xml_names:
                raise ValueError("MITRE CWE archive did not contain an XML file")
            root = ElementTree.fromstring(archive.read(xml_names[0]))
        namespace = ""
        if root.tag.startswith("{"):
            namespace = root.tag.split("}", 1)[0] + "}"
        for weakness in root.iter(f"{namespace}Weakness"):
            cwe_id = weakness.attrib.get("ID")
            if not cwe_id:
                continue
            full_id = f"CWE-{cwe_id}"
            name = weakness.attrib.get("Name")
            abstract = weakness.attrib.get("Abstraction")
            status = weakness.attrib.get("Status")
            description_node = weakness.find(f"{namespace}Description")
            description = (
                "".join(description_node.itertext()).strip()
                if description_node is not None
                else None
            )
            related: list[str] = []
            for relation in weakness.iter(f"{namespace}Related_Weakness"):
                related_id = relation.attrib.get("CWE_ID")
                if related_id:
                    related.append(f"CWE-{related_id}")
            payload = {
                "CWE_ID": cwe_id,
                "Name": name,
                "Abstraction": abstract,
                "Status": status,
                "Description": description,
                "Related_Weaknesses": sorted(set(related)),
            }
            records.append(
                SourceRecord(
                    source_id=full_id,
                    record_type="mitre_cwe",
                    payload=payload,
                    source_modified_at=datetime.now(UTC),
                )
            )
        return FetchPage(records=tuple(records), source_timestamp=datetime.now(UTC))

    async def fetch_initial(self) -> FetchPage:
        return await self._fetch()

    async def fetch_incremental(self, *, since: datetime | None) -> FetchPage:
        return await self._fetch()
