"""Unit tests for official-source ingestion response parsing."""

import json
from pathlib import Path
from zipfile import ZipFile

import httpx
import pytest

from app.ingestion.cisa_kev import CisaKevClient
from app.ingestion.cwe import CweClient
from app.ingestion.epss import EpssClient
from app.ingestion.nvd import NvdClient
from app.ingestion.osv import OsvClient

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


@pytest.mark.asyncio
async def test_nvd_paginates_and_returns_source_records() -> None:
    payload = json.loads((FIXTURES / "nvd_page.json").read_text())
    calls: list[str] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        return httpx.Response(200, json=payload)

    client = NvdClient(api_url="https://nvd.test/rest/json/cves/2.0")
    await client.close()
    client = NvdClient(api_url="https://nvd.test/rest/json/cves/2.0")
    client.client = httpx.AsyncClient(transport=httpx.MockTransport(handler))

    page = await client.fetch_initial()
    await client.close()

    assert len(page.records) == 2
    assert page.records[0].source_id == "CVE-2024-0001"
    assert len(calls) >= 1


@pytest.mark.asyncio
async def test_cisa_kev_download_is_validated() -> None:
    payload = json.loads((FIXTURES / "cisa_kev.json").read_text())

    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=payload)

    client = CisaKevClient("https://cisa.test/kev.json")
    await client.close()
    client = CisaKevClient("https://cisa.test/kev.json")
    client.client = httpx.AsyncClient(transport=httpx.MockTransport(handler))

    page = await client.fetch_initial()
    await client.close()

    assert len(page.records) == 1
    assert page.records[0].source_id == "CVE-2024-0001"


@pytest.mark.asyncio
async def test_epss_api_normalizes_source_rows() -> None:
    payload = json.loads((FIXTURES / "epss.json").read_text())

    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=payload)

    client = EpssClient(
        api_url="https://epss.test/api",
        daily_url="https://epss.test/daily.csv.gz",
    )
    await client.close()
    client = EpssClient(
        api_url="https://epss.test/api",
        daily_url="https://epss.test/daily.csv.gz",
    )
    client.client = httpx.AsyncClient(transport=httpx.MockTransport(handler))

    page = await client.fetch_api_scores(["CVE-2024-0001"])
    await client.close()

    assert page.records[0].payload["epss"] == "0.12345"


@pytest.mark.asyncio
async def test_osv_querybatch_and_detail_are_real_schema_shape() -> None:
    detail = json.loads((FIXTURES / "osv.json").read_text())

    async def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/v1/querybatch"):
            return httpx.Response(
                200, json={"results": [{"id": "CVE-2024-0001", "vulns": [{"id": "CVE-2024-0001"}]}]}
            )
        return httpx.Response(200, json=detail)

    client = OsvClient("https://osv.test")
    await client.close()
    client = OsvClient("https://osv.test")
    client.client = httpx.AsyncClient(transport=httpx.MockTransport(handler))

    page = await client.fetch_ids(["CVE-2024-0001"])
    await client.close()

    assert page.records[0].source_id == "CVE-2024-0001"
    assert page.records[0].payload["schema_version"] == "1.6.0"


@pytest.mark.asyncio
async def test_mitre_cwe_zip_parses_weaknesses(tmp_path: Path) -> None:
    archive_path = tmp_path / "cwe.zip"
    xml = b"""<?xml version="1.0"?>
<Weakness_Catalog xmlns="http://cwe.mitre.org/cwe-7">
  <Weaknesses>
    <Weakness ID="79" Name="Cross-site Scripting" Abstraction="Base" Status="Stable">
      <Description>Improper neutralization of input during web page generation.</Description>
      <Related_Weaknesses>
        <Related_Weakness CWE_ID="74"/>
      </Related_Weaknesses>
    </Weakness>
  </Weaknesses>
</Weakness_Catalog>
"""
    with ZipFile(archive_path, "w") as archive:
        archive.writestr("cwec_v7.xml", xml)

    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=archive_path.read_bytes())

    client = CweClient("https://cwe.test/cwe.zip")
    await client.close()
    client = CweClient("https://cwe.test/cwe.zip")
    client.client = httpx.AsyncClient(transport=httpx.MockTransport(handler))

    page = await client.fetch_initial()
    await client.close()

    assert page.records[0].source_id == "CWE-79"
    assert page.records[0].payload["Related_Weaknesses"] == ["CWE-74"]
