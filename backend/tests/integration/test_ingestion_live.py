"""Opt-in smoke tests against official public live source endpoints."""

import os

import httpx
import pytest

pytestmark = pytest.mark.integration


@pytest.mark.live
@pytest.mark.skipif(
    os.getenv("VULNINTEL_RUN_LIVE_INGESTION") != "1",
    reason="Set VULNINTEL_RUN_LIVE_INGESTION=1 to perform opt-in live source checks",
)
@pytest.mark.asyncio
async def test_live_cisa_kev_catalog_has_real_records() -> None:
    async with httpx.AsyncClient(timeout=60) as client:
        response = await client.get(
            "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        )
        response.raise_for_status()
        payload = response.json()

    assert isinstance(payload["count"], int)
    assert payload["count"] > 0
    assert payload["vulnerabilities"][0]["cveID"].startswith("CVE-")


@pytest.mark.live
@pytest.mark.skipif(
    os.getenv("VULNINTEL_RUN_LIVE_INGESTION") != "1",
    reason="Set VULNINTEL_RUN_LIVE_INGESTION=1 to perform opt-in live source checks",
)
@pytest.mark.asyncio
async def test_live_epss_and_osv_return_real_schema_records() -> None:
    cve_id = "CVE-2021-44228"
    async with httpx.AsyncClient(timeout=60) as client:
        epss = await client.get(
            "https://api.first.org/data/v1/epss",
            params={"cve": cve_id},
        )
        epss.raise_for_status()
        osv = await client.get(
            f"https://api.osv.dev/v1/vulns/{cve_id}",
        )
        osv.raise_for_status()

    epss_payload = epss.json()
    osv_payload = osv.json()
    assert epss_payload["data"][0]["cve"] == cve_id
    assert osv_payload["id"]


@pytest.mark.live
@pytest.mark.skipif(
    os.getenv("VULNINTEL_RUN_LIVE_INGESTION") != "1",
    reason="Set VULNINTEL_RUN_LIVE_INGESTION=1 to perform opt-in live source checks",
)
@pytest.mark.asyncio
async def test_live_nvd_and_mitre_cwe_publish_schema_records() -> None:
    async with httpx.AsyncClient(timeout=60) as client:
        nvd = await client.get(
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            params={"cveId": "CVE-2021-44228"},
        )
        nvd.raise_for_status()

        cwe = await client.get(
            "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip",
        )
        cwe.raise_for_status()

    nvd_payload = nvd.json()
    assert nvd_payload["totalResults"] >= 1
    assert nvd_payload["vulnerabilities"][0]["cve"]["id"] == "CVE-2021-44228"
    assert cwe.headers["content-type"].lower() in {
        "application/zip",
        "application/octet-stream",
        "application/x-zip-compressed",
    } or cwe.content.startswith(b"PK")
