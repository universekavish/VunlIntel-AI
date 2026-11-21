"""Tests for strict CSV and SBOM JSON import parsers."""

import pytest

from app.ingestion.csv_assets import MAX_CSV_BYTES, parse_asset_csv
from app.ingestion.sbom import parse_cyclonedx, parse_spdx


def test_csv_import_merges_duplicate_external_assets_and_tracks_bad_rows() -> None:
    content = (
        b"name,asset_type,external_id,hostname,criticality,software_name,"
        b"software_version,ecosystem,cpe,purl\n"
        b"Server 1,server,SRV-1,server1,high,OpenSSL,3.0.1,rpm,,\n"
        b"Server 1,server,SRV-1,server1,high,Python,Django,3.0,pypi,,\n"
        b",server,SRV-2,,,Missing,1.0,unknown,,\n"
    )

    assets, invalid = parse_asset_csv(content)

    assert len(assets) == 1
    assert len(assets[0].software) == 2
    assert len(invalid) == 1
    assert invalid[0]["row"] == "4"


def test_csv_import_rejects_missing_headers_and_oversize() -> None:
    with pytest.raises(ValueError, match="missing required headers"):
        parse_asset_csv(b"hostname,criticality\nhost,high\n")
    with pytest.raises(ValueError, match="exceeds"):
        parse_asset_csv(b"x" * (MAX_CSV_BYTES + 1))


def test_cyclonedx_parser_extracts_components_and_identifiers() -> None:
    payload = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "components": [
            {
                "name": "log4j-core",
                "version": "2.14.1",
                "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
                "cpe": ["cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*"],
            },
            {"name": "missing-version"},
        ],
    }

    components = parse_cyclonedx(payload)

    assert len(components) == 1
    assert components[0].ecosystem == "maven"
    assert components[0].purl.startswith("pkg:maven/")


def test_cyclonedx_parser_rejects_wrong_format() -> None:
    with pytest.raises(ValueError, match="CycloneDX"):
        parse_cyclonedx({"bomFormat": "SPDX"})


def test_spdx_parser_deduplicates_and_supports_external_refs() -> None:
    payload = {
        "spdxVersion": "SPDX-2.3",
        "packages": [
            {
                "name": "Django",
                "versionInfo": "4.2.1",
                "externalRefs": [
                    {
                        "referenceCategory": "PACKAGE-MANAGER",
                        "referenceLocator": "pkg:pypi/Django@4.2.1",
                    }
                ],
            },
            {
                "name": "Django",
                "versionInfo": "4.2.1",
                "externalRefs": [],
            },
        ],
    }

    components = parse_spdx(payload)

    assert len(components) == 1
    assert components[0].ecosystem == "pypi"


def test_spdx_parser_rejects_wrong_format() -> None:
    with pytest.raises(ValueError, match="SPDX"):
        parse_spdx({"bomFormat": "CycloneDX"})
