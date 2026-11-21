"""Edge-case tests for normalization, ecosystem versions, and range matching."""

import pytest

from app.services.product_identity import (
    canonical_product_name,
    compare_versions,
    parse_cpe,
    parse_purl,
    version_in_osv_range,
)
from app.services.vulnerability_matching import cpe_identity_matches


@pytest.mark.parametrize(
    ("ecosystem", "name", "expected"),
    [
        ("PyPI", "Django_REST-Framework", "django-rest-framework"),
        ("npm", "lodash", "lodash"),
        ("Maven", "Org.Example:Widget", "org.example:widget"),
        ("RPM", "OpenSSL", "openssl"),
    ],
)
def test_canonical_product_names(ecosystem: str, name: str, expected: str) -> None:
    assert canonical_product_name(ecosystem, name) == expected


def test_package_url_parsing() -> None:
    purl = parse_purl("pkg:maven/org.apache.commons/commons-lang3@3.14.0")

    assert purl is not None
    assert purl.ecosystem == "maven"
    assert purl.name == "org.apache.commons/commons-lang3"
    assert purl.version == "3.14.0"


def test_cpe_23_parsing() -> None:
    cpe = parse_cpe("cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*")

    assert cpe is not None
    assert cpe["vendor"] == "apache"
    assert cpe["product"] == "log4j"
    assert cpe["version"] == "*"


@pytest.mark.parametrize(
    ("ecosystem", "left", "right", "expected"),
    [
        ("pypi", "1.2.0", "1.10.0", -1),
        ("pypi", "2.0rc1", "2.0", -1),
        ("npm", "1.0.0", "1.0.0", 0),
        ("npm", "1.2.0-beta", "1.2.0", -1),
        ("debian", "1:1.2-3", "1:1.10-1", -1),
        ("generic", "2024.10", "2024.2", 1),
    ],
)
def test_ecosystem_version_comparison(
    ecosystem: str,
    left: str,
    right: str,
    expected: int,
) -> None:
    assert compare_versions(ecosystem, left, right) == expected


@pytest.mark.parametrize(
    ("version", "expected"),
    [
        ("1.0.0", True),
        ("1.4.9", True),
        ("1.5.0", False),
        ("0.9.9", False),
    ],
)
def test_osv_semver_range_is_exclusive_at_fixed(
    version: str,
    expected: bool,
) -> None:
    result = version_in_osv_range(
        "npm",
        version,
        [
            {
                "type": "SEMVER",
                "events": [
                    {"introduced": "1.0.0"},
                    {"fixed": "1.5.0"},
                ],
            }
        ],
    )
    assert result is expected


def test_osv_last_affected_is_inclusive() -> None:
    assert (
        version_in_osv_range(
            "generic",
            "2.0",
            [
                {
                    "type": "ECOSYSTEM",
                    "events": [
                        {"introduced": "1.0"},
                        {"last_affected": "2.0"},
                    ],
                }
            ],
        )
        is True
    )


def test_missing_range_returns_none_for_review() -> None:
    assert version_in_osv_range("generic", "1.0", []) is None


def test_wildcard_cpe_identity_matches_vendor_and_product() -> None:
    assert cpe_identity_matches(
        "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*",
        "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*",
    )
    assert not cpe_identity_matches(
        "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*",
        "cpe:2.3:a:eclipse:jetty:*:*:*:*:*:*:*",
    )
