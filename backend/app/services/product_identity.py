"""Deterministic ecosystem-aware software identity and version handling."""

import re
from dataclasses import dataclass

from packaging.version import InvalidVersion, Version


@dataclass(frozen=True, slots=True)
class ParsedPurl:
    ecosystem: str
    name: str
    version: str | None


def normalize_ecosystem(value: str) -> str:
    normalized = re.sub(r"[^a-z0-9]+", "_", value.strip().casefold()).strip("_")
    aliases = {
        "npm": "npm",
        "node": "npm",
        "pypi": "pypi",
        "python": "pypi",
        "maven": "maven",
        "nuget": "nuget",
        "golang": "go",
        "go": "go",
        "rust": "cargo",
        "crates_io": "cargo",
        "cargo": "cargo",
        "debian": "debian",
        "alpine": "alpine",
        "apk": "alpine",
        "rpm": "rpm",
    }
    return aliases.get(normalized, normalized)


def canonical_product_name(ecosystem: str, name: str) -> str:
    normalized = name.strip()
    ecosystem = normalize_ecosystem(ecosystem)
    if ecosystem == "pypi":
        return re.sub(r"[-_.]+", "-", normalized).casefold()
    if ecosystem in {"npm", "maven", "nuget"}:
        return normalized.casefold()
    return normalized.casefold()


def parse_purl(purl: str) -> ParsedPurl | None:
    if not purl.startswith("pkg:"):
        return None
    try:
        body = purl[4:].partition("?")[0].split("#", 1)[0]
        type_name, _, remainder = body.partition("/")
        if not type_name or not remainder:
            return None
        name = remainder if type_name.casefold() == "maven" else remainder.rsplit("/", 1)[-1]
        version = None
        if "@" in name:
            name, version = name.rsplit("@", 1)
        ecosystem = normalize_ecosystem(type_name)
        return ParsedPurl(
            ecosystem=ecosystem,
            name=canonical_product_name(ecosystem, name),
            version=version,
        )
    except (AttributeError, ValueError):
        return None


def parse_cpe(cpe: str) -> dict[str, str] | None:
    if not cpe.startswith("cpe:2.3:"):
        return None
    parts = cpe.split(":")
    if len(parts) < 12:
        return None
    return {
        "part": parts[2],
        "vendor": parts[3],
        "product": parts[4],
        "version": parts[5],
        "edition": parts[6],
        "language": parts[7],
        "sw_edition": parts[8],
        "target_sw": parts[9],
        "target_hw": parts[10],
        "other": parts[11],
    }


def compare_versions(ecosystem: str, left: str, right: str) -> int:
    """Compare two versions deterministically for the supplied ecosystem."""
    ecosystem = normalize_ecosystem(ecosystem)
    if ecosystem == "pypi":
        try:
            a, b = Version(left), Version(right)
            return (a > b) - (a < b)
        except InvalidVersion:
            pass
    if ecosystem in {"npm", "nuget", "maven", "go", "cargo"}:

        def numeric_key(value: str) -> tuple[int, tuple[int, ...], int, str]:
            cleaned = value.strip().lstrip("vV")
            match = re.match(r"^(\d+(?:\.\d+)*)(?:[-+](.*))?$", cleaned)
            if not match:
                return (1, (), 1, cleaned.casefold())
            numbers = tuple(int(item) for item in match.group(1).split("."))
            suffix = match.group(2)
            return (0, numbers, 0 if suffix else 1, suffix or "")

        a, b = numeric_key(left), numeric_key(right)
        if a < b:
            return -1
        if a > b:
            return 1
        return 0
    tokens_a = re.split(r"([0-9]+)", left)
    tokens_b = re.split(r"([0-9]+)", right)
    for token_a, token_b in zip(tokens_a, tokens_b, strict=False):
        if token_a == token_b:
            continue
        if token_a.isdigit() and token_b.isdigit():
            return (int(token_a) > int(token_b)) - (int(token_a) < int(token_b))
        return (token_a.casefold() > token_b.casefold()) - (token_a.casefold() < token_b.casefold())
    return (len(tokens_a) > len(tokens_b)) - (len(tokens_a) < len(tokens_b))


def version_in_osv_range(
    ecosystem: str,
    version: str,
    ranges: list[dict],
) -> bool | None:
    """Evaluate OSV ECOSYSTEM range events; None means no usable range."""
    evaluated = False
    for range_item in ranges:
        if range_item.get("type") not in {"ECOSYSTEM", "SEMVER"}:
            continue
        events = range_item.get("events", [])
        if not isinstance(events, list) or not events:
            continue
        introduced = False
        upper: str | None = None
        upper_kind: str | None = None
        for event in events:
            if not isinstance(event, dict):
                continue
            if "introduced" in event:
                introduced = (
                    event["introduced"] == "0"
                    or compare_versions(ecosystem, version, str(event["introduced"])) >= 0
                )
            if "fixed" in event:
                upper = str(event["fixed"])
                upper_kind = "fixed"
            if "last_affected" in event:
                upper = str(event["last_affected"])
                upper_kind = "last"
            if "limit" in event:
                limit = str(event["limit"])
                if compare_versions(ecosystem, version, limit) >= 0:
                    introduced = False
        if introduced:
            if upper is None:
                return True
            if upper_kind == "fixed":
                return compare_versions(ecosystem, version, upper) < 0
            if upper_kind == "last":
                return compare_versions(ecosystem, version, upper) <= 0
        evaluated = True
    return None if not evaluated else False
