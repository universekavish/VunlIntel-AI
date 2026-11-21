"""Validated CycloneDX and SPDX JSON/SBOM software extraction."""

from dataclasses import dataclass

from app.services.product_identity import normalize_ecosystem, parse_purl


@dataclass(frozen=True, slots=True)
class SbomComponent:
    name: str
    ecosystem: str
    version: str
    cpe: str | None
    purl: str | None


def _component_identity(component: dict) -> SbomComponent | None:
    name = component.get("name")
    version = component.get("version")
    if not isinstance(name, str) or not name.strip():
        return None
    if not isinstance(version, str) or not version.strip():
        return None
    purl = component.get("purl")
    if not isinstance(purl, str):
        purl = None
    parsed = parse_purl(purl) if purl else None
    ecosystem = parsed.ecosystem if parsed else "unknown"
    cpe = None
    cpes = component.get("cpe")
    if isinstance(cpes, list) and cpes:
        cpe = cpes[0] if isinstance(cpes[0], str) else None
    elif isinstance(cpes, str):
        cpe = cpes
    return SbomComponent(
        name=name.strip(),
        ecosystem=ecosystem,
        version=version.strip(),
        cpe=cpe,
        purl=purl,
    )


def parse_cyclonedx(payload: object) -> list[SbomComponent]:
    if not isinstance(payload, dict):
        raise ValueError("CycloneDX document must be a JSON object")
    if payload.get("bomFormat") != "CycloneDX":
        raise ValueError("JSON document is not identified as CycloneDX")
    components = payload.get("components")
    if not isinstance(components, list):
        raise ValueError("CycloneDX components must be a JSON array")
    parsed: list[SbomComponent] = []
    for component in components:
        if not isinstance(component, dict):
            continue
        identity = _component_identity(component)
        if identity:
            parsed.append(identity)
    return parsed


def parse_spdx(payload: object) -> list[SbomComponent]:
    if not isinstance(payload, dict):
        raise ValueError("SPDX document must be a JSON object")
    spdx_version = payload.get("spdxVersion")
    if not isinstance(spdx_version, str) or not spdx_version.startswith("SPDX-"):
        raise ValueError("JSON document is not identified as SPDX")
    packages = payload.get("packages")
    if not isinstance(packages, list):
        raise ValueError("SPDX packages must be a JSON array")
    parsed: list[SbomComponent] = []
    for package in packages:
        if not isinstance(package, dict):
            continue
        name = package.get("name")
        version = package.get("versionInfo")
        if not isinstance(name, str) or not isinstance(version, str):
            continue
        purl = None
        for reference in package.get("externalRefs", []):
            if (
                isinstance(reference, dict)
                and reference.get("referenceCategory") == "PACKAGE-MANAGER"
            ):
                locator = reference.get("referenceLocator")
                if isinstance(locator, str) and locator.startswith("pkg:"):
                    purl = locator
                    break
        cpe = None
        for reference in package.get("externalRefs", []):
            if isinstance(reference, dict) and reference.get("referenceType") == "cpe23Type":
                locator = reference.get("referenceLocator")
                if isinstance(locator, str):
                    cpe = locator
                    break
        parsed_purl = parse_purl(purl) if purl else None
        parsed.append(
            SbomComponent(
                name=name.strip(),
                ecosystem=parsed_purl.ecosystem if parsed_purl else "unknown",
                version=version.strip(),
                cpe=cpe,
                purl=purl,
            )
        )
    return deduplicate_components(parsed)


def deduplicate_components(components: list[SbomComponent]) -> list[SbomComponent]:
    unique: dict[tuple[str, str, str], SbomComponent] = {}
    for component in components:
        duplicate_without_ecosystem = False
        if component.ecosystem == "unknown":
            for (_, existing_name, existing_version), _ in list(unique.items()):
                if (
                    existing_name == component.name.casefold()
                    and existing_version == component.version
                ):
                    duplicate_without_ecosystem = True
                    break
        if duplicate_without_ecosystem:
            continue
        key = (
            normalize_ecosystem(component.ecosystem),
            component.name.casefold(),
            component.version,
        )
        unique.setdefault(key, component)
    return list(unique.values())
