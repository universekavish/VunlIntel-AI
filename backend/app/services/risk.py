"""Pure, deterministic contextual vulnerability risk calculation."""

from dataclasses import asdict, dataclass
from typing import Literal

RiskBand = Literal["low", "medium", "high", "critical"]


@dataclass(frozen=True, slots=True)
class RiskWeights:
    cvss: float = 25.0
    epss: float = 25.0
    kev: float = 20.0
    asset_criticality: float = 15.0
    internet_exposure: float = 10.0
    ransomware: float = 5.0

    def __post_init__(self) -> None:
        values = asdict(self)
        if any(value < 0 or not 0 <= value <= 100 for value in values.values()):
            raise ValueError("Risk weights must be percentages between 0 and 100")
        if abs(sum(values.values()) - 100.0) > 1e-9:
            raise ValueError("Risk weights must total 100")


DEFAULT_WEIGHTS = RiskWeights()


@dataclass(frozen=True, slots=True)
class RiskThresholds:
    low: float = 25.0
    medium: float = 50.0
    high: float = 75.0

    def __post_init__(self) -> None:
        if not 0 <= self.low < self.medium < self.high <= 100:
            raise ValueError("Risk thresholds must satisfy 0 <= low < medium < high <= 100")


DEFAULT_THRESHOLDS = RiskThresholds()


@dataclass(frozen=True, slots=True)
class RiskInputs:
    cvss: float | None = None
    epss: float | None = None
    kev: bool | None = None
    asset_criticality: str | None = None
    internet_exposure: bool | None = None
    ransomware: bool | None = None


@dataclass(frozen=True, slots=True)
class FactorContribution:
    name: str
    weight: float
    effective_weight: float
    raw_value: object | None
    normalized_value: float | None
    contribution: float
    status: Literal["available", "missing"]
    explanation: str


@dataclass(frozen=True, slots=True)
class RiskResult:
    score: float
    risk_band: RiskBand
    confidence: float
    missing_signals: tuple[str, ...]
    factors: tuple[FactorContribution, ...]
    explanation: str
    thresholds: RiskThresholds
    weights: RiskWeights


CRITICALITY_NORMALIZED = {
    "low": 25.0,
    "medium": 50.0,
    "high": 75.0,
    "critical": 100.0,
}


def risk_band(score: float, thresholds: RiskThresholds) -> RiskBand:
    if score <= thresholds.low:
        return "low"
    if score <= thresholds.medium:
        return "medium"
    if score <= thresholds.high:
        return "high"
    return "critical"


def calculate_risk(
    inputs: RiskInputs,
    *,
    weights: RiskWeights = DEFAULT_WEIGHTS,
    thresholds: RiskThresholds = DEFAULT_THRESHOLDS,
) -> RiskResult:
    """Calculate a 0-100 score solely from validated deterministic inputs."""
    if inputs.cvss is not None and not 0 <= inputs.cvss <= 10:
        raise ValueError("CVSS must be between 0 and 10")
    if inputs.epss is not None and not 0 <= inputs.epss <= 1:
        raise ValueError("EPSS must be between 0 and 1")
    if (
        inputs.asset_criticality is not None
        and inputs.asset_criticality.casefold() not in CRITICALITY_NORMALIZED
    ):
        raise ValueError("Asset criticality must be low, medium, high, or critical")

    raw: dict[str, object | None] = {
        "cvss": inputs.cvss,
        "epss": inputs.epss,
        "kev": inputs.kev,
        "asset_criticality": inputs.asset_criticality,
        "internet_exposure": inputs.internet_exposure,
        "ransomware": inputs.ransomware,
    }
    normalized: dict[str, float | None] = {
        "cvss": None if inputs.cvss is None else round(inputs.cvss * 10.0, 6),
        "epss": None if inputs.epss is None else round(inputs.epss * 100.0, 6),
        "kev": None if inputs.kev is None else (100.0 if inputs.kev else 0.0),
        "asset_criticality": (
            None
            if inputs.asset_criticality is None
            else CRITICALITY_NORMALIZED[inputs.asset_criticality.casefold()]
        ),
        "internet_exposure": (
            None
            if inputs.internet_exposure is None
            else (100.0 if inputs.internet_exposure else 0.0)
        ),
        "ransomware": (
            None if inputs.ransomware is None else (100.0 if inputs.ransomware else 0.0)
        ),
    }
    weight_map = {
        "cvss": weights.cvss,
        "epss": weights.epss,
        "kev": weights.kev,
        "asset_criticality": weights.asset_criticality,
        "internet_exposure": weights.internet_exposure,
        "ransomware": weights.ransomware,
    }
    available_names = tuple(name for name, value in normalized.items() if value is not None)
    available_weight = sum(weight_map[name] for name in available_names)
    confidence = round(available_weight, 6)

    factors: list[FactorContribution] = []
    weighted_total = 0.0
    for name in weight_map:
        value = normalized[name]
        original_weight = weight_map[name]
        if value is None:
            explanation = f"{name} is missing; it contributes no unverified value"
            factors.append(
                FactorContribution(
                    name=name,
                    weight=original_weight,
                    effective_weight=0.0,
                    raw_value=None,
                    normalized_value=None,
                    contribution=0.0,
                    status="missing",
                    explanation=explanation,
                )
            )
            continue
        effective_weight = (
            original_weight * 100.0 / available_weight if available_weight > 0 else 0.0
        )
        contribution = value * effective_weight / 100.0
        weighted_total += contribution
        factors.append(
            FactorContribution(
                name=name,
                weight=original_weight,
                effective_weight=round(effective_weight, 6),
                raw_value=raw[name],
                normalized_value=value,
                contribution=round(contribution, 6),
                status="available",
                explanation=_available_explanation(name, raw[name], value),
            )
        )

    score = round(max(0.0, min(100.0, weighted_total)), 2)
    missing = tuple(name for name in weight_map if normalized[name] is None)
    band = risk_band(score, thresholds)
    missing_text = (
        "Missing signals: " + ", ".join(missing) + ". "
        if missing
        else "No risk signals are missing. "
    )
    explanation = (
        f"Deterministic weighted score {score:.2f}/100 ({band}). "
        f"{missing_text}"
        f"Available signal weight {confidence:.2f}%."
    )
    return RiskResult(
        score=score,
        risk_band=band,
        confidence=confidence,
        missing_signals=missing,
        factors=tuple(factors),
        explanation=explanation,
        thresholds=thresholds,
        weights=weights,
    )


def _available_explanation(
    name: str,
    raw_value: object | None,
    normalized_value: float,
) -> str:
    if name == "cvss":
        return f"CVSS {raw_value} normalized to {normalized_value:.2f}/100"
    if name == "epss":
        return f"EPSS {raw_value} normalized to {normalized_value:.2f}/100"
    if name == "kev":
        return "CISA KEV indicator is present" if raw_value else "CISA KEV indicator is absent"
    if name == "asset_criticality":
        return f"Asset criticality {raw_value} normalized to {normalized_value:.2f}/100"
    if name == "internet_exposure":
        return (
            "Asset is internet exposed"
            if raw_value
            else "Asset is not recorded as internet exposed"
        )
    return "Ransomware indicator is present" if raw_value else "Ransomware indicator is absent"
