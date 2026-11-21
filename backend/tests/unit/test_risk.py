"""Comprehensive boundary tests for the pure deterministic risk engine."""

import pytest

from app.services.risk import (
    DEFAULT_THRESHOLDS,
    RiskInputs,
    RiskThresholds,
    RiskWeights,
    calculate_risk,
    risk_band,
)


def test_all_maximum_signals_score_100() -> None:
    result = calculate_risk(
        RiskInputs(
            cvss=10,
            epss=1,
            kev=True,
            asset_criticality="critical",
            internet_exposure=True,
            ransomware=True,
        )
    )

    assert result.score == 100
    assert result.risk_band == "critical"
    assert result.confidence == 100
    assert result.missing_signals == ()
    assert abs(sum(item.contribution for item in result.factors) - 100) < 1e-6


def test_all_zero_or_false_signals_score_zero() -> None:
    result = calculate_risk(
        RiskInputs(
            cvss=0,
            epss=0,
            kev=False,
            asset_criticality="low",
            internet_exposure=False,
            ransomware=False,
        )
    )

    assert result.score == 3.75
    assert result.risk_band == "low"
    assert result.confidence == 100
    assert not result.missing_signals


@pytest.mark.parametrize(
    ("cvss", "epss", "expected"),
    [
        (0, 0, 0),
        (5, 0.5, 50),
        (10, 1, 100),
    ],
)
def test_cvss_epss_formula_boundaries(
    cvss: float,
    epss: float,
    expected: float,
) -> None:
    result = calculate_risk(
        RiskInputs(
            cvss=cvss,
            epss=epss,
        )
    )

    assert abs(result.score - expected) < 1e-6


@pytest.mark.parametrize(
    ("criticality", "normalized"),
    [
        ("low", 25),
        ("medium", 50),
        ("high", 75),
        ("critical", 100),
    ],
)
def test_asset_criticality_boundaries(
    criticality: str,
    normalized: float,
) -> None:
    result = calculate_risk(
        RiskInputs(
            cvss=None,
            epss=None,
            kev=None,
            asset_criticality=criticality,
            internet_exposure=None,
            ransomware=None,
        )
    )
    factor = next(item for item in result.factors if item.name == "asset_criticality")

    assert factor.normalized_value == normalized
    assert result.score == normalized
    assert len(result.missing_signals) == 5
    assert result.confidence == 15


def test_missing_signals_are_explicit_and_do_not_become_zero() -> None:
    result = calculate_risk(
        RiskInputs(
            cvss=10,
            epss=None,
            kev=True,
            asset_criticality=None,
            internet_exposure=True,
            ransomware=None,
        )
    )

    assert result.missing_signals == (
        "epss",
        "asset_criticality",
        "ransomware",
    )
    assert result.confidence == 55
    missing = [factor for factor in result.factors if factor.status == "missing"]
    assert {factor.name for factor in missing} == set(result.missing_signals)
    assert all(factor.contribution == 0 for factor in missing)
    assert "Missing signals: epss, asset_criticality, ransomware." in result.explanation


def test_all_missing_signals_return_zero_with_explicit_confidence() -> None:
    result = calculate_risk(RiskInputs())

    assert result.score == 0
    assert result.confidence == 0
    assert len(result.missing_signals) == 6
    assert all(factor.status == "missing" for factor in result.factors)
    assert "Available signal weight 0.00%" in result.explanation


@pytest.mark.parametrize(
    ("score", "band"),
    [
        (0, "low"),
        (25, "low"),
        (25.01, "medium"),
        (50, "medium"),
        (50.01, "high"),
        (75, "high"),
        (75.01, "critical"),
        (100, "critical"),
    ],
)
def test_threshold_boundaries_are_inclusive(
    score: float,
    band: str,
) -> None:
    assert risk_band(score, DEFAULT_THRESHOLDS) == band


def test_custom_thresholds_change_bands_without_changing_formula() -> None:
    thresholds = RiskThresholds(low=10, medium=40, high=70)
    result = calculate_risk(
        RiskInputs(cvss=5, epss=0.5),
        thresholds=thresholds,
    )

    assert result.score == 50
    assert result.risk_band == "high"
    assert result.thresholds == thresholds


def test_custom_weights_are_supported_when_they_total_100() -> None:
    weights = RiskWeights(
        cvss=50,
        epss=10,
        kev=10,
        asset_criticality=10,
        internet_exposure=10,
        ransomware=10,
    )
    result = calculate_risk(
        RiskInputs(cvss=10, epss=1),
        weights=weights,
    )

    assert result.score == 100
    assert result.weights == weights


@pytest.mark.parametrize(
    ("weights", "message"),
    [
        (
            {
                "cvss": 99,
                "epss": 2,
                "kev": 0,
                "asset_criticality": 0,
                "internet_exposure": 0,
                "ransomware": 0,
            },
            "total",
        ),
        (
            {
                "cvss": 101,
                "epss": 0,
                "kev": 0,
                "asset_criticality": 0,
                "internet_exposure": -1,
                "ransomware": 0,
            },
            "percentages",
        ),
    ],
)
def test_invalid_weights_are_rejected(
    weights: dict[str, float],
    message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        RiskWeights(**weights)


@pytest.mark.parametrize(
    ("low", "medium", "high"),
    [
        (50, 50, 75),
        (0, 80, 79),
        (-1, 50, 75),
    ],
)
def test_invalid_thresholds_are_rejected(
    low: float,
    medium: float,
    high: float,
) -> None:
    with pytest.raises(ValueError, match="thresholds"):
        calculate_risk(
            RiskInputs(),
            thresholds=RiskThresholds(low=low, medium=medium, high=high),
        )


@pytest.mark.parametrize(
    ("inputs", "message"),
    [
        (RiskInputs(cvss=-0.01), "CVSS"),
        (RiskInputs(cvss=10.01), "CVSS"),
        (RiskInputs(epss=-0.01), "EPSS"),
        (RiskInputs(epss=1.01), "EPSS"),
        (RiskInputs(asset_criticality="unknown"), "criticality"),
    ],
)
def test_invalid_signals_are_rejected(
    inputs: RiskInputs,
    message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        calculate_risk(inputs)


def test_factor_contributions_are_independently_readable() -> None:
    result = calculate_risk(
        RiskInputs(
            cvss=10,
            epss=0.5,
            kev=True,
            asset_criticality="high",
            internet_exposure=True,
            ransomware=False,
        )
    )

    factor_map = {factor.name: factor for factor in result.factors}
    assert factor_map["cvss"].weight == 25
    assert factor_map["cvss"].effective_weight == 25
    assert factor_map["cvss"].normalized_value == 100
    assert factor_map["epss"].normalized_value == 50
    assert factor_map["kev"].raw_value is True
    assert factor_map["ransomware"].normalized_value == 0
    assert abs(sum(factor.contribution for factor in result.factors) - result.score) < 1e-6
