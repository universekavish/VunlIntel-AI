"""Pydantic contracts for deterministic risk calculations and history."""

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, model_validator


class RiskWeightsRead(BaseModel):
    cvss: float = 25.0
    epss: float = 25.0
    kev: float = 20.0
    asset_criticality: float = 15.0
    internet_exposure: float = 10.0
    ransomware: float = 5.0

    @model_validator(mode="after")
    def validate_total(self) -> "RiskWeightsRead":
        values = (
            self.cvss,
            self.epss,
            self.kev,
            self.asset_criticality,
            self.internet_exposure,
            self.ransomware,
        )
        if any(value < 0 or value > 100 for value in values):
            raise ValueError("Risk weights must be between 0 and 100")
        if abs(sum(values) - 100.0) > 1e-9:
            raise ValueError("Risk weights must total 100")
        return self


class RiskThresholdsRead(BaseModel):
    low: float = 25.0
    medium: float = 50.0
    high: float = 75.0

    @model_validator(mode="after")
    def validate_order(self) -> "RiskThresholdsRead":
        if not 0 <= self.low < self.medium < self.high <= 100:
            raise ValueError("Thresholds must satisfy 0 <= low < medium < high <= 100")
        return self


class RiskCalculateRequest(BaseModel):
    vulnerability_id: str | None = Field(default=None, max_length=255)
    cvss: float | None = Field(default=None, ge=0, le=10)
    epss: float | None = Field(default=None, ge=0, le=1)
    kev: bool | None = None
    internet_exposure: bool | None = None
    ransomware: bool | None = None
    weights: RiskWeightsRead | None = None
    thresholds: RiskThresholdsRead | None = None


class RiskFactorRead(BaseModel):
    name: str
    weight: float
    effective_weight: float
    raw_value: object | None
    normalized_value: float | None
    contribution: float
    status: Literal["available", "missing"]
    explanation: str


class RiskResultRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID | None = None
    asset_id: UUID
    vulnerability_id: str | None = None
    score: float
    risk_band: Literal["low", "medium", "high", "critical"]
    confidence: float
    missing_signals: list[str]
    factors: list[RiskFactorRead]
    explanation: str
    thresholds: dict[str, float]
    calculated_at: datetime | None = None
