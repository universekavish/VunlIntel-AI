"""Pydantic contracts for assets and software inventory."""

from enum import StrEnum
from typing import Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, field_validator


class AssetCriticality(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class SoftwareCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    ecosystem: str = Field(min_length=1, max_length=64)
    version: str = Field(min_length=1, max_length=255)
    cpe: str | None = Field(default=None, max_length=1024)
    purl: str | None = Field(default=None, max_length=1024)


class AssetCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    asset_type: str = Field(min_length=1, max_length=64)
    hostname: str | None = Field(default=None, max_length=255)
    environment: str | None = Field(default=None, max_length=64)
    criticality: AssetCriticality = AssetCriticality.MEDIUM
    external_id: str | None = Field(default=None, max_length=255)
    internet_exposed: bool | None = None
    ransomware_indicator: bool | None = None
    software: list[SoftwareCreate] = Field(default_factory=list)

    @field_validator("name", "asset_type")
    @classmethod
    def strip_required(cls, value: str) -> str:
        stripped = value.strip()
        if not stripped:
            raise ValueError("Required text cannot be blank")
        return stripped


class AssetUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=255)
    asset_type: str | None = Field(default=None, min_length=1, max_length=64)
    hostname: str | None = Field(default=None, max_length=255)
    environment: str | None = Field(default=None, max_length=64)
    criticality: AssetCriticality | None = None
    external_id: str | None = Field(default=None, max_length=255)
    active: bool | None = None
    internet_exposed: bool | None = None
    ransomware_indicator: bool | None = None


class AssetRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: UUID
    organization_id: UUID
    name: str
    asset_type: str
    hostname: str | None
    environment: str | None
    criticality: str
    external_id: str | None
    active: bool
    internet_exposed: bool | None
    ransomware_indicator: bool | None


class ImportResult(BaseModel):
    import_format: Literal["csv", "cyclonedx", "spdx"]
    assets_created: int
    assets_updated: int
    software_created: int
    software_skipped: int
    invalid_rows: list[dict[str, str]]
