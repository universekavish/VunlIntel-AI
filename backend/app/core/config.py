"""Validated environment configuration."""

from functools import lru_cache
from pathlib import Path
from typing import Self

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

BACKEND_ROOT = Path(__file__).resolve().parents[2]
REPOSITORY_ROOT = (
    BACKEND_ROOT.parent if (BACKEND_ROOT.parent / ".env.example").is_file() else BACKEND_ROOT
)
LOCAL_DEVELOPMENT_SECRET = "local-only-change-this-secret-before-deploying-7b09ac492f82487d"


class Settings(BaseSettings):
    """Application settings loaded from environment variables and the root .env file."""

    model_config = SettingsConfigDict(
        env_file=REPOSITORY_ROOT / ".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    database_url: str
    jwt_secret: SecretStr
    jwt_issuer: str = "vulnintel-ai"
    jwt_audience: str = "vulnintel-api"
    access_token_ttl_minutes: int = 30
    environment: str = "development"
    cors_origins: list[str] = Field(default_factory=list)
    nvd_api_key: SecretStr | None = None
    nvd_api_url: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    cisa_kev_url: str = (
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    )
    epss_api_url: str = "https://api.first.org/data/v1/epss"
    epss_daily_url: str = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
    osv_api_url: str = "https://api.osv.dev"
    cwe_download_url: str = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"
    rag_embedding_model: str = "sentence-transformers/all-MiniLM-L6-v2"
    rag_embedding_dimensions: int = 384
    rag_vectorstore_collection: str = "vulnintel"
    rag_embedding_provider: str = "sentence_transformer"
    qdrant_url: str = "http://qdrant:6333"
    vulnintel_ml_enabled: bool = False
    vulnintel_ml_base_model: str | None = None
    vulnintel_ml_adapter_path: str | None = None

    @field_validator("access_token_ttl_minutes")
    @classmethod
    def validate_token_lifetime(cls, value: int) -> int:
        if not 1 <= value <= 1440:
            raise ValueError("Access-token lifetime must be between 1 and 1440 minutes")
        return value

    @model_validator(mode="after")
    def validate_security_settings(self) -> Self:
        secret = self.jwt_secret.get_secret_value()
        if len(secret.encode("utf-8")) < 32:
            raise ValueError("JWT_SECRET must contain at least 32 bytes")
        if self.environment.casefold() not in {"development", "test"}:
            if secret == LOCAL_DEVELOPMENT_SECRET:
                raise ValueError(
                    "The local development JWT_SECRET cannot be used outside development"
                )
        return self


@lru_cache
def get_settings() -> Settings:
    """Return one validated settings instance per process."""
    return Settings()
