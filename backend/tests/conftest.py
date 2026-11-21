"""Shared test configuration and isolated application fixtures."""

import asyncio
import os
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import httpx
import pytest
from alembic.config import Config
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from alembic import command

os.environ["DATABASE_URL"] = "sqlite:///./tests.db"
os.environ["JWT_SECRET"] = "test-only-signing-key-with-at-least-32-bytes"
os.environ["ENVIRONMENT"] = "test"

from app.api.dependencies import get_db
from app.main import app

BACKEND_ROOT = Path(__file__).resolve().parents[1]


class ApiClient:
    """Synchronous request helper using HTTPX's ASGI transport."""

    def __init__(self) -> None:
        self.transport = httpx.ASGITransport(app=app)

    def request(self, method: str, path: str, **kwargs: Any) -> httpx.Response:
        async def send() -> httpx.Response:
            async with httpx.AsyncClient(
                transport=self.transport,
                base_url="http://testserver",
            ) as client:
                return await client.request(method, path, **kwargs)

        return asyncio.run(send())

    def get(self, path: str, **kwargs: Any) -> httpx.Response:
        return self.request("GET", path, **kwargs)

    def post(self, path: str, **kwargs: Any) -> httpx.Response:
        return self.request("POST", path, **kwargs)

    def patch(self, path: str, **kwargs: Any) -> httpx.Response:
        return self.request("PATCH", path, **kwargs)

    def delete(self, path: str, **kwargs: Any) -> httpx.Response:
        return self.request("DELETE", path, **kwargs)


@pytest.fixture
def api_client(tmp_path: Path) -> Iterator[tuple[ApiClient, sessionmaker[Session]]]:
    """Run HTTP requests against a temporary database migrated to the current head."""
    database_path = tmp_path / "api-integration.db"
    database_url = f"sqlite:///{database_path}"
    migration_config = Config(str(BACKEND_ROOT / "alembic.ini"))
    migration_config.attributes["database_url"] = database_url
    command.upgrade(migration_config, "head")

    engine = create_engine(database_url, connect_args={"check_same_thread": False})
    session_factory = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)

    def override_get_db() -> Iterator[Session]:
        session = session_factory()
        try:
            yield session
        finally:
            session.close()

    app.dependency_overrides[get_db] = override_get_db
    yield ApiClient(), session_factory
    app.dependency_overrides.clear()
    engine.dispose()
