"""Tests for the API process liveness contract."""

import asyncio

import httpx

from app.main import app


def test_liveness_reports_serving_process() -> None:
    async def get_liveness() -> httpx.Response:
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(
            transport=transport,
            base_url="http://testserver",
        ) as client:
            return await client.get("/health/live")

    response = asyncio.run(get_liveness())

    assert response.status_code == 200
    assert response.json() == {"status": "live"}
