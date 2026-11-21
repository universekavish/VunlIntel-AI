"""Cross-surface end-to-end API tests through the ASGI application."""

from conftest import ApiClient
from sqlalchemy.orm import sessionmaker


def register(client: ApiClient, organization: str, email: str) -> dict:
    response = client.post(
        "/api/v1/auth/register",
        json={
            "organization_name": organization,
            "display_name": "E2E Owner",
            "email": email,
            "password": "E2E secure password 2026!",
        },
    )
    assert response.status_code == 201
    return response.json()


def headers(auth: dict) -> dict[str, str]:
    return {"Authorization": f"Bearer {auth['access_token']}"}


def test_e2e_auth_asset_risk_history_flow(
    api_client: tuple[ApiClient, sessionmaker],
) -> None:
    client, _ = api_client
    auth = register(client, "E2E Alpha", "owner@e2e-alpha.example")

    asset_response = client.post(
        "/api/v1/assets",
        headers=headers(auth),
        json={
            "name": "E2E Web Gateway",
            "asset_type": "gateway",
            "hostname": "gateway.e2e.example",
            "environment": "production",
            "criticality": "high",
            "internet_exposed": True,
            "ransomware_indicator": False,
        },
    )
    assert asset_response.status_code == 201
    asset_id = asset_response.json()["id"]

    risk_response = client.post(
        f"/api/v1/assets/{asset_id}/risk",
        headers=headers(auth),
        json={"cvss": 9.8, "epss": 0.75, "kev": True},
    )
    assert risk_response.status_code == 200
    assert risk_response.json()["score"] >= 0
    assert len(risk_response.json()["factors"]) == 6

    history_response = client.get(
        f"/api/v1/assets/{asset_id}/risk/history",
        headers=headers(auth),
    )
    assert history_response.status_code == 200
    assert len(history_response.json()) >= 1


def test_e2e_cross_tenant_asset_investigation_is_rejected(
    api_client: tuple[ApiClient, sessionmaker],
) -> None:
    client, _ = api_client
    tenant_a = register(client, "E2E Tenant A", "owner@tenant-a.example")
    asset_response = client.post(
        "/api/v1/assets",
        headers=headers(tenant_a),
        json={
            "name": "Tenant A Private Asset",
            "asset_type": "server",
            "criticality": "critical",
        },
    )
    assert asset_response.status_code == 201
    foreign_asset_id = asset_response.json()["id"]

    tenant_b = register(client, "E2E Tenant B", "owner@tenant-b.example")
    investigation_response = client.post(
        "/api/v1/investigations",
        headers=headers(tenant_b),
        json={
            "asset_id": foreign_asset_id,
            "cve_id": "CVE-2026-0001",
            "query": "Investigate this entity",
        },
    )

    assert investigation_response.status_code == 404
    assert investigation_response.json()["detail"] == "Asset not found"


def test_e2e_request_id_is_returned(
    api_client: tuple[ApiClient, sessionmaker],
) -> None:
    client, _ = api_client
    response = client.get(
        "/health/live",
        headers={"x-request-id": "phase9-e2e-request"},
    )

    assert response.status_code == 200
    assert response.headers["x-request-id"] == "phase9-e2e-request"
