"""Integration tests for persisted tenant-scoped deterministic risk history."""

from conftest import ApiClient
from sqlalchemy import select
from sqlalchemy.orm import sessionmaker

from app.db.models import CveRecord, RiskHistory


def register_owner(client: ApiClient) -> dict:
    response = client.post(
        "/api/v1/auth/register",
        json={
            "organization_name": "Risk Org",
            "display_name": "Risk Owner",
            "email": "owner@risk.example",
            "password": "Risk owner password 2026!",
        },
    )
    assert response.status_code == 201
    return response.json()


def headers(auth: dict) -> dict[str, str]:
    return {"Authorization": f"Bearer {auth['access_token']}"}


def test_risk_calculation_persists_history_and_missing_signals(
    api_client: tuple[ApiClient, sessionmaker],
) -> None:
    client, session_factory = api_client
    owner = register_owner(client)
    asset_response = client.post(
        "/api/v1/assets",
        headers=headers(owner),
        json={
            "name": "Risk Asset",
            "asset_type": "server",
            "criticality": "high",
            "internet_exposed": True,
            "ransomware_indicator": False,
        },
    )
    assert asset_response.status_code == 201
    asset_id = asset_response.json()["id"]

    risk_response = client.post(
        f"/api/v1/assets/{asset_id}/risk",
        headers=headers(owner),
        json={
            "cvss": 10,
            "epss": 0.8,
            "kev": True,
        },
    )
    assert risk_response.status_code == 200, risk_response.text
    risk = risk_response.json()
    assert 0 <= risk["score"] <= 100
    assert risk["risk_band"] in {"low", "medium", "high", "critical"}
    assert "asset_criticality" not in risk["missing_signals"]
    assert "internet_exposure" not in risk["missing_signals"]
    assert len(risk["factors"]) == 6

    history_response = client.get(
        f"/api/v1/assets/{asset_id}/risk/history",
        headers=headers(owner),
    )
    assert history_response.status_code == 200
    assert len(history_response.json()) == 1

    with session_factory() as session:
        histories = list(session.scalars(select(RiskHistory)))
        assert len(histories) == 1
        assert histories[0].asset_id.hex == asset_id.replace("-", "")
        assert histories[0].risk_band == risk["risk_band"]


def test_risk_history_is_hidden_from_other_tenants(
    api_client: tuple[ApiClient, sessionmaker],
) -> None:
    client, _ = api_client
    owner_a = register_owner(client)
    asset = client.post(
        "/api/v1/assets",
        headers=headers(owner_a),
        json={
            "name": "Tenant A Risk",
            "asset_type": "server",
            "criticality": "medium",
        },
    ).json()
    client.post(
        f"/api/v1/assets/{asset['id']}/risk",
        headers=headers(owner_a),
        json={"cvss": 7},
    )
    owner_b = client.post(
        "/api/v1/auth/register",
        json={
            "organization_name": "Second Risk Org",
            "display_name": "Second Risk Owner",
            "email": "owner@second-risk.example",
            "password": "Second risk password 2026!",
        },
    ).json()

    foreign_history = client.get(
        f"/api/v1/assets/{asset['id']}/risk/history",
        headers=headers(owner_b),
    )

    assert foreign_history.status_code == 404


def test_vulnerability_signals_are_used_when_cve_id_is_supplied(
    api_client: tuple[ApiClient, sessionmaker],
) -> None:
    client, session_factory = api_client
    owner = register_owner(client)
    asset = client.post(
        "/api/v1/assets",
        headers=headers(owner),
        json={
            "name": "CVE Risk Asset",
            "asset_type": "server",
            "criticality": "critical",
        },
    ).json()

    with session_factory() as session:
        session.add(
            CveRecord(
                cve_id="CVE-2026-4242",
                description="Integration risk signal fixture",
                cvss={
                    "cvssData": {
                        "baseScore": 9.8,
                    }
                },
                cwe_ids=[],
                references=[],
                affected=[],
                source_ids=["nvd"],
            )
        )
        session.commit()

    response = client.post(
        f"/api/v1/assets/{asset['id']}/risk",
        headers=headers(owner),
        json={"vulnerability_id": "CVE-2026-4242"},
    )

    assert response.status_code == 200
    cvss_factor = next(factor for factor in response.json()["factors"] if factor["name"] == "cvss")
    assert cvss_factor["raw_value"] == 9.8
