"""Tenant-scoped asset CRUD and import integration tests."""

from conftest import ApiClient
from sqlalchemy.orm import sessionmaker


def register_owner(client: ApiClient) -> dict:
    response = client.post(
        "/api/v1/auth/register",
        json={
            "organization_name": "Asset Org",
            "display_name": "Asset Owner",
            "email": "owner@asset.example",
            "password": "Asset owner password 2026!",
        },
    )
    assert response.status_code == 201
    return response.json()


def headers(auth: dict) -> dict[str, str]:
    return {"Authorization": f"Bearer {auth['access_token']}"}


def test_asset_crud_is_tenant_scoped(
    api_client: tuple[ApiClient, sessionmaker],
) -> None:
    client, _ = api_client
    owner = register_owner(client)
    created = client.post(
        "/api/v1/assets",
        headers=headers(owner),
        json={
            "name": "Production Server",
            "asset_type": "server",
            "hostname": "prod-1.example",
            "environment": "production",
            "criticality": "critical",
            "external_id": "srv-001",
            "software": [
                {
                    "name": "OpenSSL",
                    "ecosystem": "rpm",
                    "version": "3.0.12",
                    "purl": "pkg:rpm/redhat/openssl@3.0.12",
                }
            ],
        },
    )
    assert created.status_code == 201, created.text
    asset_id = created.json()["id"]

    listed = client.get("/api/v1/assets", headers=headers(owner))
    assert listed.status_code == 200
    assert listed.json()[0]["name"] == "Production Server"

    patched = client.patch(
        f"/api/v1/assets/{asset_id}",
        headers=headers(owner),
        json={"criticality": "high", "environment": "staging"},
    )
    assert patched.status_code == 200
    assert patched.json()["criticality"] == "high"

    deleted = client.delete(
        f"/api/v1/assets/{asset_id}",
        headers=headers(owner),
    )
    assert deleted.status_code == 204


def test_csv_import_validates_headers_and_returns_counts(
    api_client: tuple[ApiClient, sessionmaker],
) -> None:
    client, _ = api_client
    owner = register_owner(client)
    csv_text = (
        "name,asset_type,external_id,software_name,software_version,ecosystem,purl\n"
        "Laptop,endpoint,LAP-1,Django,4.2.1,pypi,pkg:pypi/Django@4.2.1\n"
        "Laptop,endpoint,LAP-1,Requests,2.31.0,pypi,pkg:pypi/requests@2.31.0\n"
        ",server,,OpenSSL,3.0.0,rpm,\n"
    )

    response = client.post(
        "/api/v1/assets/imports/csv",
        headers=headers(owner),
        files={"file": ("assets.csv", csv_text.encode(), "text/csv")},
    )

    assert response.status_code == 200, response.text
    assert response.json()["assets_created"] == 1
    assert response.json()["software_created"] == 2
    assert len(response.json()["invalid_rows"]) == 1


def test_cyclonedx_import_rejects_wrong_format(
    api_client: tuple[ApiClient, sessionmaker],
) -> None:
    client, _ = api_client
    owner = register_owner(client)

    response = client.post(
        "/api/v1/assets/imports/sbom?format=cyclonedx",
        headers=headers(owner),
        files={
            "file": (
                "wrong.json",
                b'{"bomFormat":"SPDX","packages":[]}',
                "application/json",
            )
        },
    )

    assert response.status_code == 422


def test_cross_tenant_asset_lookup_is_hidden(
    api_client: tuple[ApiClient, sessionmaker],
) -> None:
    client, _ = api_client
    owner_a = register_owner(client)
    created = client.post(
        "/api/v1/assets",
        headers=headers(owner_a),
        json={
            "name": "Tenant A Asset",
            "asset_type": "server",
            "external_id": "tenant-a",
        },
    )
    asset_id = created.json()["id"]

    owner_b = client.post(
        "/api/v1/auth/register",
        json={
            "organization_name": "Second Asset Org",
            "display_name": "Second Owner",
            "email": "owner@second-asset.example",
            "password": "Second asset password 2026!",
        },
    ).json()

    foreign = client.get(
        f"/api/v1/assets/{asset_id}",
        headers=headers(owner_b),
    )
    assert foreign.status_code == 404
