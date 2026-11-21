"""HTTP integration tests for tenant identity, RBAC, and isolation."""

from uuid import UUID, uuid4

import pytest
from conftest import ApiClient
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker

from app.db.models import AuditEvent, Organization, User


def register(
    client: ApiClient,
    *,
    organization: str = "Northwind Security",
    email: str = "owner@northwind.example",
) -> dict[str, object]:
    response = client.post(
        "/api/v1/auth/register",
        json={
            "organization_name": organization,
            "display_name": "Tenant Owner",
            "email": email,
            "password": "Secure test password 2026!",
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


def auth_headers(auth_response: dict[str, object]) -> dict[str, str]:
    return {"Authorization": f"Bearer {auth_response['access_token']}"}


def test_register_login_and_profile_round_trip(
    api_client: tuple[ApiClient, sessionmaker],
) -> None:
    client, session_factory = api_client
    registration = register(client, email="OWNER@northwind.example")

    assert registration["user"]["role"] == "owner"
    assert registration["user"]["email"] == "owner@northwind.example"
    assert registration["organization"]["slug"] == "northwind-security"
    assert "password_hash" not in registration["user"]

    profile = client.get("/api/v1/auth/me", headers=auth_headers(registration))
    assert profile.status_code == 200
    assert profile.json()["id"] == registration["user"]["id"]
    assert client.get("/health/ready").status_code == 200

    with session_factory() as session:
        stored_user = session.get(User, UUID(registration["user"]["id"]))
        assert stored_user is not None
        assert stored_user.password_hash.startswith("$argon2")
        assert stored_user.password_hash != "Secure test password 2026!"

    login_response = client.post(
        "/api/v1/auth/login",
        json={
            "email": "owner@northwind.example",
            "password": "Secure test password 2026!",
        },
    )
    assert login_response.status_code == 200
    assert login_response.json()["user"]["id"] == registration["user"]["id"]


def test_invalid_login_does_not_disclose_account_existence(
    api_client: tuple[ApiClient, sessionmaker],
) -> None:
    client, _ = api_client
    register(client)
    existing = client.post(
        "/api/v1/auth/login",
        json={"email": "owner@northwind.example", "password": "not the password"},
    )
    unknown = client.post(
        "/api/v1/auth/login",
        json={"email": "missing@northwind.example", "password": "not the password"},
    )

    assert existing.status_code == unknown.status_code == 401
    assert existing.json() == unknown.json() == {"detail": "Invalid email or password"}


def test_registration_conflicts_are_generic(
    api_client: tuple[ApiClient, sessionmaker],
) -> None:
    client, _ = api_client
    register(client)

    duplicate_email = client.post(
        "/api/v1/auth/register",
        json={
            "organization_name": "A Different Organization",
            "display_name": "Second Owner",
            "email": "owner@northwind.example",
            "password": "Another secure password 2026!",
        },
    )
    duplicate_slug = client.post(
        "/api/v1/auth/register",
        json={
            "organization_name": "Northwind Security",
            "display_name": "Another Owner",
            "email": "another@northwind.example",
            "password": "Another secure password 2026!",
        },
    )

    assert duplicate_email.status_code == duplicate_slug.status_code == 409
    assert duplicate_email.json() == duplicate_slug.json()


def test_database_rejects_a_second_owner_in_one_organization(
    api_client: tuple[ApiClient, sessionmaker],
) -> None:
    _, session_factory = api_client
    with session_factory() as session:
        organization = Organization(
            id=uuid4(),
            name="Single Owner Org",
            slug="single-owner-org",
        )
        session.add(organization)
        session.flush()
        session.add_all(
            [
                User(
                    id=uuid4(),
                    organization_id=organization.id,
                    email="owner1@single-owner.example",
                    display_name="Owner One",
                    password_hash="not-used-in-this-test",
                    role="owner",
                    is_active=True,
                ),
                User(
                    id=uuid4(),
                    organization_id=organization.id,
                    email="owner2@single-owner.example",
                    display_name="Owner Two",
                    password_hash="not-used-in-this-test",
                    role="owner",
                    is_active=True,
                ),
            ]
        )

        with pytest.raises(IntegrityError):
            session.flush()
        session.rollback()


def test_membership_is_tenant_scoped_and_cross_tenant_ids_are_hidden(
    api_client: tuple[ApiClient, sessionmaker],
) -> None:
    client, _ = api_client
    tenant_a = register(client)
    tenant_b = register(
        client,
        organization="Contoso Defense",
        email="owner@contoso.example",
    )
    created = client.post(
        "/api/v1/organizations/current/members",
        headers=auth_headers(tenant_a),
        json={
            "display_name": "Northwind Analyst",
            "email": "analyst@northwind.example",
            "password": "Analyst secure password 2026!",
            "role": "analyst",
        },
    )
    assert created.status_code == 201, created.text

    tenant_b_members = client.get(
        "/api/v1/organizations/current/members",
        headers=auth_headers(tenant_b),
    )
    foreign_lookup = client.delete(
        f"/api/v1/organizations/current/members/{created.json()['id']}",
        headers=auth_headers(tenant_b),
    )

    assert tenant_b_members.status_code == 200
    assert {member["email"] for member in tenant_b_members.json()["members"]} == {
        "owner@contoso.example"
    }
    assert foreign_lookup.status_code == 404


def test_rbac_and_owner_role_protection(
    api_client: tuple[ApiClient, sessionmaker],
) -> None:
    client, _ = api_client
    owner = register(client)
    admin = client.post(
        "/api/v1/organizations/current/members",
        headers=auth_headers(owner),
        json={
            "display_name": "Tenant Admin",
            "email": "admin@northwind.example",
            "password": "Admin secure password 2026!",
            "role": "admin",
        },
    )
    viewer = client.post(
        "/api/v1/organizations/current/members",
        headers=auth_headers(owner),
        json={
            "display_name": "Tenant Viewer",
            "email": "viewer@northwind.example",
            "password": "Viewer secure password 2026!",
            "role": "viewer",
        },
    )
    assert admin.status_code == viewer.status_code == 201

    admin_login = client.post(
        "/api/v1/auth/login",
        json={
            "email": "admin@northwind.example",
            "password": "Admin secure password 2026!",
        },
    ).json()
    viewer_login = client.post(
        "/api/v1/auth/login",
        json={
            "email": "viewer@northwind.example",
            "password": "Viewer secure password 2026!",
        },
    ).json()
    forbidden_admin_create = client.post(
        "/api/v1/organizations/current/members",
        headers=auth_headers(admin_login),
        json={
            "display_name": "Another Admin",
            "email": "admin2@northwind.example",
            "password": "Second admin password 2026!",
            "role": "admin",
        },
    )
    forbidden_viewer_create = client.post(
        "/api/v1/organizations/current/members",
        headers=auth_headers(viewer_login),
        json={
            "display_name": "Unauthorized",
            "email": "unauthorized@northwind.example",
            "password": "Unauthorized password 2026!",
            "role": "viewer",
        },
    )
    forbidden_role_change = client.patch(
        f"/api/v1/organizations/current/members/{viewer.json()['id']}/role",
        headers=auth_headers(admin_login),
        json={"role": "analyst"},
    )

    assert forbidden_admin_create.status_code == 403
    assert forbidden_viewer_create.status_code == 403
    assert forbidden_role_change.status_code == 403


def test_deactivated_user_token_is_immediately_rejected(
    api_client: tuple[ApiClient, sessionmaker],
) -> None:
    client, _ = api_client
    owner = register(client)
    member = client.post(
        "/api/v1/organizations/current/members",
        headers=auth_headers(owner),
        json={
            "display_name": "To Be Deactivated",
            "email": "inactive@northwind.example",
            "password": "Inactive user password 2026!",
            "role": "viewer",
        },
    )
    member_auth = client.post(
        "/api/v1/auth/login",
        json={
            "email": "inactive@northwind.example",
            "password": "Inactive user password 2026!",
        },
    ).json()

    deactivated = client.delete(
        f"/api/v1/organizations/current/members/{member.json()['id']}",
        headers=auth_headers(owner),
    )
    stale_token = client.get("/api/v1/auth/me", headers=auth_headers(member_auth))
    new_login = client.post(
        "/api/v1/auth/login",
        json={
            "email": "inactive@northwind.example",
            "password": "Inactive user password 2026!",
        },
    )

    assert deactivated.status_code == 204
    assert stale_token.status_code == 401
    assert new_login.status_code == 401


def test_authorization_uses_current_database_role_not_token_role(
    api_client: tuple[ApiClient, sessionmaker],
) -> None:
    client, _ = api_client
    owner = register(client)
    viewer = client.post(
        "/api/v1/organizations/current/members",
        headers=auth_headers(owner),
        json={
            "display_name": "Promoted Viewer",
            "email": "promoted@northwind.example",
            "password": "Promoted user password 2026!",
            "role": "viewer",
        },
    ).json()
    viewer_token = client.post(
        "/api/v1/auth/login",
        json={
            "email": "promoted@northwind.example",
            "password": "Promoted user password 2026!",
        },
    ).json()

    changed = client.patch(
        f"/api/v1/organizations/current/members/{viewer['id']}/role",
        headers=auth_headers(owner),
        json={"role": "admin"},
    )
    member_list = client.get(
        "/api/v1/organizations/current/members",
        headers=auth_headers(viewer_token),
    )

    assert changed.status_code == 200
    assert changed.json()["role"] == "admin"
    assert member_list.status_code == 200


def test_authentication_and_membership_actions_are_audited(
    api_client: tuple[ApiClient, sessionmaker],
) -> None:
    client, session_factory = api_client
    owner = register(client)
    member = client.post(
        "/api/v1/organizations/current/members",
        headers=auth_headers(owner),
        json={
            "display_name": "Audited Member",
            "email": "audited@northwind.example",
            "password": "Audited member password 2026!",
            "role": "viewer",
        },
    ).json()
    client.patch(
        f"/api/v1/organizations/current/members/{member['id']}/role",
        headers=auth_headers(owner),
        json={"role": "analyst"},
    )
    client.delete(
        f"/api/v1/organizations/current/members/{member['id']}",
        headers=auth_headers(owner),
    )
    client.post(
        "/api/v1/auth/login",
        json={
            "email": "owner@northwind.example",
            "password": "Secure test password 2026!",
        },
    )
    with session_factory() as session:
        audit = list(session.scalars(select(AuditEvent).order_by(AuditEvent.action)))

    actions = [event.action for event in audit]
    assert actions == [
        "auth.login_succeeded",
        "organization.member_created",
        "organization.member_deactivated",
        "organization.member_role_changed",
        "organization.registered",
    ]
    assert all("password" not in event.details for event in audit)
