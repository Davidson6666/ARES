"""Administração do Core: usuários, papéis (leitura) e permissões (ADR 0008)."""

import uuid
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from typing import Any, cast

import pytest
from fastapi.testclient import TestClient
from httpx import Response
from sqlalchemy import Engine, select, text
from sqlalchemy.orm import Session as DbSession

from app.auth.dependencies import CSRF_HEADER
from app.auth.models import Permission, Role, RolePermission, User, UserRole
from app.main import create_app
from tests.test_auth import PASSWORD, _settings, login, login_admin, make_user

pytestmark = pytest.mark.db


@pytest.fixture
def client(app_engine: Engine) -> Iterator[TestClient]:
    with TestClient(create_app(_settings(), engine=app_engine), base_url="https://testserver") as c:
        yield c


def anon(client: TestClient) -> TestClient:
    return TestClient(client.app, base_url="https://testserver")


def admin(client: TestClient, engine: Engine) -> dict[str, str]:
    me = login_admin(client, engine, "root@ares.test")
    return {CSRF_HEADER: str(me["csrf_token"])}


def custom_role(engine: Engine, name: str, permissions: list[str]) -> None:
    with DbSession(engine) as db:
        role = Role(id=uuid.uuid4(), name=name, description="", is_system=False)
        db.add(role)
        db.flush()
        for perm in permissions:
            perm_id = db.scalar(select(Permission.id).where(Permission.name == perm))
            db.add(RolePermission(role_id=role.id, permission_id=perm_id))
        db.commit()


def user_with(
    engine: Engine, email: str, permissions: list[str], tenant: str | None = None
) -> uuid.UUID:
    """Usuário sem MFA com um papel personalizado que dá só as permissões pedidas."""
    role = f"r-{uuid.uuid4().hex[:8]}"
    custom_role(engine, role, permissions)
    uid = make_user(engine, email, roles=(role,))
    if tenant is not None:
        with engine.begin() as conn:
            conn.execute(
                text("UPDATE users SET tenant_id = :t WHERE id = :i"), {"t": tenant, "i": uid}
            )
    return uid


def acting_as(client: TestClient, email: str) -> tuple[TestClient, dict[str, str]]:
    c = anon(client)
    me = login(c, email)
    return c, {CSRF_HEADER: str(me["csrf_token"])}


def post_user(
    c: TestClient, headers: dict[str, str], key: str = "k-1", **overrides: Any
) -> Response:
    body = {"email": "Nova@Ares.Test", "display_name": "Nova"} | overrides
    return cast(
        Response, c.post("/api/v1/users", json=body, headers={**headers, "Idempotency-Key": key})
    )


# --- leitura ---------------------------------------------------------------------------


def test_list_users_requires_permission_and_never_leaks_secrets(
    client: TestClient, admin_engine: Engine
) -> None:
    make_user(admin_engine, "viewer@ares.test", roles=("viewer",))
    viewer, _ = acting_as(client, "viewer@ares.test")
    assert viewer.get("/api/v1/users").status_code == 403
    assert anon(client).get("/api/v1/users").status_code == 401

    admin(client, admin_engine)
    r = client.get("/api/v1/users")
    assert r.status_code == 200 and r.headers["cache-control"] == "no-store"
    text_ = r.text.lower()
    assert "password" not in text_ and "secret" not in text_ and "token" not in text_
    emails = {u["email"] for u in r.json()["items"]}
    assert emails == {"root@ares.test", "viewer@ares.test"}
    root = next(u for u in r.json()["items"] if u["email"] == "root@ares.test")
    assert root["roles"] == ["super_admin"]


def test_cursor_pagination_has_no_gaps_or_repeats(client: TestClient, admin_engine: Engine) -> None:
    for i in range(6):
        make_user(admin_engine, f"u{i}@ares.test", roles=("viewer",))
    admin(client, admin_engine)
    seen: list[str] = []
    cursor: str | None = None
    pages = 0
    while True:
        url = "/api/v1/users?limit=2" + (f"&cursor={cursor}" if cursor else "")
        body = client.get(url).json()
        assert len(body["items"]) <= 2
        seen += [u["email"] for u in body["items"]]
        pages += 1
        cursor = body["next_cursor"]
        if cursor is None:
            break
    assert pages == 4 and len(seen) == len(set(seen)) == 7


@pytest.mark.parametrize("cursor", ["x", "e30", "WyJhIl0", "!!!", "W10"])
def test_malformed_cursor_is_400(client: TestClient, admin_engine: Engine, cursor: str) -> None:
    admin(client, admin_engine)
    assert client.get(f"/api/v1/users?cursor={cursor}").status_code == 400


def test_limit_bounds_and_unknown_query(client: TestClient, admin_engine: Engine) -> None:
    admin(client, admin_engine)
    assert client.get("/api/v1/users?limit=0").status_code == 422
    assert client.get("/api/v1/users?limit=201").status_code == 422
    assert client.get("/api/v1/users?limit=200").status_code == 200
    assert client.get("/api/v1/users?foo=1").status_code == 400


def test_scoped_user_sees_only_their_tenant_idor(client: TestClient, admin_engine: Engine) -> None:
    """9.2, IDOR: escopo A não lê nem altera usuário do escopo B (404)."""
    user_with(admin_engine, "a@ares.test", ["users.read", "users.write"], tenant="A")
    b = make_user(admin_engine, "b@ares.test", roles=("viewer",))
    same = make_user(admin_engine, "a2@ares.test", roles=("viewer",))
    with admin_engine.begin() as conn:
        conn.execute(text("UPDATE users SET tenant_id = 'B' WHERE id = :i"), {"i": b})
        conn.execute(text("UPDATE users SET tenant_id = 'A' WHERE id = :i"), {"i": same})
    c, headers = acting_as(client, "a@ares.test")
    emails = {u["email"] for u in c.get("/api/v1/users").json()["items"]}
    assert emails == {"a@ares.test", "a2@ares.test"}
    other = c.patch(f"/api/v1/users/{b}", json={"display_name": "x"}, headers=headers)
    mine = c.patch(f"/api/v1/users/{same}", json={"display_name": "ok"}, headers=headers)
    missing = c.patch(f"/api/v1/users/{uuid.uuid4()}", json={"display_name": "x"}, headers=headers)
    assert other.status_code == 404 and other.json()["code"] == "not_found"
    assert missing.status_code == 404 and missing.json()["message"] == other.json()["message"]
    assert mine.status_code == 200 and mine.json()["display_name"] == "ok"


# --- criação ---------------------------------------------------------------------------


def test_create_user_returns_setup_token_once_and_onboarding_works(
    client: TestClient, admin_engine: Engine
) -> None:
    headers = admin(client, admin_engine)
    r = post_user(client, headers)
    assert r.status_code == 201 and r.headers["cache-control"] == "no-store"
    body = r.json()
    assert body["email"] == "nova@ares.test" and body["roles"] == [] and body["replayed"] is False
    token = body["setup_token"]
    assert token and "password" not in r.text.lower()
    expires = datetime.fromisoformat(body["setup_expires_at"])
    assert timedelta(hours=23) < expires - datetime.now(UTC) <= timedelta(hours=24)

    # No banco: só o hash do token, e a senha não é utilizável.
    with admin_engine.connect() as conn:
        assert token not in str(conn.execute(text("SELECT token_hash FROM recovery_tokens")).all())
        stored = conn.execute(
            text("SELECT password_hash FROM users WHERE email = 'nova@ares.test'")
        ).scalar_one()
    assert not stored.startswith("$argon2")
    for guess in ("!", PASSWORD, "qualquer senha longa o bastante"):
        r = anon(client).post(
            "/api/v1/auth/login", json={"email": "nova@ares.test", "password": guess}
        )
        assert r.status_code == 401

    # O novo usuário define a senha com o token (uso único) e entra.
    c = anon(client)
    ok = c.post(
        "/api/v1/auth/recovery/confirm",
        json={"token": token, "new_password": "uma senha bem longa 1"},
    )
    assert ok.status_code == 200
    again = c.post(
        "/api/v1/auth/recovery/confirm",
        json={"token": token, "new_password": "outra senha bem longa 2"},
    )
    assert again.status_code == 401
    assert login(c, "nova@ares.test", "uma senha bem longa 1")["email"] == "nova@ares.test"


def test_create_user_idempotency_replays_without_the_token(
    client: TestClient, admin_engine: Engine
) -> None:
    headers = admin(client, admin_engine)
    first = post_user(client, headers)
    again = post_user(client, headers)
    assert again.status_code == 201 and again.headers["Idempotent-Replay"] == "true"
    assert again.json()["setup_token"] is None and again.json()["replayed"] is True
    assert again.json()["id"] == first.json()["id"]
    different = post_user(client, headers, display_name="Outro nome")
    assert different.status_code == 409
    no_key = client.post(
        "/api/v1/users", json={"email": "z@ares.test", "display_name": "Z"}, headers=headers
    )
    assert no_key.status_code == 400 and no_key.json()["code"] == "idempotency_key_required"


def test_create_user_validation_and_duplicates(client: TestClient, admin_engine: Engine) -> None:
    headers = admin(client, admin_engine)
    assert post_user(client, headers, key="a").status_code == 201
    dup = post_user(client, headers, key="b", email="NOVA@ares.test")
    assert dup.status_code == 409 and dup.json()["code"] == "email_in_use"
    bad_bodies: list[dict[str, Any]] = [
        {"email": "sem-arroba"},
        {"email": "a b@ares.test"},
        {"email": "a@" + "x" * 300},
        {"email": "x@ares.test\n"},
        {"display_name": ""},
        {"display_name": "linha\nfalsa"},
        {"roles": ["super_admin"]},  # atribuição em massa
        {"status": "active"},
        {"password": "uma senha bem longa 1"},
        {"is_system": True},
    ]
    for i, bad in enumerate(bad_bodies):
        r = post_user(client, headers, key=f"bad{i}", **bad)
        assert r.status_code == 422, (bad, r.text)
    # Nada disso criou usuário.
    with admin_engine.connect() as conn:
        count = conn.execute(text("SELECT count(*) FROM users")).scalar_one()
    assert count == 2  # o admin e "nova"


def test_create_user_needs_write_permission_and_csrf(
    client: TestClient, admin_engine: Engine
) -> None:
    user_with(admin_engine, "reader@ares.test", ["users.read"])
    c, headers = acting_as(client, "reader@ares.test")
    assert post_user(c, headers).status_code == 403
    user_with(admin_engine, "writer@ares.test", ["users.write"])
    w, whead = acting_as(client, "writer@ares.test")
    no_csrf = w.post(
        "/api/v1/users",
        json={"email": "q@ares.test", "display_name": "Q"},
        headers={"Idempotency-Key": "k"},
    )
    assert no_csrf.status_code == 403 and no_csrf.json()["code"] == "csrf_failed"
    assert post_user(w, whead).status_code == 201


def test_scoped_admin_creates_only_inside_their_tenant(
    client: TestClient, admin_engine: Engine
) -> None:
    user_with(admin_engine, "t@ares.test", ["users.write", "users.read"], tenant="A")
    c, headers = acting_as(client, "t@ares.test")
    assert post_user(c, headers, key="1", email="x@ares.test", tenant_id="B").status_code == 403
    inherited = post_user(c, headers, key="2", email="y@ares.test")
    assert inherited.status_code == 201 and inherited.json()["tenant_id"] == "A"
    explicit = post_user(c, headers, key="3", email="z@ares.test", tenant_id="A")
    assert explicit.status_code == 201


def test_create_user_is_audited_without_secrets(client: TestClient, admin_engine: Engine) -> None:
    headers = admin(client, admin_engine)
    r = post_user(client, headers)
    with admin_engine.connect() as conn:
        rows = conn.execute(
            text(
                "SELECT action, resource_id, details::text FROM audit_logs "
                "WHERE action = 'user.created'"
            )
        ).all()
    assert len(rows) == 1 and rows[0][1] == r.json()["id"]
    assert r.json()["setup_token"] not in str(rows) and "nova@" not in str(rows)


# --- PATCH -----------------------------------------------------------------------------


def test_patch_user_rejects_mass_assignment(client: TestClient, admin_engine: Engine) -> None:
    """9.2, atribuição em massa: PATCH /users/{id} com `roles` → 422."""
    headers = admin(client, admin_engine)
    target = make_user(admin_engine, "t@ares.test", roles=("viewer",))
    url = f"/api/v1/users/{target}"
    for bad in (
        {"roles": ["super_admin"]},
        {"status": "disabled"},
        {"email": "outro@ares.test"},
        {"password_hash": "x"},
        {"id": str(uuid.uuid4())},
        {"display_name": "ok", "roles": ["super_admin"]},
        {},
        {"display_name": ""},
        {"display_name": "a\nb"},
    ):
        r = client.patch(url, json=bad, headers=headers)
        assert r.status_code == 422, (bad, r.text)
    with admin_engine.connect() as conn:
        row = conn.execute(
            text("SELECT display_name, status FROM users WHERE id = :i"), {"i": target}
        ).one()
        roles = conn.execute(
            text(
                "SELECT r.name FROM user_roles ur JOIN roles r ON r.id = ur.role_id "
                "WHERE ur.user_id = :i"
            ),
            {"i": target},
        ).all()
    assert row == ("t", "active") and [r[0] for r in roles] == ["viewer"]


def test_patch_user_changes_name_audits_fields_only(
    client: TestClient, admin_engine: Engine
) -> None:
    headers = admin(client, admin_engine)
    target = make_user(admin_engine, "t@ares.test", roles=("viewer",))
    r = client.patch(f"/api/v1/users/{target}", json={"display_name": "Nome Novo"}, headers=headers)
    assert r.status_code == 200 and r.json()["display_name"] == "Nome Novo"
    assert r.json()["roles"] == ["viewer"]
    with admin_engine.connect() as conn:
        details = conn.execute(
            text("SELECT details::text FROM audit_logs WHERE action = 'user.updated'")
        ).scalar_one()
    assert "display_name" in details and "Nome Novo" not in details
    no_csrf = client.patch(f"/api/v1/users/{target}", json={"display_name": "x"})
    assert no_csrf.status_code == 403


def test_scoped_admin_cannot_move_users_between_tenants(
    client: TestClient, admin_engine: Engine
) -> None:
    user_with(admin_engine, "s@ares.test", ["users.write"], tenant="A")
    target = make_user(admin_engine, "m@ares.test", roles=("viewer",))
    with admin_engine.begin() as conn:
        conn.execute(text("UPDATE users SET tenant_id = 'A' WHERE id = :i"), {"i": target})
    c, headers = acting_as(client, "s@ares.test")
    r = c.patch(f"/api/v1/users/{target}", json={"tenant_id": "B"}, headers=headers)
    assert r.status_code == 403
    with admin_engine.connect() as conn:
        tenant = conn.execute(text("SELECT tenant_id FROM users WHERE id = :i"), {"i": target})
        assert tenant.scalar_one() == "A"


# --- papéis e permissões (leitura) -----------------------------------------------------


def test_roles_and_permissions_listing(client: TestClient, admin_engine: Engine) -> None:
    user_with(admin_engine, "rd@ares.test", ["users.read"])
    reader, _ = acting_as(client, "rd@ares.test")
    roles = reader.get("/api/v1/roles")
    assert roles.status_code == 200 and roles.headers["cache-control"] == "no-store"
    names = {r["name"] for r in roles.json()["items"]}
    assert {"super_admin", "security_admin", "security_analyst", "auditor", "viewer"} <= names
    sa = next(r for r in roles.json()["items"] if r["name"] == "super_admin")
    assert sa["is_system"] is True and "roles.manage" in sa["permissions"]
    # users.read lê papéis, mas o catálogo de permissões é só de roles.manage.
    assert reader.get("/api/v1/permissions").status_code == 403
    make_user(admin_engine, "v@ares.test", roles=("viewer",))
    viewer, _ = acting_as(client, "v@ares.test")
    assert viewer.get("/api/v1/roles").status_code == 403

    admin(client, admin_engine)
    perms = client.get("/api/v1/permissions")
    assert perms.status_code == 200
    assert {p["name"] for p in perms.json()["items"]} >= {"users.read", "roles.manage"}


def test_roles_and_permissions_paginate(client: TestClient, admin_engine: Engine) -> None:
    admin(client, admin_engine)
    for path, expected in (("/api/v1/roles", 6), ("/api/v1/permissions", 15)):
        seen: list[str] = []
        cursor: str | None = None
        while True:
            url = f"{path}?limit=4" + (f"&cursor={cursor}" if cursor else "")
            body = client.get(url).json()
            seen += [i["name"] for i in body["items"]]
            cursor = body["next_cursor"]
            if cursor is None:
                break
        assert len(seen) == len(set(seen)) >= expected - 1
        assert seen == sorted(seen)
    assert client.get("/api/v1/roles?cursor=abc").status_code == 400


def test_permissions_listing_matches_database(client: TestClient, admin_engine: Engine) -> None:
    admin(client, admin_engine)
    with DbSession(admin_engine) as db:
        expected = set(db.scalars(select(Permission.name)))
        users = db.scalar(select(User).where(User.email == "root@ares.test"))
        assert users is not None and db.scalars(select(UserRole.role_id)).first() is not None
    got = {p["name"] for p in client.get("/api/v1/permissions?limit=200").json()["items"]}
    assert got == expected
