"""Papéis, escalada de privilégio, último administrador, desativação, reset de MFA e
sessões (ADR 0008)."""

import threading
import uuid
from collections.abc import Iterator
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, text

from app import cli
from app.auth.dependencies import CSRF_HEADER
from app.main import create_app
from tests.test_admin_users import acting_as, admin, anon, custom_role, post_user, user_with
from tests.test_auth import PASSWORD, _settings, add_factor, login_admin, login_mfa, make_user

pytestmark = pytest.mark.db


@pytest.fixture
def client(app_engine: Engine) -> Iterator[TestClient]:
    with TestClient(create_app(_settings(), engine=app_engine), base_url="https://testserver") as c:
        yield c


def admin_count(engine: Engine) -> int:
    with engine.connect() as conn:
        return int(
            conn.execute(
                text(
                    "SELECT count(DISTINCT u.id) FROM users u "
                    "JOIN user_roles ur ON ur.user_id = u.id "
                    "JOIN role_permissions rp ON rp.role_id = ur.role_id "
                    "JOIN permissions p ON p.id = rp.permission_id "
                    "WHERE u.status = 'active' AND p.name = 'roles.manage'"
                )
            ).scalar_one()
        )


def role_id(engine: Engine, name: str) -> str:
    with engine.connect() as conn:
        return str(
            conn.execute(text("SELECT id FROM roles WHERE name = :n"), {"n": name}).scalar_one()
        )


def roles_of(engine: Engine, user_id: Any) -> list[str]:
    with engine.connect() as conn:
        return sorted(
            r[0]
            for r in conn.execute(
                text(
                    "SELECT r.name FROM user_roles ur JOIN roles r ON r.id = ur.role_id "
                    "WHERE ur.user_id = :i"
                ),
                {"i": user_id},
            )
        )


def audit_actions(engine: Engine, prefix: str) -> list[str]:
    with engine.connect() as conn:
        return [
            r[0]
            for r in conn.execute(
                text("SELECT action FROM audit_logs WHERE action LIKE :p ORDER BY id"),
                {"p": f"{prefix}%"},
            )
        ]


def second_admin(
    client: TestClient, engine: Engine, email: str
) -> tuple[TestClient, dict[str, str]]:
    c = anon(client)
    me = login_admin(c, engine, email)
    return c, {CSRF_HEADER: str(me["csrf_token"])}


# --- papéis ---------------------------------------------------------------------------


def test_create_role_with_permissions_and_audit(client: TestClient, admin_engine: Engine) -> None:
    headers = admin(client, admin_engine)
    r = client.post(
        "/api/v1/roles",
        json={"name": "event_reader", "description": "lê eventos", "permissions": ["events.read"]},
        headers=headers,
    )
    assert r.status_code == 201
    assert r.json()["is_system"] is False and r.json()["permissions"] == ["events.read"]
    assert audit_actions(admin_engine, "role.") == ["role.created"]
    dup = client.post("/api/v1/roles", json={"name": "event_reader"}, headers=headers)
    assert dup.status_code == 409
    for bad in (
        {"name": "X"},
        {"name": "super admin"},
        {"name": "ok_name", "permissions": ["nao.existe"]},
        {"name": "ok_name", "is_system": True},
        {"name": "ok_name", "description": "a\nb"},
    ):
        assert client.post("/api/v1/roles", json=bad, headers=headers).status_code == 422, bad


def test_cannot_create_role_with_permissions_you_do_not_have(
    client: TestClient, admin_engine: Engine
) -> None:
    user_with(admin_engine, "rm@ares.test", ["roles.manage", "events.read"])
    c, headers = acting_as(client, "rm@ares.test")
    denied = c.post(
        "/api/v1/roles",
        json={"name": "sneaky", "permissions": ["events.read", "users.write"]},
        headers=headers,
    )
    assert denied.status_code == 403 and denied.json()["code"] == "privilege_escalation"
    ok = c.post(
        "/api/v1/roles", json={"name": "mine", "permissions": ["events.read"]}, headers=headers
    )
    assert ok.status_code == 201


def test_system_roles_cannot_be_changed_through_the_api(
    client: TestClient, admin_engine: Engine
) -> None:
    headers = admin(client, admin_engine)
    r = client.put(
        f"/api/v1/roles/{role_id(admin_engine, 'viewer')}/permissions",
        json={"permissions": ["events.read"]},
        headers=headers,
    )
    assert r.status_code == 409 and r.json()["code"] == "system_role_immutable"
    missing = client.put(
        f"/api/v1/roles/{uuid.uuid4()}/permissions", json={"permissions": []}, headers=headers
    )
    assert missing.status_code == 404


def test_role_permission_changes_respect_escalation_both_ways(
    client: TestClient, admin_engine: Engine
) -> None:
    custom_role(admin_engine, "target_role", ["events.read", "audit.read"])
    user_with(admin_engine, "rm@ares.test", ["roles.manage", "events.read", "alerts.read"])
    c, headers = acting_as(client, "rm@ares.test")
    url = f"/api/v1/roles/{role_id(admin_engine, 'target_role')}/permissions"
    # Adicionar o que não tem: não.
    add = c.put(
        url, json={"permissions": ["events.read", "audit.read", "users.write"]}, headers=headers
    )
    assert add.status_code == 403
    # Tirar o que não tem (audit.read) também não.
    remove = c.put(url, json={"permissions": ["events.read"]}, headers=headers)
    assert remove.status_code == 403
    # Mexer só no que tem: sim.
    ok = c.put(
        url, json={"permissions": ["events.read", "audit.read", "alerts.read"]}, headers=headers
    )
    assert ok.status_code == 200 and ok.json()["permissions"] == [
        "alerts.read",
        "audit.read",
        "events.read",
    ]
    assert audit_actions(admin_engine, "role.permissions") == ["role.permissions_changed"]


def test_removing_roles_manage_from_the_last_admins_role_is_refused(
    client: TestClient, admin_engine: Engine
) -> None:
    custom_role(admin_engine, "governance", ["roles.manage", "users.read", "users.write"])
    solo = make_user(admin_engine, "solo@ares.test", roles=("governance",))
    c, headers = acting_as(client, "solo@ares.test")
    assert admin_count(admin_engine) == 1
    r = c.put(
        f"/api/v1/roles/{role_id(admin_engine, 'governance')}/permissions",
        json={"permissions": ["users.read", "users.write"]},
        headers=headers,
    )
    assert r.status_code == 409 and r.json()["code"] == "last_admin"
    assert admin_count(admin_engine) == 1 and roles_of(admin_engine, solo) == ["governance"]


# --- papéis de usuário --------------------------------------------------------------------


def test_set_user_roles_grants_and_revokes_with_one_audit_line_each(
    client: TestClient, admin_engine: Engine
) -> None:
    headers = admin(client, admin_engine)
    target = make_user(admin_engine, "t@ares.test", roles=("viewer",))
    r = client.put(
        f"/api/v1/users/{target}/roles",
        json={"roles": ["auditor", "security_analyst"]},
        headers=headers,
    )
    assert r.status_code == 200 and r.json()["roles"] == ["auditor", "security_analyst"]
    assert sorted(audit_actions(admin_engine, "user.role")) == [
        "user.role_granted",
        "user.role_granted",
        "user.role_revoked",
    ]
    with admin_engine.connect() as conn:
        granted_by = conn.execute(
            text("SELECT DISTINCT granted_by FROM user_roles WHERE user_id = :i"), {"i": target}
        ).all()
    root = conn_scalar(admin_engine, "SELECT id FROM users WHERE email = 'root@ares.test'")
    assert [str(g[0]) for g in granted_by] == [root]
    # Mesmo conjunto: nada muda e nada é auditado.
    again = client.put(
        f"/api/v1/users/{target}/roles",
        json={"roles": ["auditor", "security_analyst"]},
        headers=headers,
    )
    assert again.status_code == 200 and len(audit_actions(admin_engine, "user.role")) == 3


def conn_scalar(engine: Engine, sql: str) -> str:
    with engine.connect() as conn:
        return str(conn.execute(text(sql)).scalar_one())


def test_set_user_roles_validation_self_and_scope(client: TestClient, admin_engine: Engine) -> None:
    headers = admin(client, admin_engine)
    root = conn_scalar(admin_engine, "SELECT id FROM users WHERE email = 'root@ares.test'")
    me = client.put(f"/api/v1/users/{root}/roles", json={"roles": []}, headers=headers)
    assert me.status_code == 403 and me.json()["code"] == "self_modification"
    target = make_user(admin_engine, "t@ares.test")
    unknown = client.put(f"/api/v1/users/{target}/roles", json={"roles": ["god"]}, headers=headers)
    assert unknown.status_code == 422
    extra = client.put(
        f"/api/v1/users/{target}/roles", json={"roles": [], "user_id": root}, headers=headers
    )
    assert extra.status_code == 422
    missing = client.put(f"/api/v1/users/{uuid.uuid4()}/roles", json={"roles": []}, headers=headers)
    assert missing.status_code == 404


def test_cannot_grant_or_revoke_roles_beyond_your_permissions(
    client: TestClient, admin_engine: Engine
) -> None:
    user_with(admin_engine, "rm@ares.test", ["roles.manage", "users.read", "events.read"])
    custom_role(admin_engine, "small", ["events.read"])
    target = make_user(admin_engine, "t@ares.test", roles=("auditor",))
    c, headers = acting_as(client, "rm@ares.test")
    url = f"/api/v1/users/{target}/roles"
    # Conceder super_admin (tudo) ou viewer (permissões que o ator não tem): não.
    for roles in (["auditor", "super_admin"], ["auditor", "viewer"]):
        r = c.put(url, json={"roles": roles}, headers=headers)
        assert r.status_code == 403 and r.json()["code"] == "privilege_escalation", roles
    # Retirar auditor (audit.read, que o ator não tem): não.
    assert c.put(url, json={"roles": []}, headers=headers).status_code == 403
    # Conceder papel só com o que ele tem: sim.
    ok = c.put(url, json={"roles": ["auditor", "small"]}, headers=headers)
    assert ok.status_code == 200 and roles_of(admin_engine, target) == ["auditor", "small"]


def test_removing_the_other_admin_is_fine_but_never_the_last(
    client: TestClient, admin_engine: Engine
) -> None:
    headers = admin(client, admin_engine)
    other, other_headers = second_admin(client, admin_engine, "b@ares.test")
    b = conn_scalar(admin_engine, "SELECT id FROM users WHERE email = 'b@ares.test'")
    r = client.put(f"/api/v1/users/{b}/roles", json={"roles": ["viewer"]}, headers=headers)
    assert r.status_code == 200 and admin_count(admin_engine) == 1
    # b perdeu roles.manage na hora (permissões são lidas a cada requisição).
    root = conn_scalar(admin_engine, "SELECT id FROM users WHERE email = 'root@ares.test'")
    assert (
        other.put(
            f"/api/v1/users/{root}/roles", json={"roles": []}, headers=other_headers
        ).status_code
        == 403
    )


# --- desativar ------------------------------------------------------------------------


def test_disable_kills_sessions_and_pending_tokens_at_once(
    client: TestClient, admin_engine: Engine
) -> None:
    headers = admin(client, admin_engine)
    make_user(admin_engine, "v@ares.test", roles=("viewer",))
    victim, _ = acting_as(client, "v@ares.test")
    assert victim.get("/api/v1/me").status_code == 200
    created = post_user(client, headers).json()
    token = created["setup_token"]
    v = conn_scalar(admin_engine, "SELECT id FROM users WHERE email = 'v@ares.test'")

    r = client.post(f"/api/v1/users/{v}/disable", headers=headers)
    assert r.status_code == 200 and r.json()["status"] == "disabled"
    assert victim.get("/api/v1/me").status_code == 401  # sessão morreu na hora
    # E no banco: revogada de fato (não só barrada pelo status da conta).
    with admin_engine.connect() as conn:
        alive = conn.execute(
            text("SELECT count(*) FROM sessions WHERE user_id = :i AND revoked_at IS NULL"),
            {"i": v},
        ).scalar_one()
    assert alive == 0
    login = anon(client).post(
        "/api/v1/auth/login", json={"email": "v@ares.test", "password": PASSWORD}
    )
    assert login.status_code == 401

    # Desativar a conta nova mata o token de configuração pendente.
    client.post(f"/api/v1/users/{created['id']}/disable", headers=headers)
    with admin_engine.connect() as conn:
        pending = conn.execute(
            text("SELECT count(*) FROM recovery_tokens WHERE user_id = :i AND used_at IS NULL"),
            {"i": created["id"]},
        ).scalar_one()
    assert pending == 0
    confirm = anon(client).post(
        "/api/v1/auth/recovery/confirm",
        json={"token": token, "new_password": "uma senha bem longa 1"},
    )
    assert confirm.status_code == 401

    # Repetir não audita de novo.
    client.post(f"/api/v1/users/{v}/disable", headers=headers)
    assert audit_actions(admin_engine, "user.disabled") == ["user.disabled", "user.disabled"]


def test_disable_rules_self_power_and_permission(client: TestClient, admin_engine: Engine) -> None:
    headers = admin(client, admin_engine)
    root = conn_scalar(admin_engine, "SELECT id FROM users WHERE email = 'root@ares.test'")
    me = client.post(f"/api/v1/users/{root}/disable", headers=headers)
    assert me.status_code == 403 and me.json()["code"] == "self_modification"
    user_with(admin_engine, "w@ares.test", ["users.write", "users.read"])
    w, wheaders = acting_as(client, "w@ares.test")
    # Administrador menor não derruba o maior.
    assert w.post(f"/api/v1/users/{root}/disable", headers=wheaders).status_code == 403
    peer = make_user(admin_engine, "p@ares.test")
    assert w.post(f"/api/v1/users/{peer}/disable", headers=wheaders).status_code == 200
    make_user(admin_engine, "v@ares.test", roles=("viewer",))
    viewer, vheaders = acting_as(client, "v@ares.test")
    assert viewer.post(f"/api/v1/users/{peer}/disable", headers=vheaders).status_code == 403
    assert w.post(f"/api/v1/users/{peer}/disable").status_code == 403  # sem CSRF


def test_two_admins_disabling_each_other_at_once_never_empty_the_group(
    client: TestClient, admin_engine: Engine
) -> None:
    """Concorrência: cada requisição sozinha passaria; juntas não podem zerar o grupo."""
    a, a_headers = second_admin(client, admin_engine, "a@ares.test")
    b, b_headers = second_admin(client, admin_engine, "b@ares.test")
    a_id = conn_scalar(admin_engine, "SELECT id FROM users WHERE email = 'a@ares.test'")
    b_id = conn_scalar(admin_engine, "SELECT id FROM users WHERE email = 'b@ares.test'")
    assert admin_count(admin_engine) == 2
    barrier = threading.Barrier(2)
    codes: dict[str, int] = {}

    def go(name: str, c: TestClient, headers: dict[str, str], target: str) -> None:
        barrier.wait()
        codes[name] = c.post(f"/api/v1/users/{target}/disable", headers=headers).status_code

    threads = [
        threading.Thread(target=go, args=("a", a, a_headers, b_id)),
        threading.Thread(target=go, args=("b", b, b_headers, a_id)),
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert sorted(codes.values()) == [200, 409], codes
    assert admin_count(admin_engine) == 1


# --- reset de MFA -------------------------------------------------------------------------


def test_admin_resets_another_users_mfa_with_reauthentication(
    client: TestClient, admin_engine: Engine
) -> None:
    headers = admin(client, admin_engine)
    uid = make_user(admin_engine, "m@ares.test", roles=("security_analyst",))
    secret = add_factor(admin_engine, uid)
    victim = anon(client)
    login_mfa(victim, admin_engine, "m@ares.test", secret)
    url = f"/api/v1/users/{uid}/mfa/reset"

    wrong = client.post(url, json={"password": "senha errada demais"}, headers=headers)
    assert wrong.status_code == 401
    assert client.post(url, json={}, headers=headers).status_code == 422
    ok = client.post(url, json={"password": PASSWORD}, headers=headers)
    assert ok.status_code == 200
    assert victim.get("/api/v1/me").status_code == 401  # sessões do alvo morreram
    with admin_engine.connect() as conn:
        status = conn.execute(
            text("SELECT status FROM mfa_factors WHERE user_id = :i"), {"i": uid}
        ).scalar_one()
    assert status == "revoked"
    again = client.post(url, json={"password": PASSWORD}, headers=headers)
    assert again.status_code == 409 and again.json()["code"] == "mfa_not_enrolled"
    with admin_engine.connect() as conn:
        results = [
            r[0]
            for r in conn.execute(
                text("SELECT result FROM audit_logs WHERE action = 'user.mfa_reset' ORDER BY id")
            )
        ]
    assert results == ["failure", "success"]  # a reautenticação falha também é auditada


def test_mfa_reset_rules(client: TestClient, admin_engine: Engine) -> None:
    headers = admin(client, admin_engine)
    root = conn_scalar(admin_engine, "SELECT id FROM users WHERE email = 'root@ares.test'")
    me = client.post(
        f"/api/v1/users/{root}/mfa/reset", json={"password": PASSWORD}, headers=headers
    )
    assert me.status_code == 403
    user_with(admin_engine, "w@ares.test", ["users.write", "users.read"])
    w, wheaders = acting_as(client, "w@ares.test")
    stronger = w.post(
        f"/api/v1/users/{root}/mfa/reset", json={"password": PASSWORD}, headers=wheaders
    )
    assert stronger.status_code == 403
    with admin_engine.connect() as conn:
        assert (
            conn.execute(
                text("SELECT count(*) FROM mfa_factors WHERE status = 'active'")
            ).scalar_one()
            == 1
        )


def test_cli_revoke_mfa(admin_engine: Engine) -> None:
    uid = make_user(admin_engine, "solo@ares.test", roles=("super_admin",))
    add_factor(admin_engine, uid)
    cli.revoke_mfa(admin_engine, "SOLO@ares.test")
    with admin_engine.connect() as conn:
        status = conn.execute(
            text("SELECT status FROM mfa_factors WHERE user_id = :i"), {"i": uid}
        ).scalar_one()
        reason = conn.execute(
            text("SELECT actor_type, reason FROM audit_logs WHERE action = 'user.mfa_reset'")
        ).one()
    assert status == "revoked" and tuple(reason) == ("system", "cli")
    with pytest.raises(cli.CliError):
        cli.revoke_mfa(admin_engine, "solo@ares.test")  # já sem MFA
    with pytest.raises(cli.CliError):
        cli.revoke_mfa(admin_engine, "ninguem@ares.test")


# --- sessões ----------------------------------------------------------------------------


def test_list_and_revoke_own_sessions(client: TestClient, admin_engine: Engine) -> None:
    make_user(admin_engine, "v@ares.test", roles=("viewer",))
    first, h1 = acting_as(client, "v@ares.test")
    second, _ = acting_as(client, "v@ares.test")
    listing = first.get("/api/v1/auth/sessions")
    assert listing.status_code == 200 and listing.headers["cache-control"] == "no-store"
    items = listing.json()["items"]
    assert len(items) == 2 and sum(i["current"] for i in items) == 1
    assert "token" not in listing.text and "ua_hash" not in listing.text
    other = next(i for i in items if not i["current"])
    assert first.delete(f"/api/v1/auth/sessions/{other['id']}", headers=h1).status_code == 204
    assert second.get("/api/v1/me").status_code == 401
    assert first.get("/api/v1/me").status_code == 200
    assert audit_actions(admin_engine, "auth.session_revoked") == ["auth.session_revoked"]


def test_sessions_of_other_users_need_users_write(client: TestClient, admin_engine: Engine) -> None:
    make_user(admin_engine, "v@ares.test", roles=("viewer",))
    victim, _ = acting_as(client, "v@ares.test")
    vid = conn_scalar(admin_engine, "SELECT id FROM users WHERE email = 'v@ares.test'")
    vsession = victim.get("/api/v1/auth/sessions").json()["items"][0]["id"]

    make_user(admin_engine, "x@ares.test", roles=("viewer",))
    peer, ph = acting_as(client, "x@ares.test")
    assert peer.get(f"/api/v1/auth/sessions?user_id={vid}").status_code == 403
    # Sem users.write, a sessão de outro "não existe" (404), e continua viva.
    assert peer.delete(f"/api/v1/auth/sessions/{vsession}", headers=ph).status_code == 404
    assert victim.get("/api/v1/me").status_code == 200

    # users.write, e pelo menos as permissões do alvo (não atinge quem tem mais poder).
    user_with(
        admin_engine,
        "w@ares.test",
        [
            "users.write",
            "users.read",
            "modules.read",
            "events.read",
            "alerts.read",
            "incidents.read",
        ],
    )
    w, wh = acting_as(client, "w@ares.test")
    listing = w.get(f"/api/v1/auth/sessions?user_id={vid}")
    assert listing.status_code == 200 and [i["id"] for i in listing.json()["items"]] == [vsession]
    assert w.delete(f"/api/v1/auth/sessions/{vsession}", headers=wh).status_code == 204
    assert victim.get("/api/v1/me").status_code == 401
    assert w.get("/api/v1/auth/sessions?foo=1").status_code == 400
    assert w.delete(f"/api/v1/auth/sessions/{uuid.uuid4()}", headers=wh).status_code == 404
