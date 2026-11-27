"""Trilha de auditoria (item 5 da 21.13; ADR 0004)."""

import threading
from collections.abc import Iterator

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, select, text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session as DbSession

from app import cli
from app.audit import service as audit
from app.audit.models import AuditLog
from app.auth.dependencies import CSRF_HEADER, SESSION_COOKIE
from app.auth.models import Session
from app.main import create_app
from tests.test_auth import PASSWORD, _settings, login, make_user

pytestmark = pytest.mark.db


@pytest.fixture
def client(app_engine: Engine) -> Iterator[TestClient]:
    app = create_app(_settings(), engine=app_engine)
    with TestClient(app, base_url="https://testserver", raise_server_exceptions=False) as c:
        yield c


def entries(engine: Engine) -> list[AuditLog]:
    with DbSession(engine) as db:
        return list(db.scalars(select(AuditLog).order_by(AuditLog.id)))


def raw_rows(engine: Engine) -> str:
    with engine.connect() as conn:
        return str(conn.execute(text("SELECT json_agg(a)::text FROM audit_logs a")).scalar())


# --- o que é registrado ----------------------------------------------------


def test_login_success_is_audited(client: TestClient, admin_engine: Engine) -> None:
    uid = make_user(admin_engine, "ok@ares.test")
    r = client.post("/api/v1/auth/login", json={"email": "ok@ares.test", "password": PASSWORD})
    [e] = entries(admin_engine)
    assert (e.action, e.result, e.actor_type, e.actor_user_id) == (
        "auth.login",
        "success",
        "user",
        uid,
    )
    assert str(e.request_id) == r.headers["X-Request-ID"]
    token = client.cookies.get(SESSION_COOKIE)
    assert token and token not in raw_rows(admin_engine)


def test_unknown_account_failure_records_no_email(client: TestClient, admin_engine: Engine) -> None:
    client.post(
        "/api/v1/auth/login", json={"email": "alvo-secreto@ares.test", "password": "x" * 12}
    )
    [e] = entries(admin_engine)
    assert (e.action, e.result, e.actor_type, e.reason) == (
        "auth.login",
        "failure",
        "anonymous",
        "unknown_account",
    )
    assert e.actor_user_id is None
    dump = raw_rows(admin_engine)
    assert "alvo-secreto" not in dump
    assert "x" * 12 not in dump


def test_known_account_failure_and_lock_are_audited(
    client: TestClient, admin_engine: Engine
) -> None:
    uid = make_user(admin_engine, "lk@ares.test")
    for _ in range(5):
        client.post("/api/v1/auth/login", json={"email": "lk@ares.test", "password": "errada-1234"})
    client.post("/api/v1/auth/login", json={"email": "lk@ares.test", "password": PASSWORD})
    rows = entries(admin_engine)
    assert [e.reason for e in rows] == ["invalid_password"] * 5 + ["account_locked"]
    assert all(e.actor_user_id == uid for e in rows)
    assert [e.details for e in rows][:5] == [{}, {}, {}, {}, {"locked_now": True}]
    assert "errada-1234" not in raw_rows(admin_engine)


def test_logout_csrf_failure_and_denied_permission_are_audited(
    client: TestClient, admin_engine: Engine
) -> None:
    uid = make_user(admin_engine, "v@ares.test", roles=("viewer",))
    csrf = str(login(client, "v@ares.test")["csrf_token"])
    assert client.get("/api/v1/permissions").status_code == 403
    assert client.post("/api/v1/auth/logout").status_code == 403
    assert client.post("/api/v1/auth/logout", headers={CSRF_HEADER: csrf}).status_code == 204
    rows = entries(admin_engine)
    assert [(e.action, e.result) for e in rows] == [
        ("auth.login", "success"),
        ("authz.denied", "denied"),
        ("auth.csrf_failed", "denied"),
        ("auth.logout", "success"),
    ]
    assert all(e.actor_user_id == uid for e in rows)
    assert rows[1].details == {"permission": "roles.manage"}
    assert rows[1].resource_id == "GET /api/v1/permissions"  # template da rota
    assert csrf not in raw_rows(admin_engine)


def test_bootstrap_is_audited_as_system(admin_engine: Engine) -> None:
    uid = cli.create_admin(admin_engine, "boot@ares.test", "Boot", PASSWORD)
    [e] = entries(admin_engine)
    assert (e.action, e.actor_type, e.actor_user_id, e.resource_id) == (
        "user.bootstrap_admin",
        "system",
        None,
        str(uid),
    )


def test_action_is_rolled_back_if_audit_fails(
    client: TestClient, admin_engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    make_user(admin_engine, "atom@ares.test")

    def broken(*_: object, **__: object) -> None:
        raise RuntimeError("falha simulada na auditoria")

    monkeypatch.setattr(audit, "record", broken)
    r = client.post("/api/v1/auth/login", json={"email": "atom@ares.test", "password": PASSWORD})
    assert r.status_code == 500
    with DbSession(admin_engine) as db:
        assert db.scalar(select(Session.id)) is None  # sessão não foi gravada


# --- integridade -----------------------------------------------------------


def test_app_role_cannot_update_or_delete(app_engine: Engine, admin_engine: Engine) -> None:
    with DbSession(app_engine) as db:
        audit.record(db, action="test.event", result="success", actor_type="system")
        db.commit()
    for stmt in (
        "UPDATE audit_logs SET reason = 'x'",
        "DELETE FROM audit_logs",
        "TRUNCATE audit_logs",
    ):
        with app_engine.connect() as conn, pytest.raises(DBAPIError, match="permission denied"):
            conn.execute(text(stmt))
    assert len(entries(admin_engine)) == 1


def test_trigger_blocks_ordinary_update_delete_truncate(admin_engine: Engine) -> None:
    with DbSession(admin_engine) as db:
        audit.record(db, action="test.event", result="success", actor_type="system")
        db.commit()
    for stmt in (
        "UPDATE audit_logs SET reason = 'x'",
        "DELETE FROM audit_logs",
        "TRUNCATE audit_logs",
    ):
        with admin_engine.connect() as conn, pytest.raises(DBAPIError, match="append-only"):
            conn.execute(text(stmt))


def _seed(engine: Engine, n: int) -> None:
    with DbSession(engine) as db:
        for i in range(n):
            audit.record(
                db, action="test.event", result="success", actor_type="system", details={"i": i}
            )
        db.commit()


def test_chain_verifies(admin_engine: Engine) -> None:
    _seed(admin_engine, 5)
    result = cli.verify_audit(admin_engine)
    assert result.ok and result.checked == 5


@pytest.mark.parametrize(
    "tamper",
    [
        "UPDATE audit_logs SET details = '{\"i\": 99}' WHERE id = :id",
        "DELETE FROM audit_logs WHERE id = :id",
    ],
)
def test_tampering_is_detected(admin_engine: Engine, tamper: str) -> None:
    _seed(admin_engine, 5)
    target = entries(admin_engine)[2].id
    # Simula quem tem a credencial do dono (ou superusuário) e desliga o trigger.
    with admin_engine.begin() as conn:
        conn.execute(text("ALTER TABLE audit_logs DISABLE TRIGGER audit_logs_no_update_delete"))
        conn.execute(text(tamper), {"id": target})
        conn.execute(text("ALTER TABLE audit_logs ENABLE TRIGGER audit_logs_no_update_delete"))
    result = cli.verify_audit(admin_engine)
    assert not result.ok
    assert result.checked == 2
    assert result.first_bad_id in (target, target + 1)


def test_concurrent_writers_do_not_fork_chain(app_engine: Engine, admin_engine: Engine) -> None:
    writers = 8
    barrier = threading.Barrier(writers)

    def write(i: int) -> None:
        with DbSession(app_engine) as db:
            barrier.wait()
            audit.record(
                db, action="test.event", result="success", actor_type="system", details={"i": i}
            )
            db.commit()

    threads = [threading.Thread(target=write, args=(i,)) for i in range(writers)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    result = cli.verify_audit(admin_engine)
    assert result.ok and result.checked == writers


# --- leitura ---------------------------------------------------------------


def test_audit_logs_requires_audit_read(client: TestClient, admin_engine: Engine) -> None:
    make_user(admin_engine, "vw@ares.test", roles=("viewer",))
    login(client, "vw@ares.test")
    r = client.get("/api/v1/audit-logs")
    assert r.status_code == 403


def test_auditor_reads_with_cursor_pagination(client: TestClient, admin_engine: Engine) -> None:
    make_user(admin_engine, "aud@ares.test", roles=("auditor",))
    _seed(admin_engine, 7)
    login(client, "aud@ares.test")
    ids: list[int] = []
    cursor = None
    while True:
        params = {"limit": "3"} | ({"cursor": cursor} if cursor else {})
        r = client.get("/api/v1/audit-logs", params=params)
        assert r.status_code == 200
        page = r.json()
        ids += [item["id"] for item in page["items"]]
        cursor = page["next_cursor"]
        if cursor is None:
            break
    assert ids == sorted(ids, reverse=True)
    assert len(ids) == len(set(ids)) == 8  # 7 semeadas + o login do auditor
    assert "prev_hash" not in r.text


@pytest.mark.parametrize("cursor", ["!!", "YWJj", "a" * 40])
def test_audit_logs_invalid_cursor(client: TestClient, admin_engine: Engine, cursor: str) -> None:
    make_user(admin_engine, "a2@ares.test", roles=("auditor",))
    login(client, "a2@ares.test")
    r = client.get("/api/v1/audit-logs", params={"cursor": cursor})
    assert r.status_code == 400
    assert r.json()["code"] == "invalid_cursor"


@pytest.mark.parametrize(
    ("params", "status", "code"),
    [
        ({"ordem": "id"}, 400, "unknown_query_parameter"),
        ({"limit": "201"}, 422, "validation_error"),
        ({"limit": "0"}, 422, "validation_error"),
    ],
)
def test_audit_logs_rejects_bad_query(
    client: TestClient, admin_engine: Engine, params: dict[str, str], status: int, code: str
) -> None:
    make_user(admin_engine, "a3@ares.test", roles=("auditor",))
    login(client, "a3@ares.test")
    r = client.get("/api/v1/audit-logs", params=params)
    assert r.status_code == status
    assert r.json()["code"] == code


def test_audit_logs_default_limit_is_50(client: TestClient, admin_engine: Engine) -> None:
    make_user(admin_engine, "a4@ares.test", roles=("auditor",))
    _seed(admin_engine, 60)
    login(client, "a4@ares.test")
    page = client.get("/api/v1/audit-logs").json()
    assert len(page["items"]) == 50
    assert page["next_cursor"] is not None


# --- achados da revisão de segurança ----------------------------------------


def test_removing_last_entry_is_detected_only_with_anchor(admin_engine: Engine) -> None:
    _seed(admin_engine, 4)
    before = cli.verify_audit(admin_engine)
    assert before.ok and before.head_id is not None and before.head_hash is not None
    anchor = (before.head_id, before.head_hash)

    with admin_engine.begin() as conn:
        conn.execute(text("ALTER TABLE audit_logs DISABLE TRIGGER audit_logs_no_update_delete"))
        conn.execute(text("DELETE FROM audit_logs WHERE id = :id"), {"id": anchor[0]})
        conn.execute(text("ALTER TABLE audit_logs ENABLE TRIGGER audit_logs_no_update_delete"))

    assert cli.verify_audit(admin_engine).ok  # sem âncora, a cadeia curta parece válida
    with_anchor = cli.verify_audit(admin_engine, anchor)
    assert not with_anchor.ok
    assert with_anchor.problem is not None and "âncora" in with_anchor.problem


def test_anchor_with_wrong_hash_fails(admin_engine: Engine) -> None:
    _seed(admin_engine, 2)
    head = cli.verify_audit(admin_engine)
    assert head.head_id is not None
    assert not cli.verify_audit(admin_engine, (head.head_id, b"\x01" * 32)).ok


def test_anchor_older_than_head_still_passes(admin_engine: Engine) -> None:
    _seed(admin_engine, 2)
    old = cli.verify_audit(admin_engine)
    assert old.head_id is not None and old.head_hash is not None
    _seed(admin_engine, 3)
    assert cli.verify_audit(admin_engine, (old.head_id, old.head_hash)).ok


def test_parse_head() -> None:
    assert cli.parse_head("7:" + "ab" * 32) == (7, bytes.fromhex("ab" * 32))
    for bad in ("7", "x:" + "ab" * 32, "7:abc", "7:" + "ab" * 31):
        with pytest.raises(cli.CliError):
            cli.parse_head(bad)


@pytest.mark.parametrize(
    "details",
    [{"x": 1.5}, {"x": float("nan")}, {1: "a"}, {"x": {"y": [0.1]}}, {"x": object()}],
)
def test_details_rejects_values_jsonb_would_rewrite(
    admin_engine: Engine, details: dict[object, object]
) -> None:
    with DbSession(admin_engine) as db, pytest.raises(TypeError):
        audit.record(
            db,
            action="test.event",
            result="success",
            actor_type="system",
            details=details,  # type: ignore[arg-type]
        )


def test_downgrade_refuses_to_drop_audit_with_rows(
    migrated_database_url: str, admin_engine: Engine, monkeypatch: pytest.MonkeyPatch
) -> None:
    from alembic import command

    from tests.conftest import alembic_config

    _seed(admin_engine, 1)
    monkeypatch.delenv("ARES_ALLOW_AUDIT_DROP", raising=False)
    with pytest.raises(RuntimeError, match="downgrade recusado"):
        command.downgrade(alembic_config(migrated_database_url), "0002")
    assert len(entries(admin_engine)) == 1
