"""Identidade, login, sessão e autorização mínima (item 4 da 21.13).

A API roda como ares_app (ver fixture ``app_engine``). Os testes de
segurança do CLAUDE.md, seção 9.2, que este item cobre estão marcados.
"""

import io
import threading
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta

import pytest
from fastapi import Depends
from fastapi.testclient import TestClient
from pydantic import SecretStr
from sqlalchemy import Engine, select, text, update
from sqlalchemy.orm import Session as DbSession

from app import cli
from app.auth import passwords, service
from app.auth.dependencies import CSRF_HEADER, SESSION_COOKIE, require_session
from app.auth.models import Role, Session, User, UserRole
from app.core.config import Settings
from app.main import create_app

pytestmark = pytest.mark.db

PASSWORD = "uma-senha-longa-de-teste"


def _settings(**overrides: object) -> Settings:
    return Settings(_env_file=None, env="test", **overrides)  # type: ignore[arg-type]


def make_user(
    engine: Engine,
    email: str,
    roles: tuple[str, ...] = (),
    password: str = PASSWORD,
    status: str = "active",
) -> uuid.UUID:
    with DbSession(engine) as db:
        user = User(
            id=uuid.uuid4(),
            email=email.lower(),
            display_name=email.split("@")[0],
            password_hash=passwords.hash_password(password),
            status=status,
            failed_login_count=0,
        )
        db.add(user)
        db.flush()
        for name in roles:
            role_id = db.scalar(select(Role.id).where(Role.name == name))
            db.add(UserRole(user_id=user.id, role_id=role_id, granted_at=datetime.now(UTC)))
        db.commit()
        return user.id


@pytest.fixture
def client(app_engine: Engine) -> Iterator[TestClient]:
    # https: o cookie é Secure e o httpx só o envia em conexão segura.
    with TestClient(create_app(_settings(), engine=app_engine), base_url="https://testserver") as c:
        yield c


def use_cookie(client: TestClient, token: str) -> None:
    """Troca o cookie de sessão do cliente por ``token`` (jar limpo antes)."""
    client.cookies.clear()
    client.cookies.set(SESSION_COOKIE, token)


def login(client: TestClient, email: str, password: str = PASSWORD) -> dict[str, object]:
    r = client.post("/api/v1/auth/login", json={"email": email, "password": password})
    assert r.status_code == 200, r.text
    body: dict[str, object] = r.json()
    return body


def _error(r_json: dict[str, object]) -> dict[str, object]:
    return {k: v for k, v in r_json.items() if k != "request_id"}


# --- login -----------------------------------------------------------------


def test_login_sets_hardened_cookie_and_returns_no_session_token(
    client: TestClient, admin_engine: Engine
) -> None:
    make_user(admin_engine, "ana@ares.test", roles=("viewer",))
    r = client.post("/api/v1/auth/login", json={"email": "ana@ares.test", "password": PASSWORD})
    assert r.status_code == 200
    cookie = r.headers["set-cookie"]
    assert cookie.startswith(f"{SESSION_COOKIE}=")
    for attr in ("HttpOnly", "Secure", "SameSite=strict", "Path=/"):
        assert attr.lower() in cookie.lower(), attr
    assert "domain=" not in cookie.lower()
    token = client.cookies.get(SESSION_COOKIE)
    assert token and token not in r.text
    body = r.json()
    assert body["roles"] == ["viewer"]
    assert "events.read" in body["permissions"]
    assert body["csrf_token"]


def test_session_token_is_stored_only_as_hash(client: TestClient, admin_engine: Engine) -> None:
    make_user(admin_engine, "hash@ares.test")
    login(client, "hash@ares.test")
    token = client.cookies.get(SESSION_COOKIE)
    assert token
    with DbSession(admin_engine) as db:
        stored = db.scalar(select(Session.token_hash))
        dump = db.execute(text("SELECT row_to_json(s)::text FROM sessions s")).scalar_one()
    assert stored is not None and len(stored) == 32
    assert token not in dump


def test_password_stored_as_argon2id(admin_engine: Engine) -> None:
    make_user(admin_engine, "argon@ares.test")
    with DbSession(admin_engine) as db:
        stored = db.scalar(select(User.password_hash))
    assert stored is not None and stored.startswith("$argon2id$")
    assert PASSWORD not in stored


def test_login_email_is_case_insensitive(client: TestClient, admin_engine: Engine) -> None:
    make_user(admin_engine, "caixa@ares.test")
    login(client, "  CAIXA@Ares.Test ")


def test_failures_are_indistinguishable(client: TestClient, admin_engine: Engine) -> None:
    make_user(admin_engine, "real@ares.test")
    make_user(admin_engine, "off@ares.test", status="disabled")
    cases = [
        {"email": "real@ares.test", "password": "senha-errada-123"},
        {"email": "naoexiste@ares.test", "password": PASSWORD},
        {"email": "off@ares.test", "password": PASSWORD},
    ]
    bodies = []
    for case in cases:
        r = client.post("/api/v1/auth/login", json=case)
        assert r.status_code == 401
        assert "set-cookie" not in r.headers
        bodies.append(_error(r.json()))
    assert bodies[0] == bodies[1] == bodies[2]
    assert bodies[0]["code"] == "invalid_credentials"


def test_unknown_account_still_spends_argon2_time(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[str] = []
    original = passwords.verify_dummy

    def spy(password: str) -> None:
        calls.append(password)
        original(password)

    monkeypatch.setattr(passwords, "verify_dummy", spy)
    r = client.post("/api/v1/auth/login", json={"email": "x@ares.test", "password": "qualquer"})
    assert r.status_code == 401
    assert calls == ["qualquer"]


def test_login_rejects_extra_fields(client: TestClient) -> None:  # 9.2: atribuição em massa
    r = client.post(
        "/api/v1/auth/login",
        json={"email": "a@ares.test", "password": PASSWORD, "roles": ["super_admin"]},
    )
    assert r.status_code == 422
    assert {"field": "body.roles", "type": "extra_forbidden"} in r.json()["details"]


def test_login_requires_json_content_type(client: TestClient) -> None:
    r = client.post(
        "/api/v1/auth/login",
        content=b"email=a@ares.test&password=x",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
    )
    assert r.status_code == 400
    assert r.json()["code"] == "unsupported_content_type"


def test_account_locks_after_repeated_failures(client: TestClient, admin_engine: Engine) -> None:
    make_user(admin_engine, "lock@ares.test")
    for _ in range(5):
        r = client.post(
            "/api/v1/auth/login", json={"email": "lock@ares.test", "password": "errada-errada"}
        )
        assert r.status_code == 401
    # Bloqueada: até a senha certa falha, com o mesmo erro genérico.
    r = client.post("/api/v1/auth/login", json={"email": "lock@ares.test", "password": PASSWORD})
    assert r.status_code == 401
    assert r.json()["code"] == "invalid_credentials"

    with DbSession(admin_engine) as db:
        user = db.scalar(select(User).where(User.email == "lock@ares.test"))
        assert user is not None and user.locked_until is not None
        user.locked_until = datetime.now(UTC) - timedelta(seconds=1)
        db.commit()
    body = login(client, "lock@ares.test")
    assert body["email"] == "lock@ares.test"
    with DbSession(admin_engine) as db:
        user = db.scalar(select(User).where(User.email == "lock@ares.test"))
        assert user is not None and user.failed_login_count == 0 and user.locked_until is None


def test_ip_rate_limit_returns_429_with_retry_after(app_engine: Engine) -> None:
    app = create_app(_settings(login_rate_limit_per_minute=3), engine=app_engine)
    with TestClient(app, base_url="https://testserver") as c:
        for _ in range(3):
            r = c.post("/api/v1/auth/login", json={"email": "x@ares.test", "password": "y"})
            assert r.status_code == 401
        r = c.post("/api/v1/auth/login", json={"email": "x@ares.test", "password": "y"})
        assert r.status_code == 429
        assert r.json()["code"] == "rate_limited"
        assert int(r.headers["Retry-After"]) >= 1


# --- sessão ----------------------------------------------------------------


def test_me_requires_session(client: TestClient) -> None:
    r = client.get("/api/v1/me")
    assert r.status_code == 401
    assert r.json()["code"] == "unauthenticated"


def test_session_fixation_previous_session_dies_on_login(  # 9.2: fixação de sessão
    client: TestClient, admin_engine: Engine
) -> None:
    make_user(admin_engine, "fix@ares.test")
    login(client, "fix@ares.test")
    old = client.cookies.get(SESSION_COOKIE)
    login(client, "fix@ares.test")
    new = client.cookies.get(SESSION_COOKIE)
    assert old and new and old != new

    use_cookie(client, old)
    assert client.get("/api/v1/me").status_code == 401
    use_cookie(client, new)
    assert client.get("/api/v1/me").status_code == 200


def test_logout_requires_csrf_and_revokes(client: TestClient, admin_engine: Engine) -> None:
    make_user(admin_engine, "out@ares.test")
    csrf = login(client, "out@ares.test")["csrf_token"]
    assert isinstance(csrf, str)

    assert client.post("/api/v1/auth/logout").json()["code"] == "csrf_failed"
    r = client.post("/api/v1/auth/logout", headers={CSRF_HEADER: "errado"})
    assert r.status_code == 403

    token = client.cookies.get(SESSION_COOKIE)
    r = client.post("/api/v1/auth/logout", headers={CSRF_HEADER: csrf})
    assert r.status_code == 204
    assert token
    use_cookie(client, token)
    assert client.get("/api/v1/me").status_code == 401


def test_idle_and_absolute_expiry(client: TestClient, admin_engine: Engine) -> None:
    make_user(admin_engine, "exp@ares.test")
    login(client, "exp@ares.test")
    assert client.get("/api/v1/me").status_code == 200
    past = datetime.now(UTC) - timedelta(seconds=1)

    with DbSession(admin_engine) as db:
        db.execute(update(Session).values(idle_expires_at=past))
        db.commit()
    assert client.get("/api/v1/me").status_code == 401

    login(client, "exp@ares.test")
    with DbSession(admin_engine) as db:
        db.execute(
            update(Session)
            .where(Session.revoked_at.is_(None), Session.idle_expires_at > past)
            .values(absolute_expires_at=past, idle_expires_at=past)
        )
        db.commit()
    assert client.get("/api/v1/me").status_code == 401


def test_disabled_user_loses_active_session(client: TestClient, admin_engine: Engine) -> None:
    make_user(admin_engine, "dis@ares.test")
    login(client, "dis@ares.test")
    with DbSession(admin_engine) as db:
        db.execute(update(User).values(status="disabled"))
        db.commit()
    assert client.get("/api/v1/me").status_code == 401


# --- autorização -----------------------------------------------------------


def test_permissions_requires_roles_manage(client: TestClient, admin_engine: Engine) -> None:
    make_user(admin_engine, "viewer@ares.test", roles=("viewer",))
    login(client, "viewer@ares.test")
    r = client.get("/api/v1/permissions")
    assert r.status_code == 403
    assert r.json()["code"] == "permission_denied"


def test_permissions_cursor_pagination(client: TestClient, admin_engine: Engine) -> None:
    make_user(admin_engine, "root@ares.test", roles=("super_admin",))
    login(client, "root@ares.test")
    names: list[str] = []
    cursor = None
    while True:
        params = {"limit": "4"} | ({"cursor": cursor} if cursor else {})
        r = client.get("/api/v1/permissions", params=params)
        assert r.status_code == 200
        page = r.json()
        assert len(page["items"]) <= 4
        names += [i["name"] for i in page["items"]]
        cursor = page["next_cursor"]
        if cursor is None:
            break
    assert names == sorted(names)
    assert len(names) == len(set(names)) == 15


@pytest.mark.parametrize(
    ("params", "status", "code"),
    [
        ({"cursor": "!!!"}, 400, "invalid_cursor"),
        ({"cursor": "Zm9v"}, 400, "invalid_cursor"),  # base64 válido, conteúdo não
        ({"limit": "201"}, 422, "validation_error"),
        ({"limit": "0"}, 422, "validation_error"),
        ({"ordem": "x"}, 400, "unknown_query_parameter"),
    ],
)
def test_permissions_rejects_bad_query(
    client: TestClient, admin_engine: Engine, params: dict[str, str], status: int, code: str
) -> None:
    make_user(admin_engine, "q@ares.test", roles=("super_admin",))
    login(client, "q@ares.test")
    r = client.get("/api/v1/permissions", params=params)
    assert r.status_code == status
    assert r.json()["code"] == code


# --- bootstrap por CLI -----------------------------------------------------


def test_cli_creates_first_admin_only_once(admin_engine: Engine) -> None:
    # O CLI roda como ares_owner; nos testes, o administrador faz esse papel.
    user_id = cli.create_admin(admin_engine, "Chefe@Ares.Test", "Chefe", PASSWORD)
    with DbSession(admin_engine) as db:
        user = db.get(User, user_id)
        assert user is not None and user.email == "chefe@ares.test"
    with pytest.raises(cli.CliError, match="Já existe um administrador"):
        cli.create_admin(admin_engine, "outro@ares.test", "Outro", PASSWORD)


@pytest.mark.parametrize(
    ("password", "error"),
    [
        ("curta", "password_too_short"),
        ("x" * 129, "password_too_long"),
        ("admin@ares.test", "password_equals_email"),
    ],
)
def test_cli_enforces_password_policy(admin_engine: Engine, password: str, error: str) -> None:
    with pytest.raises(cli.CliError, match=error):
        cli.create_admin(admin_engine, "admin@ares.test", "Admin", password)


def test_cli_reads_password_from_stdin(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("sys.stdin", io.StringIO(PASSWORD + "\n"))
    assert cli._read_password(from_stdin=True) == PASSWORD


def test_real_argon2_parameters() -> None:
    # A suíte usa parâmetros baratos; aqui conferimos os de produção.
    assert (passwords.TIME_COST, passwords.MEMORY_COST_KIB, passwords.PARALLELISM) == (
        10,
        65536,
        4,
    )


# --- achados das revisões de segurança e de conformidade --------------------


def test_cli_rejects_non_ascii_email(admin_engine: Engine) -> None:
    with pytest.raises(cli.CliError, match="ASCII"):
        cli.create_admin(admin_engine, "joão@ares.test", "João", PASSWORD)


def test_cli_concurrent_bootstrap_creates_one_admin(admin_engine: Engine) -> None:
    results: list[str] = []
    barrier = threading.Barrier(2)

    def run(email: str) -> None:
        barrier.wait()
        try:
            cli.create_admin(admin_engine, email, "X", PASSWORD)
            results.append("ok")
        except cli.CliError:
            results.append("recusado")

    threads = [threading.Thread(target=run, args=(f"a{i}@ares.test",)) for i in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert sorted(results) == ["ok", "recusado"]


def test_concurrent_failures_are_all_counted(app_engine: Engine, admin_engine: Engine) -> None:
    """Sem trava de linha, tentativas simultâneas perderiam incrementos."""
    make_user(admin_engine, "race@ares.test")
    settings = _settings(login_max_failures=100)
    attempts = 8
    barrier = threading.Barrier(attempts)

    def attempt() -> None:
        with DbSession(app_engine) as db:
            barrier.wait()
            service.authenticate(db, settings, "race@ares.test", "errada-errada", datetime.now(UTC))

    threads = [threading.Thread(target=attempt) for _ in range(attempts)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    with DbSession(admin_engine) as db:
        count = db.scalar(select(User.failed_login_count).where(User.email == "race@ares.test"))
    assert count == attempts


@pytest.mark.parametrize("kind", ["disabled", "locked"])
def test_disabled_and_locked_spend_argon2_time(
    client: TestClient, admin_engine: Engine, monkeypatch: pytest.MonkeyPatch, kind: str
) -> None:
    make_user(admin_engine, "t@ares.test", status="disabled" if kind == "disabled" else "active")
    if kind == "locked":
        with DbSession(admin_engine) as db:
            db.execute(update(User).values(locked_until=datetime.now(UTC) + timedelta(minutes=5)))
            db.commit()
    calls: list[str] = []
    original = passwords.verify_dummy

    def spy(password: str) -> None:
        calls.append(password)
        original(password)

    monkeypatch.setattr(passwords, "verify_dummy", spy)
    r = client.post("/api/v1/auth/login", json={"email": "t@ares.test", "password": PASSWORD})
    assert r.status_code == 401
    assert r.json()["code"] == "invalid_credentials"
    assert calls == [PASSWORD]


def test_csrf_token_of_other_session_is_rejected(client: TestClient, admin_engine: Engine) -> None:
    make_user(admin_engine, "c1@ares.test")
    make_user(admin_engine, "c2@ares.test")
    csrf_1 = login(client, "c1@ares.test")["csrf_token"]
    login(client, "c2@ares.test")
    r = client.post("/api/v1/auth/logout", headers={CSRF_HEADER: str(csrf_1)})
    assert r.status_code == 403
    assert r.json()["code"] == "csrf_failed"


def test_csrf_required_on_all_mutating_methods(app_engine: Engine, admin_engine: Engine) -> None:
    app = create_app(_settings(), engine=app_engine)

    @app.api_route("/_mut", methods=["PUT", "PATCH", "DELETE"], status_code=204)
    def mutate(_: object = Depends(require_session)) -> None:
        return None

    make_user(admin_engine, "m@ares.test")
    with TestClient(app, base_url="https://testserver") as c:
        csrf = str(login(c, "m@ares.test")["csrf_token"])
        for method in ("PUT", "PATCH", "DELETE"):
            assert c.request(method, "/_mut").status_code == 403, method
            assert c.request(method, "/_mut", headers={CSRF_HEADER: csrf}).status_code == 204


def test_non_ascii_csrf_header_is_403_not_500(client: TestClient, admin_engine: Engine) -> None:
    make_user(admin_engine, "na@ares.test")
    login(client, "na@ares.test")
    r = client.post("/api/v1/auth/logout", headers={CSRF_HEADER: "été".encode("latin-1")})
    assert r.status_code == 403


def test_hasher_busy_returns_503(app_engine: Engine, admin_engine: Engine) -> None:
    make_user(admin_engine, "busy@ares.test")
    passwords.configure_for_tests(max_concurrent=1, acquire_timeout=0.01)
    try:
        assert passwords._slots.acquire()  # ocupa o único slot
        app = create_app(_settings(), engine=app_engine)
        with TestClient(app, base_url="https://testserver") as c:
            r = c.post("/api/v1/auth/login", json={"email": "busy@ares.test", "password": PASSWORD})
        assert r.status_code == 503
        assert r.json()["code"] == "busy"
        assert r.headers["Retry-After"] == "1"
    finally:
        passwords.configure_for_tests()


def test_cursor_too_long_is_400(client: TestClient, admin_engine: Engine) -> None:
    make_user(admin_engine, "cur@ares.test", roles=("super_admin",))
    login(client, "cur@ares.test")
    r = client.get("/api/v1/permissions", params={"cursor": "a" * 201})
    assert r.status_code == 400
    assert r.json()["code"] == "invalid_cursor"


def test_database_down_is_503() -> None:
    url = "postgresql+psycopg://u:p@127.0.0.1:1/nada"
    app = create_app(_settings(database_url=SecretStr(url)))
    with TestClient(app, base_url="https://testserver", raise_server_exceptions=False) as c:
        c.cookies.set(SESSION_COOKIE, "qualquer")
        r = c.get("/api/v1/me")
    assert r.status_code == 503
    assert r.json()["code"] == "dependency_unavailable"
    assert "127.0.0.1" not in r.text
