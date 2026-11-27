"""Agentes, credenciais e termo de autorização (ADR 0006)."""

import uuid
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from typing import Any, cast

import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient
from httpx import Response
from sqlalchemy import Engine, select, text, update
from sqlalchemy.orm import Session as DbSession

from app import cli
from app.agents.deps import AgentContext, require_agent
from app.agents.models import Agent, AgentCredential, AgentEnrollmentToken, OperatorAuthorization
from app.auth.dependencies import CSRF_HEADER, SESSION_COOKIE
from app.auth.models import User
from app.main import create_app
from tests.test_auth import PASSWORD, _settings, add_factor, login_admin, login_mfa, make_user

pytestmark = pytest.mark.db


def build_app(engine: Engine, **settings: Any) -> FastAPI:
    app = create_app(_settings(**settings), engine=engine)

    @app.get("/_whoami")
    def whoami(ctx: AgentContext = Depends(require_agent)) -> dict[str, str]:
        return {"agent_id": str(ctx.agent.id), "module": ctx.agent.module}

    return app


@pytest.fixture
def client(app_engine: Engine) -> Iterator[TestClient]:
    with TestClient(build_app(app_engine), base_url="https://testserver") as c:
        yield c


def authorize(engine: Engine, days: int = 30) -> uuid.UUID:
    return cli.record_authorization(engine, "TERMO-001", "Laboratório próprio de testes", days)


def admin_headers(
    client: TestClient, engine: Engine, email: str = "adm@ares.test"
) -> dict[str, str]:
    me = login_admin(client, engine, email)
    return {CSRF_HEADER: str(me["csrf_token"])}


def create_agent(
    client: TestClient,
    headers: dict[str, str],
    authorization_id: uuid.UUID,
    key: str = "k-1",
    **overrides: Any,
) -> Response:
    body = {
        "name": "ag-1",
        "module": "endpoint",
        "authorization_id": str(authorization_id),
    } | overrides
    return cast(
        Response,
        client.post("/api/v1/agents", json=body, headers={**headers, "Idempotency-Key": key}),
    )


def enroll(client: TestClient, token: str, **extra: Any) -> Response:
    return cast(
        Response, client.post("/api/v1/agents/enroll", json={"enrollment_token": token} | extra)
    )


def enrolled_agent(
    client: TestClient, engine: Engine, headers: dict[str, str], **overrides: Any
) -> tuple[str, str]:
    """Cria e enrola um agente; devolve (agent_id, credencial)."""
    auth_id = authorize(engine)
    created = create_agent(client, headers, auth_id, **overrides)
    assert created.status_code == 201, created.text
    r = enroll(client, created.json()["enrollment_token"])
    assert r.status_code == 200, r.text
    return r.json()["agent_id"], r.json()["credential"]


def whoami(client: TestClient, credential: str) -> Response:
    return cast(Response, client.get("/_whoami", headers={"Authorization": f"Agent {credential}"}))


# --- termo de autorização (CLAUDE.md 9.4) ------------------------------------


def test_cannot_create_agent_without_authorization(
    client: TestClient, admin_engine: Engine
) -> None:
    headers = admin_headers(client, admin_engine)
    r = create_agent(client, headers, uuid.uuid4())  # nenhum termo existe
    assert r.status_code == 409 and r.json()["code"] == "authorization_required"
    with DbSession(admin_engine) as db:
        assert db.scalar(select(Agent.id)) is None


@pytest.mark.parametrize("how", ["expired", "revoked"])
def test_expired_or_revoked_authorization_blocks_creation(
    client: TestClient, admin_engine: Engine, how: str
) -> None:
    headers = admin_headers(client, admin_engine)
    auth_id = authorize(admin_engine)
    with DbSession(admin_engine) as db:
        values = (
            {
                "valid_until": datetime.now(UTC) - timedelta(seconds=1),
                "valid_from": datetime.now(UTC) - timedelta(days=1),
            }
            if how == "expired"
            else {"revoked_at": datetime.now(UTC)}
        )
        db.execute(update(OperatorAuthorization).values(**values))
        db.commit()
    r = create_agent(client, headers, auth_id)
    assert r.status_code == 409 and r.json()["code"] == "authorization_required"


def test_authorization_revoked_before_enrollment_blocks_enrollment(
    client: TestClient, admin_engine: Engine
) -> None:
    headers = admin_headers(client, admin_engine)
    auth_id = authorize(admin_engine)
    token = create_agent(client, headers, auth_id).json()["enrollment_token"]
    cli.revoke_authorization(admin_engine, auth_id)
    r = enroll(client, token)
    assert r.status_code == 409 and r.json()["code"] == "authorization_required"
    with DbSession(admin_engine) as db:
        assert db.scalar(select(Agent.status)) == "pending"  # não ativou


def test_agent_records_which_authorization_covers_it(
    client: TestClient, admin_engine: Engine
) -> None:
    headers = admin_headers(client, admin_engine)
    auth_id = authorize(admin_engine)
    create_agent(client, headers, auth_id)
    with DbSession(admin_engine) as db:
        assert db.scalar(select(Agent.authorization_id)) == auth_id


def test_authorization_cli_validations_and_audit(admin_engine: Engine) -> None:
    for days in (0, 366):
        with pytest.raises(cli.CliError):
            cli.record_authorization(admin_engine, "R", "D", days)
    with pytest.raises(cli.CliError):
        cli.record_authorization(admin_engine, " ", "D", 5)
    with pytest.raises(cli.CliError, match="controle"):
        cli.record_authorization(admin_engine, "R\nforjada", "D", 5)
    auth_id = authorize(admin_engine)
    cli.revoke_authorization(admin_engine, auth_id)
    with pytest.raises(cli.CliError, match="já estava revogado"):
        cli.revoke_authorization(admin_engine, auth_id)
    with pytest.raises(cli.CliError, match="não encontrado"):
        cli.revoke_authorization(admin_engine, uuid.uuid4())
    with admin_engine.connect() as conn:
        rows = conn.execute(text("SELECT action, actor_type FROM audit_logs ORDER BY id")).all()
    assert [(r[0], r[1]) for r in rows] == [
        ("authorization.recorded", "system"),
        ("authorization.revoked", "system"),
    ]


# --- criar agente -------------------------------------------------------------


def test_create_agent_returns_token_once_and_stores_only_hash(
    client: TestClient, admin_engine: Engine
) -> None:
    headers = admin_headers(client, admin_engine)
    r = create_agent(client, headers, authorize(admin_engine))
    assert r.status_code == 201
    assert r.headers["cache-control"] == "no-store"
    body = r.json()
    token = body["enrollment_token"]
    assert len(token) >= 40 and body["status"] == "pending" and body["replayed"] is False
    with admin_engine.connect() as conn:
        dump = conn.execute(
            text("SELECT json_agg(t)::text FROM agent_enrollment_tokens t")
        ).scalar_one()
        idem = conn.execute(text("SELECT json_agg(i)::text FROM idempotency_keys i")).scalar_one()
        audit_dump = conn.execute(text("SELECT json_agg(a)::text FROM audit_logs a")).scalar_one()
    for blob in (dump, idem, audit_dump):
        assert token not in blob
    with DbSession(admin_engine) as db:
        row = db.scalar(select(AgentEnrollmentToken))
        assert row is not None and row.expires_at - row.created_at == timedelta(hours=24)


def test_create_agent_requires_permission_csrf_and_session(
    client: TestClient, admin_engine: Engine
) -> None:
    auth_id = authorize(admin_engine)
    r = create_agent(client, {}, auth_id)
    assert r.status_code == 401
    make_user(admin_engine, "viewer@ares.test", roles=("viewer",))
    client.post("/api/v1/auth/login", json={"email": "viewer@ares.test", "password": PASSWORD})
    me = client.get("/api/v1/me").json()
    assert create_agent(client, {CSRF_HEADER: me["csrf_token"]}, auth_id).status_code == 403
    assert create_agent(client, {}, auth_id).status_code == 403  # CSRF antes da permissão


def test_create_agent_input_validation(client: TestClient, admin_engine: Engine) -> None:
    headers = admin_headers(client, admin_engine)
    auth_id = authorize(admin_engine)
    base = {"name": "a", "module": "endpoint", "authorization_id": str(auth_id)}

    def post(body: dict[str, Any], extra: dict[str, str] | None = None) -> Response:
        return cast(
            Response, client.post("/api/v1/agents", json=body, headers={**headers, **(extra or {})})
        )

    assert post(base).status_code == 400  # sem Idempotency-Key
    assert post(base).json()["code"] == "idempotency_key_required"
    ik = {"Idempotency-Key": "k-v"}
    assert post(base | {"status": "active"}, ik).status_code == 422  # atribuição em massa
    assert post(base | {"module": "Endpoint!"}, ik).status_code == 422
    assert post(base | {"name": "a\nb"}, ik).status_code == 422  # caractere de controle
    assert post(base | {"name": "a\x00b"}, ik).status_code == 422
    r = client.post(
        "/api/v1/agents", content=b"x=1", headers={**headers, **ik, "Content-Type": "text/plain"}
    )
    assert r.status_code == 400
    r = client.post("/api/v1/agents", params={"x": 1}, json=base, headers={**headers, **ik})
    assert r.status_code == 400 and r.json()["code"] == "unknown_query_parameter"
    for bad in ("", "a b", "a/b", "x" * 129):
        assert post(base, {"Idempotency-Key": bad}).status_code == 400


def test_idempotency_replay_and_conflict(client: TestClient, admin_engine: Engine) -> None:
    headers = admin_headers(client, admin_engine)
    auth_id = authorize(admin_engine)
    first = create_agent(client, headers, auth_id, key="same")
    again = create_agent(client, headers, auth_id, key="same")
    assert again.status_code == 201 and again.headers["idempotent-replay"] == "true"
    assert again.json()["agent_id"] == first.json()["agent_id"]
    assert again.json()["enrollment_token"] is None  # o segredo não fica guardado
    assert again.json()["replayed"] is True
    other = create_agent(client, headers, auth_id, key="same", name="outro")
    assert other.status_code == 409 and other.json()["code"] == "idempotency_key_reused"
    with DbSession(admin_engine) as db:
        assert len(db.scalars(select(Agent.id)).all()) == 1  # nenhuma duplicata


def test_expired_idempotency_key_is_reusable(
    client: TestClient, admin_engine: Engine, app_engine: Engine
) -> None:
    headers = admin_headers(client, admin_engine)
    auth_id = authorize(admin_engine)
    create_agent(client, headers, auth_id, key="old")
    with admin_engine.begin() as conn:
        conn.execute(text("UPDATE idempotency_keys SET expires_at = now() - interval '1 second'"))
    again = create_agent(client, headers, auth_id, key="old", name="novo")
    assert again.status_code == 201 and again.json()["replayed"] is False
    with DbSession(admin_engine) as db:
        assert len(db.scalars(select(Agent.id)).all()) == 2


# --- enrolamento --------------------------------------------------------------


def test_enroll_issues_credential_once_and_activates(
    client: TestClient, admin_engine: Engine
) -> None:
    headers = admin_headers(client, admin_engine)
    created = create_agent(client, headers, authorize(admin_engine)).json()
    r = enroll(client, created["enrollment_token"], host_id="host-7")
    assert r.status_code == 200 and r.headers["cache-control"] == "no-store"
    credential = r.json()["credential"]
    assert credential.startswith(f"ares_agent_{uuid.UUID(created['agent_id']).hex}.")
    with DbSession(admin_engine) as db:
        agent = db.get(Agent, uuid.UUID(created["agent_id"]))
        assert agent is not None and agent.status == "active" and agent.host_id == "host-7"
        cred = db.scalar(select(AgentCredential))
        assert cred is not None and len(cred.credential_hash) == 32
    with admin_engine.connect() as conn:
        dump = conn.execute(text("SELECT json_agg(c)::text FROM agent_credentials c")).scalar_one()
        audit_dump = conn.execute(text("SELECT json_agg(a)::text FROM audit_logs a")).scalar_one()
    secret = credential.split(".", 1)[1]
    assert secret not in dump and secret not in audit_dump and credential not in audit_dump
    with admin_engine.connect() as conn:
        actions = conn.execute(text("SELECT action, actor_type FROM audit_logs ORDER BY id")).all()
    assert [(a, t) for a, t in actions][-2:] == [
        ("agent.enrollment_token_issued", "user"),
        ("agent.enrolled", "system"),
    ]


def test_enrollment_token_is_single_use(client: TestClient, admin_engine: Engine) -> None:
    headers = admin_headers(client, admin_engine)
    token = create_agent(client, headers, authorize(admin_engine)).json()["enrollment_token"]
    assert enroll(client, token).status_code == 200
    r = enroll(client, token)
    assert r.status_code == 401 and r.json()["code"] == "invalid_enrollment"


def test_enrollment_failures_are_indistinguishable(
    client: TestClient, admin_engine: Engine
) -> None:
    headers = admin_headers(client, admin_engine)
    auth_id = authorize(admin_engine)
    used = create_agent(client, headers, auth_id, key="a").json()["enrollment_token"]
    enroll(client, used)
    revoked_agent = create_agent(client, headers, auth_id, key="c").json()
    client.post(f"/api/v1/agents/{revoked_agent['agent_id']}/revoke", headers=headers)
    bodies = []
    for token in (used, "x" * 43, revoked_agent["enrollment_token"]):
        r = enroll(client, token)
        assert r.status_code == 401
        bodies.append({k: v for k, v in r.json().items() if k != "request_id"})
    assert bodies[0] == bodies[1] == bodies[2] and bodies[0]["code"] == "invalid_enrollment"


def test_expired_enrollment_token_is_refused(client: TestClient, admin_engine: Engine) -> None:
    headers = admin_headers(client, admin_engine)
    token = create_agent(client, headers, authorize(admin_engine)).json()["enrollment_token"]
    with DbSession(admin_engine) as db:
        db.execute(
            update(AgentEnrollmentToken).values(expires_at=datetime.now(UTC) - timedelta(seconds=1))
        )
        db.commit()
    assert enroll(client, token).status_code == 401


def test_enroll_rate_limit_and_validation(app_engine: Engine, admin_engine: Engine) -> None:
    with TestClient(
        build_app(app_engine, enroll_rate_limit_per_minute=2), base_url="https://testserver"
    ) as c:
        for _ in range(2):
            assert enroll(c, "x" * 43).status_code == 401
        r = enroll(c, "x" * 43)
        assert r.status_code == 429 and int(r.headers["Retry-After"]) >= 1
    with TestClient(build_app(app_engine), base_url="https://testserver") as c:
        assert (
            c.post(
                "/api/v1/agents/enroll", json={"enrollment_token": "x" * 43, "role": "admin"}
            ).status_code
            == 422
        )
        assert (
            c.post(
                "/api/v1/agents/enroll", content=b"x", headers={"Content-Type": "text/plain"}
            ).status_code
            == 400
        )


# --- autenticação do agente ----------------------------------------------------


def test_agent_credential_authenticates_and_is_not_a_human(
    client: TestClient, admin_engine: Engine
) -> None:
    headers = admin_headers(client, admin_engine)
    agent_id, credential = enrolled_agent(client, admin_engine, headers)
    anon = TestClient(client.app, base_url="https://testserver")
    r = whoami(anon, credential)
    assert r.status_code == 200 and r.json() == {"agent_id": agent_id, "module": "endpoint"}
    # Credencial de agente não vale como sessão de humano, nem em rota protegida.
    for path in ("/api/v1/me", "/api/v1/permissions", "/api/v1/audit-logs"):
        assert anon.get(path, headers={"Authorization": f"Agent {credential}"}).status_code == 401
    # E cookie de humano não autentica agente.
    assert client.get("/_whoami").status_code == 401


@pytest.mark.parametrize(
    "header",
    [
        None,
        "",
        "Agent",
        "Agent ",
        "Bearer ares_agent_" + "0" * 32 + "." + "A" * 43,
        "Agent ares_agent_" + "0" * 32 + "." + "A" * 43,  # agente inexistente
        "Agent ares_agent_" + "0" * 31 + "." + "A" * 43,
        "Agent ares_agent_" + "g" * 32 + "." + "A" * 43,
        "Agent " + "A" * 80,
        "agent ares_agent_" + "0" * 32 + "." + "A" * 43,
    ],
)
def test_malformed_or_unknown_credentials_are_401(client: TestClient, header: str | None) -> None:
    anon = TestClient(client.app, base_url="https://testserver")
    r = anon.get("/_whoami", headers={} if header is None else {"Authorization": header})
    assert r.status_code == 401 and r.json()["code"] == "unauthenticated"


def test_wrong_secret_or_other_agents_id_is_401(client: TestClient, admin_engine: Engine) -> None:
    headers = admin_headers(client, admin_engine)
    auth_id = authorize(admin_engine)
    ids = []
    for i in range(2):
        tok = create_agent(client, headers, auth_id, key=f"k{i}", name=f"a{i}").json()
        cred = enroll(client, tok["enrollment_token"]).json()["credential"]
        ids.append((tok["agent_id"], cred))
    anon = TestClient(client.app, base_url="https://testserver")
    (id_a, cred_a), (_id_b, cred_b) = ids
    assert whoami(anon, cred_a).status_code == 200
    swapped = f"ares_agent_{uuid.UUID(id_a).hex}.{cred_b.split('.', 1)[1]}"
    assert whoami(anon, swapped).status_code == 401
    wrong = cred_a[:-1] + ("A" if cred_a[-1] != "A" else "B")
    assert whoami(anon, wrong).status_code == 401


def test_revoked_agent_credential_is_401_immediately(
    client: TestClient, admin_engine: Engine
) -> None:
    """9.2: credencial de agente revogada, 401 imediato."""
    headers = admin_headers(client, admin_engine)
    agent_id, credential = enrolled_agent(client, admin_engine, headers)
    anon = TestClient(client.app, base_url="https://testserver")
    assert whoami(anon, credential).status_code == 200
    r = client.post(f"/api/v1/agents/{agent_id}/revoke", headers=headers)
    assert r.status_code == 200 and r.json() == {"agent_id": agent_id, "status": "revoked"}
    assert whoami(anon, credential).status_code == 401
    with admin_engine.connect() as conn:
        n = conn.execute(
            text("SELECT count(*) FROM agent_credentials WHERE revoked_at IS NULL")
        ).scalar_one()
    assert n == 0


def test_revoke_is_idempotent_and_audited_once(client: TestClient, admin_engine: Engine) -> None:
    headers = admin_headers(client, admin_engine)
    agent_id, _ = enrolled_agent(client, admin_engine, headers)
    for _ in range(2):
        assert client.post(f"/api/v1/agents/{agent_id}/revoke", headers=headers).status_code == 200
    with admin_engine.connect() as conn:
        n = conn.execute(
            text("SELECT count(*) FROM audit_logs WHERE action = 'agent.revoked'")
        ).scalar_one()
    assert n == 1


def test_rotation_kills_old_credential_and_keeps_one_active(
    client: TestClient, admin_engine: Engine
) -> None:
    headers = admin_headers(client, admin_engine)
    agent_id, old = enrolled_agent(client, admin_engine, headers)
    r = client.post(f"/api/v1/agents/{agent_id}/rotate", headers=headers)
    assert r.status_code == 200 and r.headers["cache-control"] == "no-store"
    new = r.json()["credential"]
    anon = TestClient(client.app, base_url="https://testserver")
    assert whoami(anon, old).status_code == 401
    assert whoami(anon, new).status_code == 200
    with admin_engine.connect() as conn:
        active = conn.execute(
            text("SELECT count(*) FROM agent_credentials WHERE revoked_at IS NULL")
        ).scalar_one()
        total = conn.execute(text("SELECT count(*) FROM agent_credentials")).scalar_one()
    assert (active, total) == (1, 2)
    # Rotação de agente revogado ou pendente é recusada.
    client.post(f"/api/v1/agents/{agent_id}/revoke", headers=headers)
    assert client.post(f"/api/v1/agents/{agent_id}/rotate", headers=headers).status_code == 409


def test_unknown_agent_is_404_and_routes_need_csrf(
    client: TestClient, admin_engine: Engine
) -> None:
    headers = admin_headers(client, admin_engine)
    ghost = uuid.uuid4()
    assert client.post(f"/api/v1/agents/{ghost}/revoke", headers=headers).status_code == 404
    assert client.post(f"/api/v1/agents/{ghost}/rotate", headers=headers).status_code == 404
    assert client.post(f"/api/v1/agents/{ghost}/revoke").status_code == 403  # sem CSRF
    assert client.post("/api/v1/agents/não-é-uuid/revoke", headers=headers).status_code == 422


def test_revoking_pending_agent_voids_its_enrollment_token(
    client: TestClient, admin_engine: Engine
) -> None:
    headers = admin_headers(client, admin_engine)
    created = create_agent(client, headers, authorize(admin_engine)).json()
    client.post(f"/api/v1/agents/{created['agent_id']}/revoke", headers=headers)
    assert enroll(client, created["enrollment_token"]).status_code == 401


# --- escopo (tenant) -----------------------------------------------------------


def test_scoped_user_cannot_touch_agents_of_other_tenant(
    client: TestClient, admin_engine: Engine
) -> None:
    uid = make_user(admin_engine, "scoped@ares.test", roles=("security_admin",))
    with DbSession(admin_engine) as db:
        db.execute(update(User).where(User.id == uid).values(tenant_id="T1"))
        db.commit()
    csrf = str(
        login_mfa(client, admin_engine, "scoped@ares.test", add_factor(admin_engine, uid))[
            "csrf_token"
        ]
    )
    headers = {CSRF_HEADER: csrf}
    auth_id = authorize(admin_engine)
    assert create_agent(client, headers, auth_id, key="x", tenant_id="T2").status_code == 403
    mine = create_agent(client, headers, auth_id, key="y").json()  # herda o escopo T1
    assert mine["tenant_id"] == "T1"
    with DbSession(admin_engine) as db:
        other = Agent(
            id=uuid.uuid4(),
            name="o",
            module="endpoint",
            tenant_id="T2",
            status="active",
            authorization_id=auth_id,
            created_by=uid,
            created_at=datetime.now(UTC),
        )
        db.add(other)
        db.commit()
        other_id = other.id
    assert client.post(f"/api/v1/agents/{other_id}/revoke", headers=headers).status_code == 404
    assert (
        client.post(f"/api/v1/agents/{mine['agent_id']}/revoke", headers=headers).status_code == 200
    )


def test_cookie_is_not_needed_for_enroll_but_sessions_are_untouched(
    client: TestClient, admin_engine: Engine
) -> None:
    headers = admin_headers(client, admin_engine)
    token = create_agent(client, headers, authorize(admin_engine)).json()["enrollment_token"]
    assert enroll(TestClient(client.app, base_url="https://testserver"), token).status_code == 200
    assert client.cookies.get(SESSION_COOKIE)  # a sessão do administrador continua valendo
    assert client.get("/api/v1/me").status_code == 200


# --- CLI de manutenção ---------------------------------------------------------


def test_purge_expired_removes_only_expired_rows(admin_engine: Engine) -> None:
    with admin_engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO ingest_records (event_id, received_at, source_id, outcome) VALUES "
                "(gen_random_uuid(), now() - interval '8 days', 's', 'accepted'), "
                "(gen_random_uuid(), now() - interval '1 day', 's', 'accepted')"
            )
        )
        conn.execute(
            text(
                "INSERT INTO idempotency_keys (principal_type, principal_id, key, request_hash, "
                "response_status, response_body, created_at, expires_at) VALUES "
                "('user', gen_random_uuid(), 'old', '\\x"
                + "00"
                * 32
                + "', 201, '{}', now(), now() - interval '1 hour'), "
                "('user', gen_random_uuid(), 'new', '\\x"
                + "00" * 32
                + "', 201, '{}', now(), now() + interval '1 hour')"
            )
        )
    removed = cli.purge_expired(admin_engine)
    assert removed["ingest_records"] == 1 and removed["idempotency_keys"] == 1
    with admin_engine.connect() as conn:
        assert conn.execute(text("SELECT count(*) FROM ingest_records")).scalar_one() == 1
        assert conn.execute(text("SELECT count(*) FROM idempotency_keys")).scalar_one() == 1
