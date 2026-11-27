"""Integração e recuperação do Core (item 7 da seção 21.13; ADR 0006).

Estado que precisa sobreviver a queda de conexão e a reinício do processo mora
no PostgreSQL. Só os limitadores de taxa são em memória (zeram ao reiniciar, e
isso está registrado no ADR 0003).
"""

import uuid
from typing import Any

import pyotp
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import Engine, create_engine, event, make_url, text

from app import cli
from app.agents.service import make_credential
from app.auth.dependencies import CSRF_HEADER, SESSION_COOKIE
from app.core.database import build_engine
from app.main import create_app
from tests.test_agents import authorize, build_app, create_agent, enroll, whoami
from tests.test_auth import PASSWORD, _settings, add_factor, login_mfa, make_user
from tests.test_events import make_event, post_events, stored_events

pytestmark = pytest.mark.db


def _production_like_engine(url: str) -> Engine:
    """Engine criado por ``build_engine`` (com pool_pre_ping), rodando como ares_app."""
    engine = build_engine(url)

    @event.listens_for(engine, "connect")
    def _set_role(dbapi_conn: Any, _record: Any) -> None:
        with dbapi_conn.cursor() as cur:
            cur.execute("SET ROLE ares_app")
        dbapi_conn.commit()

    return engine


def _kill_other_connections(admin_engine: Engine) -> int:
    """Derruba todas as conexões do banco de teste (como um restart do PostgreSQL)."""
    with admin_engine.connect() as conn:
        killed = conn.execute(
            text(
                "SELECT count(pg_terminate_backend(pid)) FROM pg_stat_activity "
                "WHERE datname = current_database() AND pid <> pg_backend_pid()"
            )
        ).scalar_one()
        conn.commit()
    return int(killed)


def test_core_recovers_after_database_drops_every_connection(
    migrated_database_url: str, admin_engine: Engine, app_role: str
) -> None:
    uid = make_user(admin_engine, "rec@ares.test", roles=("viewer",))
    secret = add_factor(admin_engine, uid)
    engine = _production_like_engine(migrated_database_url)
    try:
        with TestClient(build_app(engine), base_url="https://testserver") as c:
            login_mfa(c, admin_engine, "rec@ares.test", secret)
            assert c.get("/ready").status_code == 200
            assert c.get("/api/v1/me").status_code == 200

            assert _kill_other_connections(admin_engine) > 0  # o banco "reiniciou"

            # A primeira requisição depois da queda já funciona: o pool detecta a
            # conexão morta (pre-ping) e reconecta, sem derrubar o processo.
            assert c.get("/ready").status_code == 200
            assert c.get("/api/v1/me").status_code == 200
            assert c.get("/health").status_code == 200
    finally:
        engine.dispose()


def test_state_survives_a_process_restart(app_engine: Engine, admin_engine: Engine) -> None:
    """Novo processo (nova instância do app) sobre o mesmo banco."""
    first = build_app(app_engine)
    with TestClient(first, base_url="https://testserver") as human:
        me = _admin_login(human, admin_engine, "boot@ares.test")
        headers = {CSRF_HEADER: str(me["csrf_token"])}
        auth_id = authorize(admin_engine)
        created = create_agent(human, headers, auth_id).json()
        credential = enroll(human, created["enrollment_token"]).json()["credential"]
        batch = [make_event(created["agent_id"]) for _ in range(3)]
        sent = post_events(human, credential, batch, key="before-restart")
        assert sent.status_code == 202
        cookies = dict(human.cookies)

    second = build_app(app_engine)  # "reinício": nada em memória do processo anterior
    with TestClient(second, base_url="https://testserver") as after:
        for name, value in cookies.items():
            after.cookies.set(name, value)
        assert after.get("/api/v1/me").status_code == 200  # a sessão continua válida
        anon = TestClient(second, base_url="https://testserver")
        assert whoami(anon, credential).status_code == 200  # credencial do agente também
        replay = post_events(anon, credential, batch, key="before-restart")
        assert replay.headers["idempotent-replay"] == "true"  # idempotência vem do banco
        assert replay.json() == sent.json()
        again = post_events(anon, credential, batch, key="new-key")
        assert [i["outcome"] for i in again.json()["results"]] == ["duplicate"] * 3
        assert after.get(f"/api/v1/events/{batch[0]['event_id']}").status_code == 200
    assert len(stored_events(admin_engine)) == 3


def _admin_login(client: TestClient, engine: Engine, email: str) -> dict[str, Any]:
    """Administrador de verdade: cadastra o TOTP pelo próprio fluxo da API."""
    make_user(engine, email, roles=("super_admin",))
    r = client.post("/api/v1/auth/login", json={"email": email, "password": PASSWORD})
    assert r.json() == {"status": "mfa_required", "purpose": "enroll"}
    secret = client.post("/api/v1/auth/mfa/enroll").json()["secret"]
    r = client.post("/api/v1/auth/mfa/confirm", json={"code": pyotp.TOTP(secret).now()})
    assert r.status_code == 200 and len(r.json()["recovery_codes"]) == 10
    me = client.get("/api/v1/me")
    assert me.status_code == 200
    body: dict[str, Any] = me.json()
    return body


def test_end_to_end_from_bootstrap_to_event_and_audit_trail(
    app_engine: Engine, admin_engine: Engine
) -> None:
    """Fluxo completo do marco 1 + 01b, sem atalhos de teste."""
    # 1. Bootstrap do primeiro administrador, só pelo CLI.
    admin_id = cli.create_admin(admin_engine, "chefe@ares.test", "Chefe", PASSWORD)
    assert admin_id

    app = create_app(_settings(), engine=app_engine)
    with TestClient(app, base_url="https://testserver") as human:
        # 2. Login em dois passos: o administrador cadastra o TOTP.
        r = human.post(
            "/api/v1/auth/login", json={"email": "chefe@ares.test", "password": PASSWORD}
        )
        assert r.json()["purpose"] == "enroll" and SESSION_COOKIE not in human.cookies
        secret = human.post("/api/v1/auth/mfa/enroll").json()["secret"]
        confirmed = human.post("/api/v1/auth/mfa/confirm", json={"code": pyotp.TOTP(secret).now()})
        assert confirmed.status_code == 200
        me = human.get("/api/v1/me").json()
        assert "modules.configure" in me["permissions"] and "events.read" in me["permissions"]
        headers = {CSRF_HEADER: me["csrf_token"]}

        # 3. Sem termo de autorização não há enrolamento; com termo, há.
        blocked = create_agent(human, headers, uuid.uuid4())
        assert blocked.status_code == 409 and blocked.json()["code"] == "authorization_required"
        auth_id = cli.record_authorization(
            admin_engine, "TERMO-2026-001", "Rede de laboratório", 30
        )
        created = create_agent(human, headers, auth_id)
        assert created.status_code == 201

        # 4. O agente se enrola com o token e envia um lote.
        agent = TestClient(app, base_url="https://testserver")
        enrolled = enroll(agent, created.json()["enrollment_token"], host_id="lab-host-1")
        assert enrolled.status_code == 201
        credential = enrolled.json()["credential"]
        agent_id = created.json()["agent_id"]
        good, bad = make_event(agent_id), make_event(agent_id, schema_version=7)
        sent = post_events(agent, credential, [good, bad], key="e2e-1")
        assert sent.status_code == 202
        assert (sent.json()["accepted"], sent.json()["rejected"]) == (1, 1)

        # 5. O humano lê o evento aceito, e o rejeitado não existe.
        read = human.get(f"/api/v1/events/{good['event_id']}")
        assert read.status_code == 200 and read.json()["data"] == good["data"]
        assert human.get(f"/api/v1/events/{bad['event_id']}").status_code == 404

        # 6. Revogar o agente corta a ingestão na hora.
        assert human.post(f"/api/v1/agents/{agent_id}/revoke", headers=headers).status_code == 200
        assert (
            post_events(agent, credential, [make_event(agent_id)], key="e2e-2").status_code == 401
        )

        # 7. A trilha de auditoria registra as ações sensíveis, e a cadeia confere.
        trail = human.get("/api/v1/audit-logs", params={"limit": 200}).json()["items"]
        seen = [(i["action"], i["result"]) for i in reversed(trail)]
    for expected in (
        ("user.bootstrap_admin", "success"),
        ("mfa.enroll", "success"),
        ("mfa.confirm", "success"),
        ("auth.login", "success"),
        ("authorization.recorded", "success"),
        ("agent.enrollment_token_issued", "success"),
        ("agent.enrolled", "success"),
        ("agent.revoked", "success"),
    ):
        assert expected in seen, expected
    # Nenhum segredo (token, credencial, TOTP, senha) chegou à auditoria.
    with admin_engine.connect() as conn:
        dump = str(conn.execute(text("SELECT json_agg(a)::text FROM audit_logs a")).scalar())
    for secret_value in (credential, credential.split(".", 1)[1], secret, PASSWORD):
        assert secret_value not in dump
    result = cli.verify_audit(admin_engine)
    assert result.ok and result.checked == len(seen)


def test_audit_chain_stays_valid_under_concurrent_mixed_activity(
    app_engine: Engine, admin_engine: Engine
) -> None:
    """Várias ações auditadas ao mesmo tempo não bifurcam a cadeia."""
    import threading

    app = build_app(app_engine)
    users = []
    for i in range(6):
        users.append(f"c{i}@ares.test")
        make_user(admin_engine, users[-1], roles=("viewer",))
    barrier = threading.Barrier(len(users))
    errors: list[str] = []

    def work(email: str) -> None:
        with TestClient(app, base_url="https://testserver") as c:
            barrier.wait()
            r = c.post("/api/v1/auth/login", json={"email": email, "password": PASSWORD})
            if r.status_code != 200:
                errors.append(f"{email}: {r.status_code}")
                return
            csrf = r.json()["csrf_token"]
            c.get("/api/v1/permissions")  # authz.denied (viewer não tem roles.manage)
            c.post("/api/v1/auth/logout", headers={CSRF_HEADER: csrf})

    threads = [threading.Thread(target=work, args=(u,)) for u in users]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errors == []
    result = cli.verify_audit(admin_engine)
    assert result.ok and result.checked == len(users) * 3


def test_credential_helper_format_matches_the_authenticator() -> None:
    agent_id = uuid.uuid4()
    credential, digest = make_credential(agent_id)
    prefix, secret = credential.split(".")
    assert prefix == f"ares_agent_{agent_id.hex}" and len(secret) == 43 and len(digest) == 32


def test_readiness_reflects_database_loss_and_recovery(
    migrated_database_url: str, admin_url: str, app_role: str
) -> None:
    db_name = make_url(migrated_database_url).database
    maintenance = create_engine(admin_url, isolation_level="AUTOCOMMIT")  # banco `postgres`
    engine = _production_like_engine(migrated_database_url)
    try:
        with TestClient(build_app(engine), base_url="https://testserver") as c:
            assert c.get("/ready").status_code == 200
            with maintenance.connect() as conn:
                conn.execute(text(f'ALTER DATABASE "{db_name}" ALLOW_CONNECTIONS false'))
                conn.execute(
                    text(
                        "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = :d"
                    ),
                    {"d": db_name},
                )
            try:
                # Banco indisponível: /ready responde 503 e /health continua 200.
                assert c.get("/ready").status_code == 503
                assert c.get("/health").status_code == 200
            finally:
                with maintenance.connect() as conn:
                    conn.execute(text(f'ALTER DATABASE "{db_name}" ALLOW_CONNECTIONS true'))
            # Banco de volta: o Core se recupera sozinho, sem reiniciar.
            assert c.get("/ready").status_code == 200
    finally:
        engine.dispose()
        maintenance.dispose()
