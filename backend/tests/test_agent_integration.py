"""O agente (``../agent``) contra o Core real e PostgreSQL (ADR 0007).

Mostra que o envelope que o agente monta é aceito pelo servidor de verdade, para cada
tipo de evento, e que revogação, termo e rate limit chegam ao agente como esperado.
Só importa o que não precisa do Gerenciador de Credenciais (nada de ``credentials``/``cli``).
"""

import random
import uuid
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast
from xml.sax.saxutils import escape

import pytest
from ares_agent import client as agent_api
from ares_agent import log as agent_log
from ares_agent.config import Config
from ares_agent.runner import CredentialRejected, Runner
from ares_agent.store import Store
from fastapi.testclient import TestClient
from sqlalchemy import Engine, text

from tests.test_agents import admin_headers, authorize, build_app, create_agent, enroll

pytestmark = pytest.mark.db

NS = "http://schemas.microsoft.com/win/2004/08/events/event"


def xml_event(windows_id: int, record_id: int, data: dict[str, str], when: str) -> str:
    items = "".join(f"<Data Name='{k}'>{escape(v)}</Data>" for k, v in data.items())
    return (
        f"<Event xmlns='{NS}'><System><EventID>{windows_id}</EventID>"
        f"<TimeCreated SystemTime='{when}'/><EventRecordID>{record_id}</EventRecordID>"
        f"<Channel>Security</Channel><Computer>LAB</Computer></System>"
        f"<EventData>{items}</EventData></Event>"
    )


SAMPLES: dict[int, dict[str, str]] = {
    4624: {"TargetUserName": "ana", "TargetDomainName": "LAB", "LogonType": "2"},
    4625: {
        "TargetUserName": "<script>alert(1)</script>",
        "LogonType": "3",
        "IpAddress": "10.0.0.9",
    },
    4648: {"SubjectUserName": "a", "TargetUserName": "b", "ProcessName": "C:\\x.exe"},
    4672: {"SubjectUserName": "adm", "SubjectDomainName": "LAB"},
    4720: {"TargetUserName": "novo", "SubjectUserName": "adm"},
    4732: {"MemberName": "CN=x", "MemberSid": "S-1-5-21-1", "TargetUserName": "Administrators"},
}


class FakeLog:
    def __init__(self) -> None:
        self.records: dict[int, str] = {}

    def add(self, record_id: int, windows_id: int = 4625, **fields: str) -> None:
        when = (datetime.now(UTC) - timedelta(seconds=5)).strftime("%Y-%m-%dT%H:%M:%S.%f0Z")
        self.records[record_id] = xml_event(
            windows_id, record_id, fields or SAMPLES[windows_id], when
        )

    def read(self, after: int, limit: int) -> str:
        ids = sorted(i for i in self.records if i > after)[:limit]
        return "".join(self.records[i] for i in ids)

    def latest(self) -> int:
        return max(self.records, default=0)


class Rig:
    """Um agente enrolado no Core de teste, com Runner e Security log sintético."""

    def __init__(
        self,
        tmp_path: Path,
        app_engine: Engine,
        admin_engine: Engine,
        **settings: Any,
    ) -> None:
        self.admin_engine = admin_engine
        self.core = TestClient(build_app(app_engine, **settings), base_url="https://testserver")
        self.core.__enter__()
        self.headers = admin_headers(self.core, admin_engine)
        self.auth_id = authorize(admin_engine)
        created = create_agent(self.core, self.headers, self.auth_id).json()
        enrolled = enroll(self.core, created["enrollment_token"]).json()
        self.agent_id: str = enrolled["agent_id"]
        self.credential: str = enrolled["credential"]
        self.fake_log = FakeLog()
        self.tmp_path = tmp_path
        self.runner, self.store = self.new_runner(tmp_path)

    def new_runner(self, home: Path) -> tuple[Runner, Store]:
        # Sem cookie: o agente usa só a credencial dele.
        anon = TestClient(self.core.app, base_url="https://testserver")
        cfg = Config(server_url="https://testserver", home=home)
        store = Store(cfg.store_path, cfg.queue_max_events, cfg.queue_max_bytes)
        runner = Runner(
            cfg,
            store,
            agent_api.ServerClient(anon, self.credential),
            self.agent_id,
            "endpoint",
            agent_log.setup(None, stderr=False),
            read=self.fake_log.read,
            latest=self.fake_log.latest,
            rng=random.Random(7),
        )
        return runner, store

    def count_events(self) -> int:
        with self.admin_engine.connect() as conn:
            return cast(int, conn.execute(text("SELECT count(*) FROM events")).scalar_one())

    def close(self) -> None:
        self.core.__exit__(None, None, None)


@pytest.fixture
def rig(tmp_path: Path, app_engine: Engine, admin_engine: Engine) -> Any:
    made: list[Rig] = []

    def factory(**settings: Any) -> Rig:
        r = Rig(tmp_path / f"home{len(made)}", app_engine, admin_engine, **settings)
        made.append(r)
        return r

    yield factory
    for r in made:
        r.close()


def test_every_supported_event_type_is_accepted_by_the_real_core(rig: Any) -> None:
    r: Rig = rig()
    r.runner.cycle()  # primeira execução: marca o ponto de partida
    for i, windows_id in enumerate(SAMPLES, start=1):
        r.fake_log.add(i, windows_id)
    assert r.runner.cycle() == 15  # sem falha: intervalo normal
    assert r.store.stats()["queued_events"] == 0
    assert r.store.stats()["rejected_total"] == 0 and r.store.get("last_error") == ""
    assert r.count_events() == len(SAMPLES)
    with r.admin_engine.connect() as conn:
        types = {t for (t,) in conn.execute(text("SELECT event_type FROM events"))}
        classes = {c for (c,) in conn.execute(text("SELECT data_classification FROM events"))}
    assert types == {
        "authentication.success",
        "authentication.failure",
        "authentication.explicit_credentials",
        "privilege.special_assigned",
        "account.created",
        "group.member_added",
    }
    assert classes == {"personal"}


def test_stored_xss_payload_from_the_log_comes_back_as_text(rig: Any) -> None:
    r: Rig = rig()
    r.runner.cycle()
    r.fake_log.add(1, 4625)  # nome de usuário com <script>
    r.runner.cycle()
    event_id = r.store.get("collected_record_id") and agent_event_id(r, 1)
    got = r.core.get(f"/api/v1/events/{event_id}")
    assert got.status_code == 200 and got.headers["content-type"].startswith("application/json")
    assert got.json()["data"]["user"] == "<script>alert(1)</script>"
    assert got.json()["source_module"] == "endpoint"


def agent_event_id(r: Rig, record_id: int) -> str:
    from ares_agent import mapping

    return mapping.make_event_id(r.agent_id, record_id)


def test_heartbeat_marks_an_idle_agent_as_seen(rig: Any) -> None:
    r: Rig = rig()
    with r.admin_engine.connect() as conn:
        before = conn.execute(text("SELECT last_seen_at FROM agents")).scalar_one()
    assert before is None
    r.runner.cycle()  # sem eventos: só o heartbeat
    with r.admin_engine.connect() as conn:
        after = conn.execute(text("SELECT last_seen_at FROM agents")).scalar_one()
    assert after is not None and r.count_events() == 0


def test_resending_after_losing_local_state_creates_no_duplicates(rig: Any, tmp_path: Path) -> None:
    r: Rig = rig()
    r.runner.cycle()
    for i in (1, 2, 3):
        r.fake_log.add(i)
    r.runner.cycle()
    assert r.count_events() == 3
    # "Reinstala" o agente: estado novo, relê os mesmos registros.
    fresh, fresh_store = r.new_runner(tmp_path / "reinstalado")
    fresh_store.put("collected_record_id", "0")
    fresh.cycle()
    assert fresh_store.stats()["queued_events"] == 0  # o servidor respondeu `duplicate`
    assert r.count_events() == 3


def test_revoked_agent_is_cut_off_and_keeps_its_events(rig: Any) -> None:
    r: Rig = rig()
    r.runner.cycle()
    r.core.post(f"/api/v1/agents/{r.agent_id}/revoke", headers=r.headers)
    r.fake_log.add(1)
    with pytest.raises(CredentialRejected):
        r.runner.cycle()
    assert r.store.stats()["queued_events"] == 1 and r.count_events() == 0


def test_revoked_authorization_term_cuts_off_an_enrolled_agent(rig: Any) -> None:
    from app import cli

    r: Rig = rig()
    r.runner.cycle()
    cli.revoke_authorization(r.admin_engine, r.auth_id)
    r.fake_log.add(1)
    with pytest.raises(CredentialRejected):
        r.runner.cycle()
    assert r.store.stats()["queued_events"] == 1 and r.count_events() == 0


def test_core_rate_limit_is_respected_and_events_wait(rig: Any) -> None:
    r: Rig = rig(agent_events_per_minute=5)
    r.runner.cycle()
    for i in range(1, 9):
        r.fake_log.add(i)
    delay = r.runner.cycle()
    # O Core recusou o lote (8 eventos > 5/min): nada se perdeu e o agente espera.
    assert r.store.stats()["queued_events"] == 8 and r.count_events() == 0
    assert r.store.get("last_error") == "rate_limited" and delay >= 1


def test_agent_credential_cannot_read_events_or_act_as_a_human(rig: Any) -> None:
    r: Rig = rig()
    r.runner.cycle()
    r.fake_log.add(1)
    r.runner.cycle()
    anon = TestClient(r.core.app, base_url="https://testserver")
    headers = {"Authorization": f"Agent {r.credential}"}
    event_id = agent_event_id(r, 1)
    assert anon.get(f"/api/v1/events/{event_id}", headers=headers).status_code == 401
    assert anon.get("/api/v1/me", headers=headers).status_code == 401
    assert str(uuid.UUID(event_id)) == event_id
