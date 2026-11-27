"""Ingestão e leitura de eventos (ADR 0006; testes de aceitação da seção 9.2)."""

import io
import json
import threading
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from typing import Any, cast

import pytest
from fastapi.testclient import TestClient
from httpx import Response
from sqlalchemy import Engine, select, text, update
from sqlalchemy.exc import DBAPIError
from sqlalchemy.orm import Session as DbSession

from app.agents.models import Agent
from app.auth.dependencies import CSRF_HEADER
from app.auth.models import User
from app.core.logging import configure_logging
from app.events.bus import PostgresEventBus
from app.events.models import Event, IdempotencyKey, IngestRecord
from tests.test_agents import (
    admin_headers,
    authorize,
    build_app,
    create_agent,
    enroll,
    enrolled_agent,
)
from tests.test_auth import PASSWORD, make_user

pytestmark = pytest.mark.db


def now_iso(delta: timedelta = timedelta()) -> str:
    return (datetime.now(UTC) + delta).strftime("%Y-%m-%dT%H:%M:%SZ")


def make_event(agent_id: str, **overrides: Any) -> dict[str, Any]:
    event: dict[str, Any] = {
        "event_id": str(uuid.uuid4()),
        "event_type": "authentication.failure",
        "schema_version": 1,
        "occurred_at": now_iso(),
        "source": {"module": "endpoint", "instance_id": agent_id},
        "data_classification": "internal",
        "data": {"user": "alice", "attempts": 3},
    }
    event.update(overrides)
    return event


def post_events(
    c: TestClient,
    credential: str | None,
    events: list[Any],
    key: str | None = "batch-1",
    **kwargs: Any,
) -> Response:
    headers = dict(kwargs.pop("headers", {}))
    if credential is not None:
        headers["Authorization"] = f"Agent {credential}"
    if key is not None:
        headers["Idempotency-Key"] = key
    return cast(
        Response, c.post("/api/v1/events", json={"events": events}, headers=headers, **kwargs)
    )


@pytest.fixture
def world(app_engine: Engine, admin_engine: Engine) -> Iterator[dict[str, Any]]:
    """Administrador logado + um agente enrolado, e um cliente anônimo para o agente."""
    app = build_app(app_engine)
    with TestClient(app, base_url="https://testserver") as human:
        headers = admin_headers(human, admin_engine)
        agent_id, credential = enrolled_agent(human, admin_engine, headers)
        with TestClient(app, base_url="https://testserver") as agent:
            yield {
                "app": app,
                "human": human,
                "agent": agent,
                "headers": headers,
                "agent_id": agent_id,
                "credential": credential,
                "engine": admin_engine,
            }


def _without_request_id(r: Response) -> dict[str, Any]:
    return {k: v for k, v in r.json().items() if k != "request_id"}


def stored_events(engine: Engine) -> list[Event]:
    with DbSession(engine) as db:
        return list(db.scalars(select(Event).order_by(Event.observed_at, Event.event_id)))


# --- caminho feliz ---------------------------------------------------------


def test_accepts_valid_batch_and_stores_it(world: dict[str, Any]) -> None:
    ev = make_event(world["agent_id"], severity="high", device_id="dev-1", correlation_id="c-1")
    r = post_events(world["agent"], world["credential"], [ev])
    assert r.status_code == 202
    assert r.json() == {
        "accepted": 1,
        "duplicate": 0,
        "rejected": 0,
        "results": [
            {"event_id": ev["event_id"], "outcome": "accepted", "error_code": None, "field": None}
        ],
    }
    [row] = stored_events(world["engine"])
    assert str(row.event_id) == ev["event_id"]
    assert (row.event_type, row.severity, row.device_id, row.correlation_id) == (
        "authentication.failure",
        "high",
        "dev-1",
        "c-1",
    )
    assert row.data == {"user": "alice", "attempts": 3} and row.flags == []
    assert str(row.agent_id) == world["agent_id"] and row.tenant_id is None
    with DbSession(world["engine"]) as db:
        rec = db.get(IngestRecord, row.event_id)
        assert rec is not None and rec.outcome == "accepted" and rec.source_id == world["agent_id"]
        agent = db.get(Agent, uuid.UUID(world["agent_id"]))
        assert agent is not None and agent.last_seen_at is not None


def test_observed_at_is_set_by_the_server(world: dict[str, Any]) -> None:
    old = make_event(world["agent_id"], occurred_at="2020-01-01T00:00:00Z")
    post_events(world["agent"], world["credential"], [old])
    [row] = stored_events(world["engine"])
    assert row.occurred_at.year == 2020
    assert abs((datetime.now(UTC) - row.observed_at).total_seconds()) < 30


def test_unknown_fields_inside_data_are_preserved(world: dict[str, Any]) -> None:
    ev = make_event(world["agent_id"], data={"novo_campo": {"a": [1, 2, None]}, "x": "y"})
    assert post_events(world["agent"], world["credential"], [ev]).json()["accepted"] == 1
    assert stored_events(world["engine"])[0].data == ev["data"]


def test_ingestion_is_not_audited_per_request(world: dict[str, Any]) -> None:
    post_events(world["agent"], world["credential"], [make_event(world["agent_id"])])
    with world["engine"].connect() as conn:
        actions = [r[0] for r in conn.execute(text("SELECT action FROM audit_logs"))]
    assert not any(a.startswith(("event", "ingest")) for a in actions)


# --- autenticação e forma da requisição ---------------------------------------


def test_requires_agent_credential(world: dict[str, Any]) -> None:
    ev = [make_event(world["agent_id"])]
    anon = TestClient(world["app"], base_url="https://testserver")
    assert post_events(anon, None, ev).status_code == 401
    # Sessão de humano não vale na ingestão.
    assert post_events(world["human"], None, ev, headers=world["headers"]).status_code == 401
    assert stored_events(world["engine"]) == []


def test_revoked_agent_cannot_ingest_immediately(world: dict[str, Any]) -> None:
    """9.2: credencial revogada, 401 imediato."""
    ev = [make_event(world["agent_id"])]
    assert post_events(world["agent"], world["credential"], ev, key="a").status_code == 202
    r = world["human"].post(f"/api/v1/agents/{world['agent_id']}/revoke", headers=world["headers"])
    assert r.status_code == 200
    r = post_events(world["agent"], world["credential"], [make_event(world["agent_id"])], key="b")
    assert r.status_code == 401
    assert len(stored_events(world["engine"])) == 1


def test_request_shape_errors(world: dict[str, Any]) -> None:
    c, cred, aid = world["agent"], world["credential"], world["agent_id"]
    ev = [make_event(aid)]
    assert post_events(c, cred, ev, key=None).json()["code"] == "idempotency_key_required"
    assert post_events(c, cred, ev, key="a b").status_code == 400
    assert post_events(c, cred, ev, params={"x": 1}).json()["code"] == "unknown_query_parameter"
    h = {"Authorization": f"Agent {cred}", "Idempotency-Key": "k"}
    r = c.post("/api/v1/events", content=b"x", headers={**h, "Content-Type": "text/plain"})
    assert r.status_code == 400 and r.json()["code"] == "unsupported_content_type"
    r = c.post(
        "/api/v1/events", content=b"{nao e json", headers={**h, "Content-Type": "application/json"}
    )
    assert r.status_code == 400 and r.json()["code"] == "malformed_request"
    # NaN e Infinity não são JSON válido.
    r = c.post(
        "/api/v1/events",
        content=b'{"events":[{"data":{"x":NaN}}]}',
        headers={**h, "Content-Type": "application/json"},
    )
    assert r.status_code == 400
    assert stored_events(world["engine"]) == []


@pytest.mark.parametrize(
    "payload",
    [
        [],
        [{"a": 1}],
        {"events": "x"},
        {"events": {}},
        {"events": [], "extra": 1},
        {"evts": []},
        "texto",
        7,
    ],
)
def test_batch_shape_is_422(world: dict[str, Any], payload: Any) -> None:
    h = {"Authorization": f"Agent {world['credential']}", "Idempotency-Key": "k"}
    r = world["agent"].post("/api/v1/events", json=payload, headers=h)
    assert r.status_code == 422
    assert r.json()["code"] in {"validation_error", "empty_batch"}


def test_batch_limits(world: dict[str, Any]) -> None:
    aid = world["agent_id"]
    r = post_events(world["agent"], world["credential"], [make_event(aid) for _ in range(101)])
    assert r.status_code == 422 and r.json()["code"] == "batch_too_large"
    r = post_events(
        world["agent"], world["credential"], [make_event(aid) for _ in range(100)], key="ok"
    )
    assert r.status_code == 202 and r.json()["accepted"] == 100


def test_body_over_2mb_is_413_even_when_chunked(world: dict[str, Any]) -> None:
    h = {
        "Authorization": f"Agent {world['credential']}",
        "Idempotency-Key": "big",
        "Content-Type": "application/json",
    }
    big = b'{"events":[' + b"0," * (1024 * 1024 + 10) + b"0]}"
    r = world["agent"].post("/api/v1/events", content=big, headers=h)
    assert r.status_code == 413 and r.json()["code"] == "payload_too_large"

    def chunks() -> Iterator[bytes]:  # sem Content-Length: lido por pedaços
        for i in range(0, len(big), 65536):
            yield big[i : i + 65536]

    r = world["agent"].post("/api/v1/events", content=chunks(), headers=h)
    assert r.status_code == 413
    assert stored_events(world["engine"]) == []


# --- validação do envelope, por evento ---------------------------------------


def _drop(field: str) -> Any:
    return lambda ev: {k: v for k, v in ev.items() if k != field}


@pytest.mark.parametrize(
    ("mutate", "code", "field"),
    [
        (_drop("event_id"), "missing_field", "event_id"),
        (_drop("event_type"), "missing_field", "event_type"),
        (_drop("schema_version"), "missing_field", "schema_version"),
        (_drop("occurred_at"), "missing_field", "occurred_at"),
        (_drop("source"), "missing_field", "source"),
        (_drop("data_classification"), "missing_field", "data_classification"),
        (_drop("data"), "missing_field", "data"),
        (lambda ev: ev | {"observed_at": now_iso()}, "observed_at_not_allowed", "observed_at"),
        (lambda ev: ev | {"role": "admin"}, "unknown_field", "role"),
        (lambda ev: ev | {"source": {**ev["source"], "x": 1}}, "unknown_field", "source.x"),
        (lambda ev: ev | {"schema_version": 2}, "unsupported_schema_version", "schema_version"),
        (lambda ev: ev | {"schema_version": 0}, "invalid_field", "schema_version"),
        (lambda ev: ev | {"schema_version": "1"}, "invalid_field", "schema_version"),
        (lambda ev: ev | {"schema_version": True}, "invalid_field", "schema_version"),
        (lambda ev: ev | {"event_type": "Auth.Fail"}, "invalid_field", "event_type"),
        (lambda ev: ev | {"event_type": "semponto"}, "invalid_field", "event_type"),
        (lambda ev: ev | {"occurred_at": "2026-11-26T19:04:00"}, "invalid_field", "occurred_at"),
        (lambda ev: ev | {"occurred_at": 1764000000}, "invalid_field", "occurred_at"),
        (lambda ev: ev | {"occurred_at": "ontem"}, "invalid_field", "occurred_at"),
        (lambda ev: ev | {"data_classification": "secret"}, "invalid_field", "data_classification"),
        (lambda ev: ev | {"data": [1, 2]}, "invalid_field", "data"),
        (lambda ev: ev | {"severity": "extreme"}, "invalid_field", "severity"),
        (lambda ev: ev | {"event_id": "não-é-uuid"}, "invalid_field", "event_id"),
        (lambda ev: ev | {"event_id": 123}, "invalid_field", "event_id"),
        (lambda ev: ev | {"correlation_id": "a\nb"}, "invalid_field", "correlation_id"),
        (lambda ev: ev | {"device_id": ""}, "invalid_field", "device_id"),
        (lambda ev: ev | {"tenant_id": "T9"}, "tenant_mismatch", "tenant_id"),
        (
            lambda ev: ev | {"source": {**ev["source"], "module": "network"}},
            "source_mismatch",
            "source",
        ),
        (
            lambda ev: ev | {"source": {**ev["source"], "instance_id": str(uuid.uuid4())}},
            "source_mismatch",
            "source",
        ),
        (lambda ev: ev | {"data": {"x": "a\u0000b"}}, "invalid_data", None),
    ],
)
def test_invalid_events_are_rejected_with_stable_codes(
    world: dict[str, Any], mutate: Any, code: str, field: str | None
) -> None:
    ev = mutate(make_event(world["agent_id"]))
    r = post_events(world["agent"], world["credential"], [ev])
    assert r.status_code == 202
    [item] = r.json()["results"]
    assert (item["outcome"], item["error_code"]) == ("rejected", code)
    if field is not None:
        assert item["field"] == field
    assert stored_events(world["engine"]) == []
    # O valor enviado nunca volta na resposta.
    assert "role" not in r.text or code == "unknown_field"


def test_partial_batch_keeps_valid_events(world: dict[str, Any]) -> None:
    aid = world["agent_id"]
    good1, good2 = make_event(aid), make_event(aid)
    bad = make_event(aid, schema_version=9)
    r = post_events(world["agent"], world["credential"], [good1, bad, "texto", good2, {"x": 1}])
    body = r.json()
    assert (body["accepted"], body["duplicate"], body["rejected"]) == (2, 0, 3)
    assert [i["outcome"] for i in body["results"]] == [
        "accepted",
        "rejected",
        "rejected",
        "accepted",
        "rejected",
    ]
    assert (
        body["results"][2]["error_code"] == "invalid_event"
        and body["results"][2]["event_id"] is None
    )
    assert {str(e.event_id) for e in stored_events(world["engine"])} == {
        good1["event_id"],
        good2["event_id"],
    }


def test_event_and_data_size_limits(world: dict[str, Any]) -> None:
    aid = world["agent_id"]
    fat_data = make_event(aid, data={"blob": "x" * (16 * 1024)})
    fat_event = make_event(
        aid,
        data={
            "a": "x" * 9000,
            "b": "y" * 9000,
            "c": "z" * 9000,
            "d": "w" * 9000,
            "e": "v" * 9000,
            "f": "u" * 9000,
            "g": "t" * 9000,
            "h": "s" * 9000,
        },
    )
    ok = make_event(aid, data={"blob": "x" * 15000})
    r = post_events(world["agent"], world["credential"], [fat_data, fat_event, ok])
    codes = [(i["outcome"], i["error_code"]) for i in r.json()["results"]]
    assert codes[0] == ("rejected", "data_too_large")
    assert codes[1][0] == "rejected" and codes[1][1] in {"event_too_large", "data_too_large"}
    assert codes[2] == ("accepted", None)


def test_deeply_nested_data_is_rejected_not_a_crash(world: dict[str, Any]) -> None:
    nested: Any = "x"
    for _ in range(50):
        nested = {"a": nested}
    r = post_events(
        world["agent"], world["credential"], [make_event(world["agent_id"], data=nested)]
    )
    assert r.status_code == 202
    assert r.json()["results"][0]["error_code"] == "invalid_data"


# --- deduplicação -----------------------------------------------------------


def test_duplicates_across_batches_and_within_a_batch(world: dict[str, Any]) -> None:
    aid = world["agent_id"]
    ev = make_event(aid)
    first = post_events(world["agent"], world["credential"], [ev, ev], key="k1")
    assert [i["outcome"] for i in first.json()["results"]] == ["accepted", "duplicate"]
    again = post_events(world["agent"], world["credential"], [ev], key="k2")
    assert again.json()["results"][0]["outcome"] == "duplicate"
    assert len(stored_events(world["engine"])) == 1


def test_event_id_of_another_agent_is_not_a_duplicate(world: dict[str, Any]) -> None:
    human, headers, engine = world["human"], world["headers"], world["engine"]
    other_id, other_cred = enrolled_agent(human, engine, headers, key="o", name="outro")
    victim = make_event(world["agent_id"])
    assert post_events(world["agent"], world["credential"], [victim]).json()["accepted"] == 1
    stolen = dict(victim, source={"module": "endpoint", "instance_id": other_id})
    r = post_events(world["agent"], other_cred, [stolen], key="x")
    assert r.json()["results"][0]["error_code"] == "event_id_conflict"
    [row] = stored_events(engine)
    assert str(row.agent_id) == world["agent_id"]  # o original não foi tocado


# --- idempotência -----------------------------------------------------------


def test_idempotent_replay_returns_same_response_without_reprocessing(
    world: dict[str, Any],
) -> None:
    aid = world["agent_id"]
    batch = [make_event(aid), make_event(aid, schema_version=5)]
    first = post_events(world["agent"], world["credential"], batch, key="idem")
    again = post_events(world["agent"], world["credential"], batch, key="idem")
    assert again.status_code == 202 and again.headers["idempotent-replay"] == "true"
    assert again.json() == first.json()
    assert len(stored_events(world["engine"])) == 1


def test_same_key_with_different_body_is_409(world: dict[str, Any]) -> None:
    aid = world["agent_id"]
    post_events(world["agent"], world["credential"], [make_event(aid)], key="same")
    r = post_events(world["agent"], world["credential"], [make_event(aid)], key="same")
    assert r.status_code == 409 and r.json()["code"] == "idempotency_key_reused"
    assert len(stored_events(world["engine"])) == 1


def test_idempotency_keys_are_per_agent(world: dict[str, Any]) -> None:
    other_id, other_cred = enrolled_agent(
        world["human"], world["engine"], world["headers"], key="o2", name="b"
    )
    a = post_events(
        world["agent"], world["credential"], [make_event(world["agent_id"])], key="shared"
    )
    b = post_events(world["agent"], other_cred, [make_event(other_id)], key="shared")
    assert a.status_code == b.status_code == 202 and b.headers.get("idempotent-replay") is None


def test_concurrent_requests_with_same_key_process_once(world: dict[str, Any]) -> None:
    batch = [make_event(world["agent_id"]) for _ in range(5)]
    barrier = threading.Barrier(2)
    responses: list[Response] = []

    def send() -> None:
        with TestClient(world["app"], base_url="https://testserver") as c:
            barrier.wait()
            responses.append(post_events(c, world["credential"], batch, key="race"))

    threads = [threading.Thread(target=send) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert [r.status_code for r in responses] == [202, 202]
    assert responses[0].json() == responses[1].json()
    assert len(stored_events(world["engine"])) == 5


def test_expired_idempotency_key_is_accepted_again(world: dict[str, Any]) -> None:
    ev = [make_event(world["agent_id"])]
    post_events(world["agent"], world["credential"], ev, key="old")
    with DbSession(world["engine"]) as db:
        db.execute(
            update(IdempotencyKey).values(expires_at=datetime.now(UTC) - timedelta(seconds=1))
        )
        db.commit()
    r = post_events(world["agent"], world["credential"], ev, key="old")
    assert r.status_code == 202 and r.headers.get("idempotent-replay") is None
    assert r.json()["results"][0]["outcome"] == "duplicate"


# --- atomicidade e recuperação ----------------------------------------------


def test_failed_batch_leaves_no_partial_state_and_retry_works(world: dict[str, Any]) -> None:
    bus = world["app"].state.event_bus
    original = PostgresEventBus.publish

    class Boom(PostgresEventBus):
        def publish(self, db: Any, agent: Any, events: Any, observed_at: Any) -> Any:
            original(self, db, agent, events[:1], observed_at)  # grava um e quebra
            raise RuntimeError("falha simulada no meio do lote")

    world["app"].state.event_bus = Boom()
    batch = [make_event(world["agent_id"]) for _ in range(3)]
    with TestClient(
        world["app"], base_url="https://testserver", raise_server_exceptions=False
    ) as c:
        r = post_events(c, world["credential"], batch, key="retry")
    assert r.status_code == 500 and r.json()["code"] == "internal_error"
    with DbSession(world["engine"]) as db:
        assert db.scalar(select(Event.event_id)) is None  # nada ficou
        assert db.scalar(select(IngestRecord.event_id)) is None
        assert (
            db.scalar(select(IdempotencyKey.key).where(IdempotencyKey.principal_type == "agent"))
            is None
        )

    world["app"].state.event_bus = bus
    ok = post_events(world["agent"], world["credential"], batch, key="retry")
    assert ok.status_code == 202 and ok.json()["accepted"] == 3
    assert len(stored_events(world["engine"])) == 3


def test_app_role_cannot_update_or_delete_events(world: dict[str, Any], app_engine: Engine) -> None:
    post_events(world["agent"], world["credential"], [make_event(world["agent_id"])])
    for stmt in ("UPDATE events SET severity = 'low'", "DELETE FROM events", "TRUNCATE events"):
        with app_engine.connect() as conn, pytest.raises(DBAPIError, match="permission denied"):
            conn.execute(text(stmt))
    assert len(stored_events(world["engine"])) == 1


# --- limite por agente (9.2: inundação) ---------------------------------------


def test_flooding_agent_gets_429_without_hurting_others(
    app_engine: Engine, admin_engine: Engine
) -> None:
    app = build_app(app_engine, agent_events_per_minute=10, agent_requests_per_minute=1000)
    with TestClient(app, base_url="https://testserver") as human:
        headers = admin_headers(human, admin_engine)
        a_id, a_cred = enrolled_agent(human, admin_engine, headers, key="a", name="a")
        b_id, b_cred = enrolled_agent(human, admin_engine, headers, key="b", name="b")
        with TestClient(app, base_url="https://testserver") as c:
            assert (
                post_events(c, a_cred, [make_event(a_id) for _ in range(10)], key="1").status_code
                == 202
            )
            r = post_events(c, a_cred, [make_event(a_id)], key="2")
            assert r.status_code == 429 and r.json()["code"] == "rate_limited"
            assert int(r.headers["Retry-After"]) >= 1
            # O agente B não é afetado.
            assert post_events(c, b_cred, [make_event(b_id)], key="3").status_code == 202
            # Lote maior que o limite inteiro nunca cabe.
            big = post_events(c, b_cred, [make_event(b_id) for _ in range(11)], key="4")
            assert big.status_code == 429
    assert len(stored_events(admin_engine)) == 11  # só o que foi aceito


def test_request_rate_limit_per_agent(app_engine: Engine, admin_engine: Engine) -> None:
    app = build_app(app_engine, agent_requests_per_minute=2)
    with TestClient(app, base_url="https://testserver") as human:
        headers = admin_headers(human, admin_engine)
        a_id, a_cred = enrolled_agent(human, admin_engine, headers)
        with TestClient(app, base_url="https://testserver") as c:
            codes = [
                post_events(c, a_cred, [make_event(a_id)], key=f"k{i}").status_code
                for i in range(3)
            ]
    assert codes == [202, 202, 429]


# --- timestamp futuro, XSS armazenado, log, escopo (9.2) ------------------------


def test_far_future_timestamp_is_accepted_and_flagged(world: dict[str, Any]) -> None:
    aid = world["agent_id"]
    future = make_event(aid, occurred_at=now_iso(timedelta(days=30)))
    near = make_event(aid, occurred_at=now_iso(timedelta(seconds=60)))
    r = post_events(world["agent"], world["credential"], [future, near])
    assert r.json()["accepted"] == 2
    flags = {str(e.event_id): e.flags for e in stored_events(world["engine"])}
    assert flags[future["event_id"]] == ["occurred_at_future"]
    assert flags[near["event_id"]] == []


def test_stored_xss_payload_comes_back_as_json_data(world: dict[str, Any]) -> None:
    payload = "<script>alert(1)</script><img src=x onerror=alert(1)>"
    ev = make_event(world["agent_id"], data={"msg": payload, "<b>k</b>": payload})
    assert post_events(world["agent"], world["credential"], [ev]).json()["accepted"] == 1
    r = world["human"].get(f"/api/v1/events/{ev['event_id']}")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("application/json")
    assert r.json()["data"] == {"msg": payload, "<b>k</b>": payload}  # texto, intacto


def test_newline_in_event_data_cannot_forge_log_lines(world: dict[str, Any]) -> None:
    buf = io.StringIO()
    configure_logging("INFO", stream=buf)
    try:
        evil = 'a\n{"level":"critical","event":"forjado"}\r\nb'
        ev = make_event(world["agent_id"], data={"msg": evil})
        world["agent"].post  # noqa: B018
        with TestClient(world["app"], base_url="https://testserver") as c:
            configure_logging("INFO", stream=buf)  # create_app reconfigura
            post_events(c, world["credential"], [ev])
    finally:
        text_out = buf.getvalue()
        configure_logging("INFO")
    lines = [ln for ln in text_out.splitlines() if ln]
    assert lines and all(json.loads(ln) for ln in lines)  # toda linha é um JSON
    assert not any(json.loads(ln).get("event") == "forjado" for ln in lines)
    assert "forjado" not in text_out  # o conteúdo do evento nem vai para o log


def test_stored_events_are_scoped_idor(app_engine: Engine, admin_engine: Engine) -> None:
    """9.2: usuário A não lê evento de escopo de B (404)."""
    app = build_app(app_engine)
    with TestClient(app, base_url="https://testserver") as admin:
        headers = admin_headers(admin, admin_engine)
        auth_id = authorize(admin_engine)
        creds = {}
        for tenant in ("T1", "T2"):
            tok = create_agent(
                admin, headers, auth_id, key=f"t-{tenant}", name=tenant, tenant_id=tenant
            ).json()
            cred = enroll(admin, tok["enrollment_token"]).json()["credential"]
            creds[tenant] = (tok["agent_id"], cred)
        ids = {}
        with TestClient(app, base_url="https://testserver") as agent:
            for tenant, (aid, cred) in creds.items():
                ev = make_event(aid, tenant_id=tenant)
                assert post_events(agent, cred, [ev], key=f"e-{tenant}").json()["accepted"] == 1
                ids[tenant] = ev["event_id"]
        assert {e.tenant_id for e in stored_events(admin_engine)} == {"T1", "T2"}

        for email, tenant in (("u1@ares.test", "T1"), ("u2@ares.test", "T2")):
            uid = make_user(admin_engine, email, roles=("viewer",))
            with DbSession(admin_engine) as db:
                db.execute(update(User).where(User.id == uid).values(tenant_id=tenant))
                db.commit()
        with TestClient(app, base_url="https://testserver") as u1:
            u1.post("/api/v1/auth/login", json={"email": "u1@ares.test", "password": PASSWORD})
            assert u1.get(f"/api/v1/events/{ids['T1']}").status_code == 200
            foreign = u1.get(f"/api/v1/events/{ids['T2']}")
            missing = u1.get(f"/api/v1/events/{uuid.uuid4()}")
            assert foreign.status_code == missing.status_code == 404
            assert _without_request_id(foreign) == _without_request_id(missing)  # indistinguível
        # Administrador sem escopo lê os dois.
        assert admin.get(f"/api/v1/events/{ids['T1']}").status_code == 200
        assert admin.get(f"/api/v1/events/{ids['T2']}").status_code == 200


def test_get_event_access_rules(world: dict[str, Any]) -> None:
    ev = make_event(world["agent_id"])
    post_events(world["agent"], world["credential"], [ev])
    url = f"/api/v1/events/{ev['event_id']}"
    anon = TestClient(world["app"], base_url="https://testserver")
    assert anon.get(url).status_code == 401
    assert (
        anon.get(url, headers={"Authorization": f"Agent {world['credential']}"}).status_code == 401
    )
    make_user(world["engine"], "noroles@ares.test")
    anon.post("/api/v1/auth/login", json={"email": "noroles@ares.test", "password": PASSWORD})
    assert anon.get(url).status_code == 403  # sem events.read
    assert world["human"].get(f"/api/v1/events/{uuid.uuid4()}").status_code == 404
    assert world["human"].get("/api/v1/events/nao-e-uuid").status_code == 422
    assert world["human"].get(url, params={"x": 1}).json()["code"] == "unknown_query_parameter"
    body = world["human"].get(url).json()
    assert body["event_id"] == ev["event_id"] and body["flags"] == []
    assert body["observed_at"] and body["agent_id"] == world["agent_id"]
    assert CSRF_HEADER not in body
