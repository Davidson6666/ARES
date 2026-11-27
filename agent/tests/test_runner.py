import json
import logging
import random
import threading
from pathlib import Path
from typing import Any, cast

import pytest

from ares_agent import client as api
from ares_agent import log, mapping
from ares_agent.client import EventResult
from ares_agent.config import Config
from ares_agent.runner import CredentialRejected, Runner
from ares_agent.store import Store
from tests.helpers import AGENT_ID, event_xml, logon_failure


class FakeLog:
    """Security log sintético: ``read`` e ``latest`` no formato esperado pelo Runner."""

    def __init__(self) -> None:
        self.records: dict[int, str] = {}
        self.reads: list[tuple[int, int]] = []

    def add(self, record_id: int, xml: str | None = None) -> None:
        self.records[record_id] = xml or logon_failure(record_id)

    def read(self, after: int, limit: int) -> str:
        self.reads.append((after, limit))
        ids = sorted(i for i in self.records if i > after)[:limit]
        return "".join(self.records[i] for i in ids)

    def latest(self) -> int:
        return max(self.records, default=0)


class FakeClient:
    """Servidor sintético: ``script`` guarda o que cada chamada deve fazer."""

    def __init__(self) -> None:
        self.script: list[Exception | str] = []
        self.sent: list[list[dict[str, Any]]] = []
        self.heartbeats = 0
        self.outcome = "accepted"

    def post_events(self, events: list[dict[str, Any]]) -> list[EventResult]:
        step = self.script.pop(0) if self.script else "ok"
        if isinstance(step, Exception):
            raise step
        self.sent.append(events)
        return [EventResult(e["event_id"], self.outcome, None) for e in events]

    def heartbeat(self) -> None:
        step = self.script.pop(0) if self.script else "ok"
        if isinstance(step, Exception):
            raise step
        self.heartbeats += 1


class Clock:
    def __init__(self) -> None:
        self.t = 1000.0

    def __call__(self) -> float:
        return self.t


def build(
    tmp_path: Path,
    fake_log: FakeLog,
    client: FakeClient,
    *,
    max_events: int = 1000,
    poll: int = 15,
    clock: Clock | None = None,
) -> tuple[Runner, Store]:
    cfg = Config(
        server_url="http://127.0.0.1:8000",
        home=tmp_path,
        poll_interval_seconds=poll,
        queue_max_events=max_events,
    )
    store = Store(cfg.store_path, cfg.queue_max_events, cfg.queue_max_bytes)
    logger = log.setup(None, stderr=False)
    runner = Runner(
        cfg,
        store,
        cast(api.ServerClient, client),
        AGENT_ID,
        "endpoint",
        logger,
        read=fake_log.read,
        latest=fake_log.latest,
        monotonic=clock or Clock(),
        rng=random.Random(1),
    )
    return runner, store


def sent_ids(client: FakeClient) -> list[str]:
    return [e["event_id"] for batch in client.sent for e in batch]


def test_first_run_starts_from_now_and_does_not_read_history(tmp_path: Path) -> None:
    fake_log, client = FakeLog(), FakeClient()
    for i in range(1, 6):
        fake_log.add(i)  # histórico que NÃO deve ser coletado
    runner, store = build(tmp_path, fake_log, client)
    runner.cycle()
    assert store.get_int("collected_record_id") == 5
    assert client.sent == []
    fake_log.add(6)
    runner.cycle()
    assert [e["data"]["record_id"] for batch in client.sent for e in batch] == [6]


def test_events_flow_to_server_and_leave_the_queue_after_ack(tmp_path: Path) -> None:
    fake_log, client = FakeLog(), FakeClient()
    runner, store = build(tmp_path, fake_log, client)
    runner.cycle()
    for i in (1, 2, 3):
        fake_log.add(i)
    runner.cycle()
    (batch,) = client.sent
    assert [e["event_id"] for e in batch] == [mapping.make_event_id(AGENT_ID, i) for i in (1, 2, 3)]
    assert all(e["source"] == {"module": "endpoint", "instance_id": AGENT_ID} for e in batch)
    assert store.stats()["queued_events"] == 0
    assert store.get_int("collected_record_id") == 3
    assert store.get("last_error") == ""


def test_events_stay_queued_while_the_server_is_down(tmp_path: Path) -> None:
    fake_log, client = FakeLog(), FakeClient()
    runner, store = build(tmp_path, fake_log, client)
    runner.cycle()
    fake_log.add(1)
    client.script = [api.RetryLater("network")]
    delay = runner.cycle()
    assert store.stats()["queued_events"] == 1 and client.sent == []
    assert store.get("last_error") == "network"
    assert delay > 15  # recuo
    runner.cycle()  # o servidor voltou
    assert store.stats()["queued_events"] == 0 and len(client.sent) == 1


def test_backoff_grows_has_jitter_a_cap_and_honors_retry_after(tmp_path: Path) -> None:
    runner, _ = build(tmp_path, FakeLog(), FakeClient())
    delays = [runner._delay(False, None) for _ in range(10)]
    assert delays[1] > delays[0] * 1.2  # cresce
    assert max(delays) <= 300 * 1.2 + 0.01  # teto de 5 min (com jitter)
    assert len(set(delays[-3:])) == 3  # jitter: não repete o mesmo valor
    assert runner._delay(False, 900) >= 900  # Retry-After manda
    assert runner._delay(True, None) == 15 and runner.failures == 11


def test_a_good_cycle_resets_the_backoff(tmp_path: Path) -> None:
    fake_log, client = FakeLog(), FakeClient()
    runner, _ = build(tmp_path, fake_log, client)
    client.script = [api.RetryLater("network")] * 3
    for _ in range(3):
        runner.cycle()
    assert runner.failures == 3
    assert runner.cycle() == 15 and runner.failures == 0


def test_rate_limited_waits_at_least_retry_after(tmp_path: Path) -> None:
    fake_log, client = FakeLog(), FakeClient()
    runner, _ = build(tmp_path, fake_log, client)
    client.script = [api.RetryLater("rate_limited", 120)]
    assert runner.cycle() >= 120


def test_rejected_events_are_dropped_and_never_resent(tmp_path: Path) -> None:
    fake_log, client = FakeLog(), FakeClient()
    runner, store = build(tmp_path, fake_log, client)
    runner.cycle()
    fake_log.add(1)
    client.outcome = "rejected"
    runner.cycle()
    client.outcome = "accepted"
    runner.cycle()
    runner.cycle()
    assert len(client.sent) == 1  # só a primeira vez
    assert store.stats()["queued_events"] == 0 and store.stats()["rejected_total"] == 1


def test_duplicates_leave_the_queue(tmp_path: Path) -> None:
    fake_log, client = FakeLog(), FakeClient()
    runner, store = build(tmp_path, fake_log, client)
    runner.cycle()
    fake_log.add(1)
    client.outcome = "duplicate"
    runner.cycle()
    assert store.stats()["queued_events"] == 0 and store.stats()["rejected_total"] == 0


def test_401_stops_the_agent_and_keeps_the_events(tmp_path: Path) -> None:
    fake_log, client = FakeLog(), FakeClient()
    runner, store = build(tmp_path, fake_log, client)
    runner.cycle()
    fake_log.add(1)
    client.script = [api.Unauthorized()]
    with pytest.raises(CredentialRejected):
        runner.cycle()
    assert store.stats()["queued_events"] == 1
    assert store.get("last_error") == "credential_rejected"


def test_401_on_heartbeat_also_stops(tmp_path: Path) -> None:
    runner, _ = build(tmp_path, FakeLog(), FakeClient())
    runner.client = cast(api.ServerClient, _always_401())
    with pytest.raises(CredentialRejected):
        runner.cycle()


def _always_401() -> FakeClient:
    client = FakeClient()
    client.script = [api.Unauthorized()]
    return client


def test_run_loop_stops_on_credential_rejection(tmp_path: Path) -> None:
    runner, _ = build(tmp_path, FakeLog(), _always_401())
    with pytest.raises(CredentialRejected):
        runner.run(threading.Event())


def test_run_loop_exits_when_asked_to_stop(tmp_path: Path) -> None:
    runner, _ = build(tmp_path, FakeLog(), FakeClient())
    stop = threading.Event()
    stop.set()
    runner.run(stop)  # não entra no laço


def test_batch_refused_drops_that_batch_and_moves_on(tmp_path: Path) -> None:
    fake_log, client = FakeLog(), FakeClient()
    runner, store = build(tmp_path, fake_log, client)
    runner.cycle()
    fake_log.add(1)
    client.script = [api.BatchRefused(422, "validation_error")]
    runner.cycle()
    assert store.stats()["queued_events"] == 0 and store.stats()["batches_dropped_total"] == 1
    assert client.sent == []  # não repetiu o lote recusado
    fake_log.add(2)
    runner.cycle()
    assert len(client.sent) == 1


def test_batches_respect_the_configured_size(tmp_path: Path) -> None:
    fake_log, client = FakeLog(), FakeClient()
    runner, _ = build(tmp_path, fake_log, client)
    runner.cfg = Config(server_url=runner.cfg.server_url, home=tmp_path, batch_size=2)
    runner.cycle()
    for i in range(1, 6):
        fake_log.add(i)
    runner.cycle()
    assert [len(b) for b in client.sent] == [2, 2, 1]


def test_oversized_batches_are_split_by_bytes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from ares_agent import runner as runner_module

    monkeypatch.setattr(runner_module, "MAX_BATCH_BYTES", 1)  # um evento por lote
    fake_log, client = FakeLog(), FakeClient()
    runner, _ = build(tmp_path, fake_log, client)
    runner.cycle()
    for i in range(1, 4):
        fake_log.add(i)
    runner.cycle()
    assert [len(b) for b in client.sent] == [1, 1, 1]


def test_crash_between_collect_and_send_loses_nothing(tmp_path: Path) -> None:
    fake_log, client = FakeLog(), FakeClient()
    runner, store = build(tmp_path, fake_log, client)
    runner.cycle()
    fake_log.add(1)
    fake_log.add(2)
    runner._collect()  # coletou e gravou; o processo "morre" antes de enviar
    store.close()
    again, store2 = build(tmp_path, fake_log, client)
    again.cycle()
    assert [e["data"]["record_id"] for b in client.sent for e in b] == [1, 2]
    assert store2.get_int("collected_record_id") == 2


def test_losing_local_state_resends_same_event_ids(tmp_path: Path) -> None:
    fake_log = FakeLog()
    first_client = FakeClient()
    runner, _ = build(tmp_path / "a", fake_log, first_client)
    runner.cycle()
    fake_log.add(1)
    runner.cycle()
    # Estado local perdido: nova fila e novo marcador relendo os mesmos registros.
    second_client = FakeClient()
    fresh, fresh_store = build(tmp_path / "b", fake_log, second_client)
    fresh_store.put("collected_record_id", "0")
    fresh.cycle()
    assert sent_ids(first_client) == sent_ids(second_client) != []  # o servidor deduplica


def test_queue_overflow_is_reported_as_an_event(tmp_path: Path) -> None:
    fake_log, client = FakeLog(), FakeClient()
    runner, store = build(tmp_path, fake_log, client, max_events=100)
    runner.cycle()
    for i in range(1, 151):
        fake_log.add(i)
    client.script = [api.RetryLater("network")]  # nada sai neste ciclo
    runner.cycle()
    assert store.stats()["dropped_total"] > 0
    runner.cycle()
    sent = [e for b in client.sent for e in b]
    overflow = [e for e in sent if e["event_type"] == "agent.queue_overflow"]
    assert len(overflow) == 1 and overflow[0]["data"]["dropped"] == store.stats()["dropped_total"]
    assert store.report_overflow(lambda p, t: ("x", "x")) is False  # já avisado


def test_heartbeat_when_idle_but_not_while_sending(tmp_path: Path) -> None:
    fake_log, client, clock = FakeLog(), FakeClient(), Clock()
    runner, _ = build(tmp_path, fake_log, client, clock=clock)
    runner.cycle()
    assert client.heartbeats == 1  # primeiro ciclo: marca o agente como visto
    clock.t += 30
    runner.cycle()
    assert client.heartbeats == 1  # ainda dentro do intervalo de 60 s
    clock.t += 31
    runner.cycle()
    assert client.heartbeats == 2
    # Enviar evento já conta como contato: sem heartbeat extra.
    fake_log.add(1)
    clock.t += 59
    runner.cycle()
    assert len(client.sent) == 1 and client.heartbeats == 2
    clock.t += 59
    runner.cycle()
    assert client.heartbeats == 2


def test_events_that_cannot_be_mapped_are_counted_not_sent(tmp_path: Path) -> None:
    fake_log, client = FakeLog(), FakeClient()
    runner, store = build(tmp_path, fake_log, client)
    runner.cycle()
    fake_log.add(1, event_xml(4625, 1, {"TargetUserName": "x"}, when="ontem"))
    fake_log.add(2)
    runner.cycle()
    assert store.stats()["malformed_total"] == 1
    assert [e["data"]["record_id"] for b in client.sent for e in b] == [2]


def test_a_poison_record_does_not_block_collection(tmp_path: Path) -> None:
    fake_log, client = FakeLog(), FakeClient()
    runner, store = build(tmp_path, fake_log, client)
    runner.cycle()
    fake_log.add(1)
    fake_log.add(2, logon_failure(2).replace("</EventData></Event>", "</Event>"))  # XML quebrado
    fake_log.add(3)
    fake_log.add(4)
    runner.cycle()
    sent = sorted(e["data"]["record_id"] for b in client.sent for e in b)
    assert sent == [1, 3, 4]  # só o registro 2 ficou de fora
    assert store.stats()["malformed_total"] == 1
    assert store.get_int("collected_record_id") == 4


def test_unreadable_output_without_record_id_is_retried_with_backoff(tmp_path: Path) -> None:
    fake_log, client = FakeLog(), FakeClient()
    runner, store = build(tmp_path, fake_log, client)
    runner.cycle()
    fake_log.add(1, "<Event><sem-id")
    delay = runner.cycle()
    assert delay > 15 and store.get("last_error")
    assert store.get_int("collected_record_id") == 0


def test_logs_have_counts_and_codes_but_never_event_content_or_credentials(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    fake_log, client = FakeLog(), FakeClient()
    runner, _ = build(tmp_path, fake_log, client)
    logging.getLogger(log.NAME).propagate = True
    runner.cycle()
    fake_log.add(1, logon_failure(1, user="usuario-secreto-xyz"))
    with caplog.at_level(logging.INFO, logger=log.NAME):
        runner.cycle()
    text = json.dumps([r.getMessage() + str(getattr(r, "fields", "")) for r in caplog.records])
    assert "batch_sent" in text
    assert "usuario-secreto-xyz" not in text and "10.0.0.5" not in text


def test_log_cleared_resets_the_marker_and_does_not_collide_with_old_ids(tmp_path: Path) -> None:
    fake_log, client = FakeLog(), FakeClient()
    runner, store = build(tmp_path, fake_log, client)
    runner.cycle()
    for i in range(1, 6):
        fake_log.add(i)
    runner.cycle()
    old_ids = sent_ids(client)
    assert len(old_ids) == 5 and store.get_int("collected_record_id") == 5
    # Alguém limpa o Security log (EventID 1102): a numeração recomeça em 1.
    fake_log.records.clear()
    fake_log.add(1)
    fake_log.add(2)
    client.sent.clear()
    runner.cycle()
    types = [e["event_type"] for b in client.sent for e in b]
    assert "agent.log_reset" in types and types.count("authentication.failure") == 2
    new_ids = [
        e["event_id"] for b in client.sent for e in b if e["event_type"] != "agent.log_reset"
    ]
    assert not set(new_ids) & set(old_ids)  # ids novos: o servidor não diria `duplicate`
    assert store.stats()["log_resets_total"] == 1 and store.get_int("collected_record_id") == 2
    reset = next(e for b in client.sent for e in b if e["event_type"] == "agent.log_reset")
    assert reset["data"] == {"epoch": 1, "previous_record_id": 5}


def test_collection_lag_is_exposed(tmp_path: Path) -> None:
    fake_log, client = FakeLog(), FakeClient()
    runner, store = build(tmp_path, fake_log, client)
    runner.cycle()
    fake_log.add(1)
    client.script = ["ok"]
    runner.cycle()
    assert store.get_int("log_latest_record_id") == 1


def test_malformed_page_switches_to_one_by_one_for_the_rest_of_the_cycle(tmp_path: Path) -> None:
    fake_log, client = FakeLog(), FakeClient()
    runner, store = build(tmp_path, fake_log, client)
    runner.cycle()
    for i in range(1, 31):
        fake_log.add(i)
    fake_log.add(15, logon_failure(15).replace("</EventData></Event>", "</Event>"))
    fake_log.reads.clear()
    runner.cycle()
    assert store.stats()["malformed_total"] == 1
    assert sorted(e["data"]["record_id"] for b in client.sent for e in b) == [
        i for i in range(1, 31) if i != 15
    ]
    # Sem repetir a consulta grande a cada passo: no máximo uma de 200 e depois só de 1.
    big = [r for r in fake_log.reads if r[1] > 1]
    assert len(big) <= 2


def test_unexpected_exceptions_do_not_kill_the_agent(tmp_path: Path) -> None:
    fake_log, client = FakeLog(), FakeClient()
    runner, store = build(tmp_path, fake_log, client)
    runner.cycle()

    def broken_read(after: int, limit: int) -> str:
        raise RuntimeError("segredo-interno")

    runner.read = broken_read
    fake_log.add(1)
    assert runner.cycle() > 15  # recuo, sem exceção
    assert store.get("last_error") == "RuntimeError"  # só o tipo, nunca a mensagem

    class Exploding(FakeClient):
        def post_events(self, events: list[dict[str, Any]]) -> list[EventResult]:
            raise OSError("disco cheio")

    runner.read = fake_log.read
    runner.client = cast(api.ServerClient, Exploding())
    runner.last_contact = None
    assert runner.cycle() > 15 and store.get("last_error") == "OSError"


def test_flood_of_failed_logons_does_not_evict_account_creation(tmp_path: Path) -> None:
    fake_log, client = FakeLog(), FakeClient()
    runner, store = build(tmp_path, fake_log, client, max_events=100)
    runner.cycle()
    fake_log.add(1, event_xml(4720, 1, {"TargetUserName": "novo", "SubjectUserName": "adm"}))
    for i in range(2, 302):
        fake_log.add(i)  # 300 logons falhos depois
    client.script = [api.RetryLater("network")] * 5  # nada sai: a fila só enche
    runner.cycle()
    queued = [json.loads(q.payload)["event_type"] for q in store.peek(1000)]
    assert "account.created" in queued
    assert store.stats()["dropped_total"] > 0
