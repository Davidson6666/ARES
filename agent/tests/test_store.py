from pathlib import Path

import pytest

from ares_agent.store import Item, Store


def make(tmp_path: Path, max_events: int = 100, max_bytes: int = 10_000_000) -> Store:
    return Store(tmp_path / "state.db", max_events, max_bytes)


def items(n: int, start: int = 0, size: int = 10, priority: int = 1) -> list[Item]:
    return [(f"id-{i}", "x" * size, priority) for i in range(start, start + n)]


def test_enqueue_peek_ack_in_order(tmp_path: Path) -> None:
    store = make(tmp_path)
    store.enqueue(items(5), collected_record_id=50)
    queued = store.peek(3)
    assert [q.event_id for q in queued] == ["id-0", "id-1", "id-2"]
    store.ack([q.seq for q in queued])
    assert [q.event_id for q in store.peek(10)] == ["id-3", "id-4"]
    assert store.get_int("collected_record_id") == 50


def test_duplicate_event_ids_are_ignored(tmp_path: Path) -> None:
    store = make(tmp_path)
    store.enqueue(items(3))
    store.enqueue(items(3))
    assert store.stats()["queued_events"] == 3


def test_state_survives_reopen(tmp_path: Path) -> None:
    store = make(tmp_path)
    store.enqueue(items(4), collected_record_id=9)
    store.put("agent_id", "abc")
    store.close()
    again = make(tmp_path)
    assert again.stats()["queued_events"] == 4
    assert again.get("agent_id") == "abc" and again.get_int("collected_record_id") == 9


def test_full_queue_drops_the_oldest_and_counts(tmp_path: Path) -> None:
    store = make(tmp_path, max_events=100)
    assert store.enqueue(items(100)) == 0
    assert store.enqueue(items(30, start=100)) == 30
    ids = [q.event_id for q in store.peek(1000)]
    assert len(ids) == 100
    assert ids[0] == "id-30" and ids[-1] == "id-129"  # os mais antigos saíram
    assert store.stats()["dropped_total"] == 30


def test_flood_of_low_priority_does_not_evict_important_events(tmp_path: Path) -> None:
    store = make(tmp_path, max_events=10)
    store.enqueue([("conta-criada", "x", 1), ("grupo", "x", 1)])
    # Inundação de logons falhos (prioridade 0): enche e descarta os próprios logons.
    dropped = store.enqueue(items(30, priority=0))
    assert dropped == 22
    ids = {q.event_id for q in store.peek(100)}
    assert {"conta-criada", "grupo"} <= ids
    assert store.stats()["queued_events"] == 10


def test_size_limit_also_drops_the_oldest(tmp_path: Path) -> None:
    store = make(tmp_path, max_events=1000, max_bytes=100)
    dropped = store.enqueue(items(15, size=10))
    assert dropped == 5
    stats = store.stats()
    assert stats["queued_events"] == 10 and stats["queued_bytes"] == 100
    assert store.peek(1)[0].event_id == "id-5"


def test_single_oversized_item_is_dropped_not_stuck(tmp_path: Path) -> None:
    store = make(tmp_path, max_bytes=50)
    assert store.enqueue([("big", "x" * 500, 1)]) == 1
    assert store.stats()["queued_events"] == 0


def test_bookmark_and_queue_move_together_on_failure(tmp_path: Path) -> None:
    store = make(tmp_path)
    store.enqueue(items(2), collected_record_id=5)
    with pytest.raises(AttributeError):
        store.enqueue([("ok", "payload", 1), ("bad", None, 1)], collected_record_id=99)  # type: ignore[list-item]
    # Nada da chamada que falhou ficou: nem o evento bom, nem o marcador.
    assert store.stats()["queued_events"] == 2
    assert store.get_int("collected_record_id") == 5


def test_counters(tmp_path: Path) -> None:
    store = make(tmp_path)
    store.add("rejected_total", 2)
    store.add("rejected_total", 3)
    store.add("malformed_total", 1)
    stats = store.stats()
    assert stats["rejected_total"] == 5 and stats["malformed_total"] == 1


def test_overflow_notice_is_atomic_and_does_not_cascade(tmp_path: Path) -> None:
    store = make(tmp_path, max_events=10)
    store.enqueue(items(10))
    assert store.report_overflow(lambda p, t: ("aviso", "x")) is False  # nada a avisar
    store.enqueue(items(5, start=50))  # descarta 5
    built: list[tuple[int, int]] = []

    def build(pending: int, total: int) -> tuple[str, str]:
        built.append((pending, total))
        return "aviso", "x"

    assert store.report_overflow(build) is True
    assert built == [(5, 5)]
    # O aviso entra sem descartar outro evento (senão cada aviso geraria um novo).
    assert store.stats()["queued_events"] == 11 and store.stats()["dropped_total"] == 5
    assert store.report_overflow(build) is False  # só avisa uma vez
    # E é o último a ser descartado quando a fila volta a encher.
    store.enqueue(items(20, start=100))
    assert "aviso" in {q.event_id for q in store.peek(100)}


def test_overflow_notice_rolls_back_with_a_failure_in_build(tmp_path: Path) -> None:
    store = make(tmp_path, max_events=10)
    store.enqueue(items(15))

    def broken(pending: int, total: int) -> tuple[str, str]:
        raise RuntimeError("falha")

    with pytest.raises(RuntimeError):
        store.report_overflow(broken)
    # O contador não foi zerado: o aviso ainda será dado.
    assert store.report_overflow(lambda p, t: ("aviso", "x")) is True


def test_reset_for_new_enrollment_clears_queue_and_marker(tmp_path: Path) -> None:
    store = make(tmp_path)
    store.enqueue(items(4), collected_record_id=77)
    store.put("agent_id", "velho")
    assert store.reset_for_new_enrollment() == 4
    assert store.stats()["queued_events"] == 0
    assert store.get("collected_record_id") is None
    assert store.get("agent_id") == "velho"  # quem chama grava a identidade nova
