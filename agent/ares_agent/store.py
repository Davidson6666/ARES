"""Estado local do agente: marcador de coleta e fila limitada (SQLite, ADR 0007).

A fila é a camada durável: o marcador de coleta (``collected_record_id``) só avança
na mesma transação em que os eventos entram na fila, e a linha da fila só sai
depois do ack do servidor. Fila cheia descarta primeiro os de MENOR prioridade e,
dentro da mesma prioridade, os mais antigos (uma inundação de logons falhos não
expulsa a criação de conta ou a mudança de grupo).
"""

import sqlite3
from collections.abc import Callable, Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

_SCHEMA = """
CREATE TABLE IF NOT EXISTS kv (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS queue (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id TEXT NOT NULL UNIQUE,
    size INTEGER NOT NULL,
    priority INTEGER NOT NULL DEFAULT 1,
    payload TEXT NOT NULL
);
"""

DROPPED_TOTAL = "queue_dropped_total"
DROPPED_PENDING = "queue_dropped_pending"

# (event_id, payload, prioridade): prioridade maior sobrevive ao descarte.
Item = tuple[str, str, int]


@dataclass(frozen=True)
class Queued:
    seq: int
    event_id: str
    size: int
    payload: str


class Store:
    def __init__(self, path: Path, max_events: int, max_bytes: int) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self._max_events = max_events
        self._max_bytes = max_bytes
        # isolation_level=None: transações explícitas (BEGIN IMMEDIATE).
        self._db = sqlite3.connect(path, isolation_level=None)
        self._db.execute("PRAGMA synchronous=FULL")
        self._db.executescript(_SCHEMA)

    def close(self) -> None:
        self._db.close()

    @contextmanager
    def _tx(self) -> Iterator[sqlite3.Connection]:
        self._db.execute("BEGIN IMMEDIATE")
        try:
            yield self._db
        except BaseException:
            self._db.execute("ROLLBACK")
            raise
        self._db.execute("COMMIT")

    # --- chave/valor -----------------------------------------------------------

    def get(self, key: str) -> str | None:
        row = self._db.execute("SELECT value FROM kv WHERE key = ?", (key,)).fetchone()
        return None if row is None else str(row[0])

    def get_int(self, key: str, default: int = 0) -> int:
        value = self.get(key)
        return default if value is None else int(value)

    def put(self, key: str, value: str) -> None:
        with self._tx() as db:
            self._put(db, key, value)

    @staticmethod
    def _put(db: sqlite3.Connection, key: str, value: str) -> None:
        db.execute(
            "INSERT INTO kv(key, value) VALUES(?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, value),
        )

    def add(self, key: str, amount: int) -> None:
        with self._tx() as db:
            self._add(db, key, amount)

    def _add(self, db: sqlite3.Connection, key: str, amount: int) -> None:
        row = db.execute("SELECT value FROM kv WHERE key = ?", (key,)).fetchone()
        self._put(db, key, str((0 if row is None else int(row[0])) + amount))

    # --- fila ------------------------------------------------------------------

    def enqueue(
        self,
        items: Sequence[Item],
        collected_record_id: int | None = None,
    ) -> int:
        """Grava os itens e avança o marcador; devolve quantos descartou.

        Evento repetido (mesmo ``event_id``) é ignorado. Cheia, descarta primeiro os de
        menor prioridade e, entre iguais, os mais antigos.
        """
        with self._tx() as db:
            self._insert(db, items)
            dropped = self._trim(db)
            if dropped:
                self._add(db, DROPPED_TOTAL, dropped)
                self._add(db, DROPPED_PENDING, dropped)
            if collected_record_id is not None:
                self._put(db, "collected_record_id", str(collected_record_id))
        return dropped

    @staticmethod
    def _insert(db: sqlite3.Connection, items: Sequence[Item]) -> None:
        for event_id, payload, priority in items:
            db.execute(
                "INSERT OR IGNORE INTO queue(event_id, size, priority, payload) VALUES(?, ?, ?, ?)",
                (event_id, len(payload.encode()), priority, payload),
            )

    def report_overflow(self, build: Callable[[int, int], tuple[str, str]]) -> bool:
        """Se houve descarte ainda não avisado, enfileira o aviso ``agent.queue_overflow``.

        Tudo na mesma transação (zerar o contador e gravar o aviso): uma queda no meio não
        perde o aviso. O aviso entra com a maior prioridade e SEM descartar outro evento
        (senão cada aviso geraria um novo); a fila passa do limite por esse aviso.
        ``build(pendentes, total)`` devolve ``(event_id, payload)``.
        """
        with self._tx() as db:
            row = db.execute("SELECT value FROM kv WHERE key = ?", (DROPPED_PENDING,)).fetchone()
            pending = 0 if row is None else int(row[0])
            if not pending:
                return False
            total = self.get_int(DROPPED_TOTAL)
            event_id, payload = build(pending, total)
            self._insert(db, [(event_id, payload, 9)])
            self._put(db, DROPPED_PENDING, "0")
        return True

    def _trim(self, db: sqlite3.Connection) -> int:
        count, size = db.execute("SELECT count(*), coalesce(sum(size), 0) FROM queue").fetchone()
        dropped = 0
        while count > 0 and (count > self._max_events or size > self._max_bytes):
            excess = max(count - self._max_events, 1)
            rows = db.execute(
                "SELECT seq, size FROM queue ORDER BY priority, seq LIMIT ?", (excess,)
            ).fetchall()
            db.executemany("DELETE FROM queue WHERE seq = ?", [(r[0],) for r in rows])
            count -= len(rows)
            size -= sum(r[1] for r in rows)
            dropped += len(rows)
        return dropped

    def peek(self, limit: int) -> list[Queued]:
        rows = self._db.execute(
            "SELECT seq, event_id, size, payload FROM queue ORDER BY seq LIMIT ?", (limit,)
        ).fetchall()
        return [Queued(*r) for r in rows]

    def ack(self, seqs: Sequence[int]) -> None:
        with self._tx() as db:
            db.executemany("DELETE FROM queue WHERE seq = ?", [(s,) for s in seqs])

    def reset_for_new_enrollment(self) -> int:
        """Esvazia a fila e o marcador (reenrolamento com outro ``agent_id``).

        Os eventos enfileirados levam o ``instance_id`` do agente antigo e o servidor os
        recusaria (``source_mismatch``). Devolve quantos eventos descartou.
        """
        with self._tx() as db:
            (count,) = db.execute("SELECT count(*) FROM queue").fetchone()
            db.execute("DELETE FROM queue")
            db.execute(
                "DELETE FROM kv WHERE key IN (?, ?, ?)",
                (
                    "collected_record_id",
                    DROPPED_PENDING,
                    "log_epoch",
                ),
            )
        return int(count)

    def stats(self) -> dict[str, int]:
        count, size = self._db.execute(
            "SELECT count(*), coalesce(sum(size), 0) FROM queue"
        ).fetchone()
        return {
            "queued_events": count,
            "queued_bytes": size,
            "dropped_total": self.get_int(DROPPED_TOTAL),
            "rejected_total": self.get_int("rejected_total"),
            "malformed_total": self.get_int("malformed_total"),
            "batches_dropped_total": self.get_int("batches_dropped_total"),
            "log_resets_total": self.get_int("log_resets_total"),
        }
