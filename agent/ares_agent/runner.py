"""Laço de polling do agente (ADR 0007).

Cada ciclo: coleta do Security log -> fila local -> envio em lotes -> heartbeat se
ficou ocioso. Garantia "pelo menos uma vez": a linha sai da fila só depois do 202.

| Resposta                         | Ação                                              |
|----------------------------------|---------------------------------------------------|
| 202, evento accepted/duplicate   | confirma (sai da fila)                            |
| 202, evento rejected             | descarta e conta; **não reenvia** (lote envenenado)|
| 429                              | espera ``Retry-After``                            |
| 408, 5xx, rede                   | recuo exponencial com jitter, teto de 5 min       |
| 401                              | **para** (credencial inválida ou revogada)        |
| 400, 409, 413, 422 no lote       | erro do agente: descarta o lote, registra, segue  |

Qualquer outra exceção num ciclo (disco cheio, banco travado, dado inesperado) é
registrada só pelo tipo, vira recuo e o agente continua vivo: um agente de defesa que
morre em silêncio é pior que um que reclama.
"""

import json
import logging
import random
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime

from ares_agent import client as api
from ares_agent import collector, mapping
from ares_agent.config import Config
from ares_agent.log import emit
from ares_agent.store import Item, Queued, Store

PAGE = 200  # eventos lidos do log por consulta
MAX_PAGES = 10  # consultas por ciclo (recupera atraso sem monopolizar)
MAX_BATCH_BYTES = 1024 * 1024  # bem abaixo dos 2 MB do servidor
MAX_BACKOFF_SECONDS = 300


class CredentialRejected(Exception):
    """O servidor respondeu 401: o agente deve parar."""


@dataclass
class Runner:
    cfg: Config
    store: Store
    client: api.ServerClient
    agent_id: str
    module: str
    logger: logging.Logger
    read: Callable[[int, int], str] = collector.query
    latest: Callable[[], int] = collector.latest_record_id
    clock: Callable[[], datetime] = lambda: datetime.now(UTC)
    monotonic: Callable[[], float] = time.monotonic
    rng: random.Random = field(default_factory=random.Random)
    failures: int = 0
    last_contact: float | None = None

    # --- ciclo -------------------------------------------------------------------

    def cycle(self) -> float:
        """Roda um ciclo e devolve quantos segundos esperar até o próximo."""
        ok = True
        hint: int | None = None
        try:
            self._collect()
        except collector.CollectorError as exc:
            ok = False
            self._failed("collect_failed", str(exc))
        except Exception as exc:  # noqa: BLE001  (o agente não pode morrer em silêncio)
            ok = False
            self._failed("collect_error", type(exc).__name__)
        try:
            self._flush()
            self._heartbeat_if_idle()
        except api.RetryLater as exc:
            ok = False
            hint = exc.delay
            self._failed("send_deferred", exc.reason)
        except api.Unauthorized:
            emit(self.logger, logging.ERROR, "credential_rejected")
            self.store.put("last_error", "credential_rejected")
            raise CredentialRejected from None
        except Exception as exc:  # noqa: BLE001
            ok = False
            self._failed("send_error", type(exc).__name__)
        if ok:
            self.failures = 0
            self.store.put("last_error", "")
        return self._delay(ok, hint)

    def run(self, stop: threading.Event) -> None:
        emit(self.logger, logging.INFO, "agent_started", agent_id=self.agent_id)
        while not stop.is_set():
            stop.wait(self.cycle())
        emit(self.logger, logging.INFO, "agent_stopped", **self.store.stats())

    # --- coleta ------------------------------------------------------------------

    def _collect(self) -> None:
        latest = self.latest()
        self.store.put("log_latest_record_id", str(latest))
        raw_mark = self.store.get("collected_record_id")
        if raw_mark is None:
            # Primeira execução: só eventos NOVOS (não relê o histórico do log).
            self.store.put("collected_record_id", str(latest))
            emit(self.logger, logging.INFO, "collection_started", from_record_id=latest)
            return
        after = int(raw_mark)
        if latest < after:
            after = self._log_was_reset(after)
        epoch = self.store.get_int("log_epoch")
        limit = PAGE
        # Em geral, até MAX_PAGES consultas; o resto do orçamento só é gasto andando um
        # evento por vez ao redor de um registro que quebra o XML.
        for _ in range(MAX_PAGES + PAGE):
            raws, skipped, limit = self._next_page(after, limit)
            if skipped is not None:
                after = skipped
                continue
            if not raws:
                break
            queued: list[Item] = []
            malformed = 0
            for raw in raws:
                envelope = mapping.to_envelope(raw, self.agent_id, self.module, epoch)
                if envelope is None:
                    malformed += 1
                else:
                    queued.append(
                        (
                            envelope["event_id"],
                            _dump(envelope),
                            mapping.priority(raw.windows_event_id),
                        )
                    )
            after = max(r.record_id for r in raws)
            dropped = self.store.enqueue(queued, after)
            if malformed:
                self.store.add("malformed_total", malformed)
            if dropped:
                emit(self.logger, logging.WARNING, "queue_overflow", dropped=dropped)
            if len(raws) < limit:
                break
        self._report_overflow()

    def _log_was_reset(self, previous: int) -> int:
        """O log tem menos registros que o marcador: foi limpo (EventID 1102) e a numeração
        recomeçou. Sem isto o agente ficaria cego até a numeração passar do marcador, e os
        ``event_id`` novos colidiriam com os antigos (o servidor diria ``duplicate``)."""
        epoch = self.store.get_int("log_epoch") + 1
        self.store.put("log_epoch", str(epoch))
        self.store.add("log_resets_total", 1)
        event = mapping.log_reset_envelope(
            self.agent_id, self.module, epoch, previous, self.clock()
        )
        self.store.enqueue([(event["event_id"], _dump(event), mapping.OVERFLOW_PRIORITY)], 0)
        emit(self.logger, logging.WARNING, "log_reset_detected", epoch=epoch)
        return 0

    def _next_page(
        self, after: int, limit: int
    ) -> tuple[list[collector.RawEvent], int | None, int]:
        """Próximos eventos: ``(eventos, marcador novo se pulou um evento ruim, limite usado)``.

        Se a página quebra o XML, lê um evento só e fica nesse modo pelo resto do ciclo
        (sem repetir a consulta grande a cada passo). Se um evento sozinho também quebra,
        ele é o registro problemático: o marcador pula só ele (um registro ruim não pode
        travar a coleta) e ele é contado.
        """
        text = self.read(after, limit)
        try:
            return collector.parse_events(text), None, limit
        except collector.MalformedOutput:
            if limit > 1:
                limit = 1
                text = self.read(after, 1)
                try:
                    return collector.parse_events(text), None, 1
                except collector.MalformedOutput:
                    pass
        record_id = collector.first_record_id(text)
        if record_id is None or record_id <= after:
            raise collector.MalformedOutput("Registro ilegível sem EventRecordID.")
        self.store.enqueue([], record_id)
        self.store.add("malformed_total", 1)
        emit(self.logger, logging.WARNING, "event_skipped", record_id=record_id)
        return [], record_id, 1

    def _report_overflow(self) -> None:
        def build(pending: int, total: int) -> tuple[str, str]:
            event = mapping.overflow_envelope(
                self.agent_id, self.module, pending, total, self.clock()
            )
            return event["event_id"], _dump(event)

        self.store.report_overflow(build)

    # --- envio -------------------------------------------------------------------

    def _flush(self) -> None:
        while True:
            items: list[Queued] = []
            size = 0
            for item in self.store.peek(self.cfg.batch_size):
                if items and size + item.size > MAX_BATCH_BYTES:
                    break
                items.append(item)
                size += item.size
            if not items:
                return
            seqs = [q.seq for q in items]
            try:
                events = [json.loads(q.payload) for q in items]
            except ValueError:
                # Linha corrompida na fila (não deveria existir): descarta o lote.
                self.store.ack(seqs)
                self.store.add("malformed_total", len(seqs))
                emit(self.logger, logging.ERROR, "queue_rows_corrupted", size=len(seqs))
                continue
            try:
                results = self.client.post_events(events)
            except api.BatchRefused as exc:
                # Defeito do agente: repetir não adianta. Descarta, conta e segue.
                self.store.ack(seqs)
                self.store.add("batches_dropped_total", 1)
                emit(self.logger, logging.ERROR, "batch_dropped", code=exc.code, size=len(seqs))
                continue
            self.store.ack(seqs)
            self._touch()
            codes: dict[str, int] = {}
            for result in results:
                if result.outcome == "rejected":
                    code = result.error_code or "unknown"
                    codes[code] = codes.get(code, 0) + 1
            rejected = sum(codes.values())
            if rejected:
                self.store.add("rejected_total", rejected)
            emit(
                self.logger,
                logging.INFO if not rejected else logging.WARNING,
                "batch_sent",
                size=len(seqs),
                accepted=sum(r.outcome == "accepted" for r in results),
                duplicate=sum(r.outcome == "duplicate" for r in results),
                rejected=rejected,
                rejected_codes=codes,
            )

    def _heartbeat_if_idle(self) -> None:
        idle = self.last_contact is None or (
            self.monotonic() - self.last_contact >= self.cfg.heartbeat_interval_seconds
        )
        if idle:
            self.client.heartbeat()
            self._touch()

    def _touch(self) -> None:
        self.last_contact = self.monotonic()
        self.store.put("last_contact_at", self.clock().isoformat(timespec="seconds"))

    # --- recuo -------------------------------------------------------------------

    def _failed(self, event: str, reason: str) -> None:
        self.store.put("last_error", reason[:200])
        emit(self.logger, logging.WARNING, event, reason=reason[:200])

    def _delay(self, ok: bool, hint: int | None) -> float:
        base = float(self.cfg.poll_interval_seconds)
        if ok:
            return base
        self.failures += 1
        backoff = min(base * float(2 ** min(self.failures, 6)), float(MAX_BACKOFF_SECONDS))
        jittered = backoff * (0.8 + 0.4 * self.rng.random())
        return max(jittered, float(hint)) if hint else jittered


def _dump(envelope: dict[str, object]) -> str:
    return json.dumps(envelope, sort_keys=True, separators=(",", ":"))
