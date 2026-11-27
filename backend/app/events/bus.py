"""Event Bus interno (CLAUDE.md, seção 5; ADR 0006).

O Event Ingress (Core) só valida e aceita; o Bus recebe os eventos aceitos,
deduplica e os persiste. O Core NUNCA consome eventos para lógica de detecção:
consumidores futuros (engines) se inscreverão no Bus, não no Core.

A implementação inicial grava na tabela ``events`` do PostgreSQL. Nenhum
consumidor existe ainda (dead-letter e retentativas ficam para quando houver;
ADR 0006, "Em aberto").
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Literal, Protocol

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session as DbSession

from app.agents.models import Agent
from app.events.envelope import Parsed
from app.events.models import Event, IngestRecord

Outcome = Literal["accepted", "duplicate", "rejected"]


@dataclass(frozen=True)
class PublishResult:
    outcome: Outcome
    error_code: str | None = None


class EventBus(Protocol):
    def publish(
        self, db: DbSession, agent: Agent, events: list[Parsed], observed_at: datetime
    ) -> list[PublishResult]:
        """Entrega os eventos já validados. Resultado na mesma ordem da entrada.
        Participa da transação de quem chama (sem commit)."""


class PostgresEventBus:
    def publish(
        self, db: DbSession, agent: Agent, events: list[Parsed], observed_at: datetime
    ) -> list[PublishResult]:
        results: list[PublishResult] = []
        for parsed in events:
            env = parsed.envelope
            inserted = db.execute(
                pg_insert(Event)
                .values(
                    event_id=env.event_id,
                    event_type=env.event_type,
                    schema_version=env.schema_version,
                    occurred_at=env.occurred_at,
                    observed_at=observed_at,  # definido pelo servidor, nunca pela fonte
                    source_module=env.source.module,
                    source_instance_id=env.source.instance_id,
                    agent_id=agent.id,
                    tenant_id=parsed.tenant_id,
                    device_id=env.device_id,
                    correlation_id=env.correlation_id,
                    severity=env.severity,
                    data_classification=env.data_classification,
                    data=env.data,
                    flags=parsed.flags,
                )
                .on_conflict_do_nothing(index_elements=["event_id"])
                .returning(Event.event_id)
            ).scalar()
            if inserted is not None:
                results.append(PublishResult("accepted"))
                continue
            owner = db.scalar(select(Event.agent_id).where(Event.event_id == env.event_id))
            if owner == agent.id:
                results.append(PublishResult("duplicate"))
            else:
                # Mesmo event_id de outro agente: não é duplicata nossa.
                results.append(PublishResult("rejected", "event_id_conflict"))
        return results


def record_outcome(
    db: DbSession, event_id: str, agent: Agent, outcome: str, code: str | None, now: datetime
) -> None:
    """Último resultado por event_id (``ingest_records``; retenção de 7 dias)."""
    stmt = pg_insert(IngestRecord).values(
        event_id=event_id,
        received_at=now,
        source_id=str(agent.id),
        outcome=outcome,
        error_code=code,
    )
    db.execute(
        stmt.on_conflict_do_update(
            index_elements=["event_id"],
            set_={
                "received_at": stmt.excluded.received_at,
                "source_id": stmt.excluded.source_id,
                "outcome": stmt.excluded.outcome,
                "error_code": stmt.excluded.error_code,
            },
        )
    )
