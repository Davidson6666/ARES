"""Event Ingress: POST /events e GET /events/{event_id} (complemento 3.2; ADR 0006).

O Ingress pertence ao Core e SÓ valida e aceita: entrega ao Event Bus e não
interpreta o conteúdo (CLAUDE.md, seção 5).
"""

import json
import uuid
from datetime import datetime, timedelta
from typing import Any, Literal

import structlog
from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session as DbSession

from app.agents.deps import AgentContext, require_agent
from app.auth.dependencies import (
    allow_query,
    get_db,
    get_settings,
    require_json,
    require_permission,
    utcnow,
)
from app.auth.service import AuthContext
from app.auth.session_flow import request_id
from app.core import idempotency
from app.core.config import Settings
from app.core.errors import ApiError
from app.events import envelope
from app.events.bus import EventBus, PublishResult, record_outcome
from app.events.models import Event

router = APIRouter(prefix="/api/v1")
log = structlog.get_logger("ares.ingress")

_require_events_read = require_permission("events.read")
_LAST_SEEN_INTERVAL = timedelta(seconds=60)


class ResultItem(BaseModel):
    event_id: str | None
    outcome: Literal["accepted", "duplicate", "rejected"]
    error_code: str | None = None
    field: str | None = None


class IngestResponse(BaseModel):
    accepted: int
    duplicate: int
    rejected: int
    results: list[ResultItem]


class EventOut(BaseModel):
    event_id: uuid.UUID
    event_type: str
    schema_version: int
    occurred_at: datetime
    observed_at: datetime
    source_module: str
    source_instance_id: str
    agent_id: uuid.UUID
    tenant_id: str | None
    device_id: str | None
    correlation_id: str | None
    severity: str | None
    data_classification: str
    # Conteúdo NÃO CONFIÁVEL enviado pelo agente: devolvido como JSON, nunca
    # como HTML. O frontend precisa escapar por padrão (CLAUDE.md, 9.1).
    data: dict[str, Any]
    flags: list[str]


def limited_agent(request: Request, ctx: AgentContext = Depends(require_agent)) -> AgentContext:
    """Autentica o agente e aplica o limite de requisições por agente (429)."""
    retry_after = request.app.state.agent_request_limiter.hit(str(ctx.agent.id))
    if retry_after is not None:
        log.warning("ingest.rate_limited", agent_id=str(ctx.agent.id), kind="requests")
        raise ApiError(
            429,
            "rate_limited",
            "Limite de requisições do agente excedido.",
            headers={"Retry-After": str(retry_after)},
        )
    return ctx


async def read_limited_body(request: Request) -> bytes:
    """Lê o corpo até MAX_BODY_BYTES; acima disso, 413 sem carregar o resto."""
    declared = request.headers.get("content-length")
    if declared is not None and declared.isdigit() and int(declared) > envelope.MAX_BODY_BYTES:
        raise ApiError(413, "payload_too_large", "Corpo da requisição acima do limite (2 MB).")
    chunks: list[bytes] = []
    total = 0
    async for chunk in request.stream():
        total += len(chunk)
        if total > envelope.MAX_BODY_BYTES:
            raise ApiError(413, "payload_too_large", "Corpo da requisição acima do limite (2 MB).")
        chunks.append(chunk)
    return b"".join(chunks)


def _parse_batch(raw: bytes) -> list[Any]:
    try:
        payload = json.loads(raw, parse_constant=envelope.reject_constant)
    except ValueError, RecursionError:
        raise ApiError(
            400, "malformed_request", "A requisição não pôde ser interpretada."
        ) from None
    if (
        not isinstance(payload, dict)
        or set(payload) != {"events"}
        or not isinstance(payload["events"], list)
    ):
        raise ApiError(
            422,
            "validation_error",
            "O corpo deve ser um objeto com a lista `events`.",
            details=[{"field": "body", "type": "invalid_shape"}],
        )
    events: list[Any] = payload["events"]
    if not events:
        raise ApiError(
            422,
            "empty_batch",
            "O lote não tem eventos.",
            details=[{"field": "events", "type": "empty"}],
        )
    if len(events) > envelope.MAX_BATCH:
        raise ApiError(
            422,
            "batch_too_large",
            f"O lote excede {envelope.MAX_BATCH} eventos.",
            details=[{"field": "events", "type": "too_many"}],
        )
    return events


@router.post(
    "/events",
    status_code=202,
    response_model=IngestResponse,
    dependencies=[Depends(require_json), Depends(allow_query())],
)
def ingest(
    request: Request,
    ctx: AgentContext = Depends(limited_agent),
    raw: bytes = Depends(read_limited_body),
    db: DbSession = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> IngestResponse | JSONResponse:
    now = utcnow()
    agent = ctx.agent
    key = idempotency.read_key(request)
    events = _parse_batch(raw)
    digest = idempotency.request_hash(raw)
    stored = idempotency.lock_and_lookup(db, "agent", agent.id, key, digest, now)
    if stored is not None:
        return JSONResponse(
            stored.body, status_code=stored.status, headers={"Idempotent-Replay": "true"}
        )

    retry_after = request.app.state.agent_event_limiter.hit(str(agent.id), cost=len(events))
    if retry_after is not None:
        log.warning("ingest.rate_limited", agent_id=str(agent.id), kind="events", batch=len(events))
        raise ApiError(
            429,
            "rate_limited",
            "Limite de eventos do agente excedido.",
            headers={"Retry-After": str(retry_after)},
        )

    bus: EventBus = request.app.state.event_bus
    slots: list[envelope.Parsed | envelope.Rejected] = [
        envelope.validate_event(e, agent, now, settings.occurred_at_future_seconds) for e in events
    ]
    parsed = [s for s in slots if isinstance(s, envelope.Parsed)]
    published = iter(bus.publish(db, agent, parsed, now))

    items: list[ResultItem] = []
    for slot in slots:
        if isinstance(slot, envelope.Rejected):
            result = PublishResult("rejected", slot.code)
            item = ResultItem(
                event_id=slot.event_id, outcome="rejected", error_code=slot.code, field=slot.field
            )
        else:
            result = next(published)
            item = ResultItem(
                event_id=str(slot.envelope.event_id),
                outcome=result.outcome,
                error_code=result.error_code,
            )
        if item.event_id is not None:
            record_outcome(db, item.event_id, agent, result.outcome, result.error_code, now)
        items.append(item)

    body = IngestResponse(
        accepted=sum(i.outcome == "accepted" for i in items),
        duplicate=sum(i.outcome == "duplicate" for i in items),
        rejected=sum(i.outcome == "rejected" for i in items),
        results=items,
    )
    idempotency.store(db, "agent", agent.id, key, digest, 202, body.model_dump(mode="json"), now)
    if agent.last_seen_at is None or now - agent.last_seen_at >= _LAST_SEEN_INTERVAL:
        agent.last_seen_at = now
    db.commit()
    # Só contagens no log: o conteúdo dos eventos nunca vai para o log.
    log.info(
        "ingest",
        agent_id=str(agent.id),
        request_id=request_id(request),
        accepted=body.accepted,
        duplicate=body.duplicate,
        rejected=body.rejected,
    )
    return body


@router.get(
    "/events/{event_id}",
    response_model=EventOut,
    dependencies=[Depends(allow_query())],
)
def get_event(
    event_id: uuid.UUID,
    ctx: AuthContext = Depends(_require_events_read),
    db: DbSession = Depends(get_db),
) -> EventOut:
    event = db.get(Event, event_id)
    tenant = ctx.user.tenant_id
    # Fora do escopo: 404, igual a inexistente (não revela existência; IDOR).
    if event is None or (tenant is not None and event.tenant_id != tenant):
        raise ApiError(404, "not_found", "Recurso não encontrado.")
    return EventOut.model_validate(event, from_attributes=True)
