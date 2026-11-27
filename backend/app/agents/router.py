"""Rotas de agentes (complemento 3.2; ADR 0006).

POST /agents, /agents/{id}/rotate e /agents/{id}/revoke são de humano
(``modules.configure``, cookie + CSRF). POST /agents/enroll é do próprio agente:
público, com rate limit, autenticado pelo token de enrolamento (uso único).
"""

import re
import uuid
from datetime import datetime, timedelta
from typing import Any

import structlog
from fastapi import APIRouter, Depends, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy.orm import Session as DbSession

from app.agents import service
from app.agents.deps import AgentContext, limited_agent, lock_active_agent
from app.agents.models import Agent
from app.audit import service as audit
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
from app.core.rate_limit import client_key

router = APIRouter(prefix="/api/v1")
log = structlog.get_logger("ares.agents")

_require_configure = require_permission("modules.configure")
_NO_STORE = {"Cache-Control": "no-store"}
_LAST_SEEN_INTERVAL = timedelta(seconds=30)
_MODULE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")


def _no_control(value: str) -> str:
    if any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise ValueError("caractere de controle")
    return value


class CreateAgentRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=64)
    module: str = Field(pattern=_MODULE.pattern)
    tenant_id: str | None = Field(default=None, min_length=1, max_length=128)
    authorization_id: uuid.UUID

    _name = field_validator("name")(_no_control)
    _tenant = field_validator("tenant_id")(lambda v: v if v is None else _no_control(v))


class EnrollRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enrollment_token: str = Field(min_length=20, max_length=128)
    host_id: str | None = Field(default=None, min_length=1, max_length=128)

    _host = field_validator("host_id")(lambda v: v if v is None else _no_control(v))


class AgentCreated(BaseModel):
    agent_id: uuid.UUID
    name: str
    module: str
    tenant_id: str | None
    status: str
    # Única vez em que o token existe em claro. Em repetição da mesma
    # Idempotency-Key ele NÃO é devolvido (não fica guardado).
    enrollment_token: str | None
    enrollment_expires_at: datetime
    replayed: bool = False


class Enrolled(BaseModel):
    agent_id: uuid.UUID
    module: str
    tenant_id: str | None
    # Única vez em que a credencial existe em claro.
    credential: str


class Rotated(BaseModel):
    agent_id: uuid.UUID
    credential: str


class AgentStatus(BaseModel):
    agent_id: uuid.UUID
    status: str


def _audit(
    db: DbSession,
    request: Request,
    action: str,
    ctx: AuthContext | None,
    agent: Agent,
    now: datetime,
    details: dict[str, Any] | None = None,
) -> None:
    audit.record(
        db,
        action=action,
        result="success",
        actor_type="user" if ctx else "system",
        actor_user_id=ctx.user.id if ctx else None,
        resource_type="agent",
        resource_id=str(agent.id),
        request_id=request_id(request),
        details=details,
        now=now,
    )


def _visible_agent(db: DbSession, ctx: AuthContext, agent_id: uuid.UUID) -> Agent:
    """Agente dentro do escopo do usuário; fora dele, 404 (não revela existência)."""
    agent = db.get(Agent, agent_id, with_for_update=True)
    tenant = ctx.user.tenant_id
    if agent is None or (tenant is not None and agent.tenant_id != tenant):
        raise ApiError(404, "not_found", "Recurso não encontrado.")
    return agent


@router.post(
    "/agents",
    status_code=201,
    response_model=AgentCreated,
    dependencies=[Depends(require_json), Depends(allow_query())],
)
def create_agent(
    body: CreateAgentRequest,
    request: Request,
    response: Response,
    ctx: AuthContext = Depends(_require_configure),
    db: DbSession = Depends(get_db),
) -> AgentCreated | JSONResponse:
    now = utcnow()
    key = idempotency.read_key(request)
    digest = idempotency.request_hash(body.model_dump_json().encode())
    stored = idempotency.lock_and_lookup(db, "user", ctx.user.id, key, digest, now)
    if stored is not None:
        return JSONResponse(
            stored.body,
            status_code=stored.status,
            headers={**_NO_STORE, "Idempotent-Replay": "true"},
        )

    tenant = ctx.user.tenant_id
    if tenant is not None and body.tenant_id not in (None, tenant):
        raise ApiError(403, "permission_denied", "A operação não é permitida.")
    tenant_id = tenant if tenant is not None else body.tenant_id
    if service.current_authorization(db, body.authorization_id, now) is None:
        # Complemento/CLAUDE.md 9.4: sem termo vigente, sem enrolamento.
        raise ApiError(
            409,
            "authorization_required",
            "Não há termo de autorização vigente para este agente.",
        )
    agent, token = service.create_agent(
        db,
        created_by=ctx.user.id,
        name=body.name,
        module=body.module,
        tenant_id=tenant_id,
        authorization_id=body.authorization_id,
        now=now,
    )
    _audit(
        db,
        request,
        "agent.enrollment_token_issued",
        ctx,
        agent,
        now,
        details={"authorization_id": str(body.authorization_id)},
    )
    expires = now + timedelta(hours=service.ENROLLMENT_TOKEN_HOURS)
    created = AgentCreated(
        agent_id=agent.id,
        name=agent.name,
        module=agent.module,
        tenant_id=agent.tenant_id,
        status=agent.status,
        enrollment_token=token,
        enrollment_expires_at=expires,
    )
    # O que fica guardado para repetição NÃO tem o token.
    safe = created.model_copy(update={"enrollment_token": None, "replayed": True})
    idempotency.store(db, "user", ctx.user.id, key, digest, 201, safe.model_dump(mode="json"), now)
    db.commit()
    response.headers.update(_NO_STORE)
    return created


@router.post(
    "/agents/enroll",
    status_code=201,
    response_model=Enrolled,
    dependencies=[Depends(require_json), Depends(allow_query())],
)
def enroll(
    body: EnrollRequest,
    request: Request,
    response: Response,
    db: DbSession = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> Enrolled:
    retry_after = request.app.state.enroll_limiter.hit(
        client_key(request.client.host if request.client else None)
    )
    if retry_after is not None:
        raise ApiError(
            429,
            "rate_limited",
            "Muitas tentativas. Tente novamente mais tarde.",
            headers={"Retry-After": str(retry_after)},
        )
    now = utcnow()
    try:
        agent, credential = service.redeem_enrollment(db, body.enrollment_token, body.host_id, now)
    except service.EnrollmentRefused:
        log.warning("agent.enroll_refused", request_id=request_id(request))
        raise ApiError(
            401, "invalid_enrollment", "Token de enrolamento inválido ou expirado."
        ) from None
    except service.AuthorizationLapsed:
        raise ApiError(
            409,
            "authorization_required",
            "O termo de autorização deste agente não está mais vigente.",
        ) from None
    _audit(db, request, "agent.enrolled", None, agent, now)
    db.commit()
    response.headers.update(_NO_STORE)
    return Enrolled(
        agent_id=agent.id, module=agent.module, tenant_id=agent.tenant_id, credential=credential
    )


@router.post(
    "/agents/heartbeat",
    status_code=204,
    dependencies=[Depends(allow_query())],
)
def heartbeat(
    ctx: AgentContext = Depends(limited_agent),
    db: DbSession = Depends(get_db),
) -> Response:
    """Marca o agente como visto (``last_seen_at``) sem enviar evento.

    Sem corpo e sem auditoria: é frequente e não muda estado de segurança. O
    limite por agente (429) é o mesmo da ingestão.
    """
    agent = lock_active_agent(db, ctx.agent.id)
    now = utcnow()
    # Como na ingestão: não grava a cada chamada (cada UPDATE deixa tupla morta).
    if agent.last_seen_at is None or now - agent.last_seen_at >= _LAST_SEEN_INTERVAL:
        agent.last_seen_at = now
    db.commit()
    return Response(status_code=204, headers=_NO_STORE)


@router.post(
    "/agents/{agent_id}/rotate",
    response_model=Rotated,
    dependencies=[Depends(allow_query())],
)
def rotate(
    agent_id: uuid.UUID,
    request: Request,
    response: Response,
    ctx: AuthContext = Depends(_require_configure),
    db: DbSession = Depends(get_db),
) -> Rotated:
    now = utcnow()
    agent = _visible_agent(db, ctx, agent_id)
    if agent.status != "active":
        raise ApiError(409, "agent_not_active", "O agente não está ativo.")
    credential = service.rotate_credential(db, agent, now)
    _audit(db, request, "agent.rotated", ctx, agent, now)
    db.commit()
    response.headers.update(_NO_STORE)
    return Rotated(agent_id=agent.id, credential=credential)


@router.post(
    "/agents/{agent_id}/revoke",
    response_model=AgentStatus,
    dependencies=[Depends(allow_query())],
)
def revoke(
    agent_id: uuid.UUID,
    request: Request,
    ctx: AuthContext = Depends(_require_configure),
    db: DbSession = Depends(get_db),
) -> AgentStatus:
    now = utcnow()
    agent = _visible_agent(db, ctx, agent_id)
    already = agent.status == "revoked"
    service.revoke_agent(db, agent, now)
    if not already:
        _audit(db, request, "agent.revoked", ctx, agent, now)
    db.commit()
    return AgentStatus(agent_id=agent.id, status=agent.status)
