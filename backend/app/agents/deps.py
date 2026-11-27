"""Autenticação de agente: ``Authorization: Agent <credencial>`` (complemento 3.1).

O agente nunca recebe papéis nem permissões: ``AgentContext`` é um tipo à
parte, que as rotas de humano não aceitam. A credencial é conferida no banco a
cada requisição (sem cache), então revogar vale na requisição seguinte.
"""

import re
import secrets
import uuid
from dataclasses import dataclass

import structlog
from fastapi import Depends, Request
from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession

from app.agents.models import Agent, AgentCredential, OperatorAuthorization
from app.agents.service import sha256
from app.auth.dependencies import get_db, utcnow
from app.core.errors import ApiError
from app.core.rate_limit import client_key

log = structlog.get_logger("ares.agents")

_CREDENTIAL = re.compile(r"^ares_agent_([0-9a-f]{32})\.([A-Za-z0-9_-]{43})$")
_ZERO_HASH = b"\x00" * 32


@dataclass(frozen=True)
class AgentContext:
    agent: Agent
    credential_id: uuid.UUID


def _unauthenticated() -> ApiError:
    return ApiError(401, "unauthenticated", "Credencial de agente ausente ou inválida.")


def _failed(request: Request, agent_id: uuid.UUID | None) -> ApiError:
    """Falha de credencial: log (sem a credencial) e limite por IP. Cada falha
    bem formada custa uma consulta ao banco, então o IP que insiste leva 429."""
    log.warning("agent.auth_failed", agent_id=str(agent_id) if agent_id else None)
    retry_after = request.app.state.agent_auth_fail_limiter.hit(
        client_key(request.client.host if request.client else None)
    )
    if retry_after is not None:
        return ApiError(
            429,
            "rate_limited",
            "Muitas credenciais inválidas. Tente novamente mais tarde.",
            headers={"Retry-After": str(retry_after)},
        )
    return _unauthenticated()


def require_agent(request: Request, db: DbSession = Depends(get_db)) -> AgentContext:
    scheme, _, value = request.headers.get("authorization", "").partition(" ")
    match = _CREDENTIAL.fullmatch(value) if scheme == "Agent" else None
    if match is None:
        raise _failed(request, None)
    agent_id = uuid.UUID(match.group(1))
    digest = sha256(match.group(2))
    now = utcnow()
    row = db.execute(
        select(AgentCredential, Agent, OperatorAuthorization)
        .join(Agent, Agent.id == AgentCredential.agent_id)
        .join(OperatorAuthorization, OperatorAuthorization.id == Agent.authorization_id)
        .where(AgentCredential.agent_id == agent_id, AgentCredential.revoked_at.is_(None))
    ).first()
    stored = row[0].credential_hash if row else _ZERO_HASH
    matches = secrets.compare_digest(stored, digest)  # sempre compara, achando ou não
    if (
        row is None
        or not matches
        or row[1].status != "active"
        or (row[0].expires_at is not None and row[0].expires_at <= now)
        # CLAUDE.md 9.1 e 9.4: termo revogado ou vencido corta também o agente
        # JÁ enrolado, não só o enrolamento novo.
        or not row[2].is_current(now)
    ):
        raise _failed(request, agent_id)
    ctx = AgentContext(agent=row[1], credential_id=row[0].id)
    # Fecha a transação da autenticação: o corpo ainda será lido, e uma conexão
    # parada dentro de transação (corpo gotejado) prenderia o pool. Os objetos
    # continuam carregados (expire_on_commit=False); quem grava reabre transação.
    db.commit()
    return ctx


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


def lock_active_agent(db: DbSession, agent_id: uuid.UUID) -> Agent:
    """Relê o agente travando a linha (FOR KEY SHARE) e exige ``status = 'active'``.

    Um ``revoke`` (FOR UPDATE) que chegou durante a leitura do corpo termina antes
    ou espera esta requisição acabar. KEY SHARE não conflita com o UPDATE de
    ``last_seen_at`` de outra requisição do mesmo agente (FOR SHARE daria deadlock).
    """
    agent = db.scalar(
        select(Agent)
        .where(Agent.id == agent_id)
        .with_for_update(read=True, key_share=True)
        # Sem isto o SQLAlchemy devolve o objeto já carregado (status antigo).
        .execution_options(populate_existing=True)
    )
    if agent is None or agent.status != "active":
        raise _unauthenticated()
    return agent
