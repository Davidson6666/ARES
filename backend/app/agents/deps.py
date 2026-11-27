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

from app.agents.models import Agent, AgentCredential
from app.agents.service import sha256
from app.auth.dependencies import get_db, utcnow
from app.core.errors import ApiError

log = structlog.get_logger("ares.agents")

_CREDENTIAL = re.compile(r"^ares_agent_([0-9a-f]{32})\.([A-Za-z0-9_-]{43})$")
_ZERO_HASH = b"\x00" * 32


@dataclass(frozen=True)
class AgentContext:
    agent: Agent
    credential_id: uuid.UUID


def _unauthenticated() -> ApiError:
    return ApiError(401, "unauthenticated", "Credencial de agente ausente ou inválida.")


def require_agent(request: Request, db: DbSession = Depends(get_db)) -> AgentContext:
    scheme, _, value = request.headers.get("authorization", "").partition(" ")
    match = _CREDENTIAL.fullmatch(value) if scheme == "Agent" else None
    if match is None:
        raise _unauthenticated()
    agent_id = uuid.UUID(match.group(1))
    digest = sha256(match.group(2))
    now = utcnow()
    row = db.execute(
        select(AgentCredential, Agent)
        .join(Agent, Agent.id == AgentCredential.agent_id)
        .where(AgentCredential.agent_id == agent_id, AgentCredential.revoked_at.is_(None))
    ).first()
    stored = row[0].credential_hash if row else _ZERO_HASH
    matches = secrets.compare_digest(stored, digest)  # sempre compara, achando ou não
    if (
        row is None
        or not matches
        or row[1].status != "active"
        or (row[0].expires_at is not None and row[0].expires_at <= now)
    ):
        # Só log, sem a credencial: sob ataque, não gravar no banco a cada tentativa.
        log.warning("agent.auth_failed", agent_id=str(agent_id))
        raise _unauthenticated()
    return AgentContext(agent=row[1], credential_id=row[0].id)
