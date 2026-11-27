"""Agentes, credenciais e termo de autorização (ADR 0006).

Sem dependência de HTTP. NÃO faz commit: quem chama grava a ação e a
auditoria na mesma transação (ADR 0004).

Segredos (token de enrolamento, credencial) só existem em claro na resposta
que os entrega; no banco fica o SHA-256 (256 bits aleatórios dispensam Argon2,
que custaria memória a cada lote de eventos).
"""

import hashlib
import secrets
import uuid
from datetime import datetime, timedelta

from sqlalchemy import select, update
from sqlalchemy.orm import Session as DbSession

from app.agents.models import Agent, AgentCredential, AgentEnrollmentToken, OperatorAuthorization

ENROLLMENT_TOKEN_HOURS = 24
CREDENTIAL_PREFIX = "ares_agent_"


def sha256(value: str) -> bytes:
    return hashlib.sha256(value.encode("utf-8")).digest()


def make_credential(agent_id: uuid.UUID) -> tuple[str, bytes]:
    """Credencial em claro (``ares_agent_<id>.<segredo>``) e o hash a gravar."""
    secret = secrets.token_urlsafe(32)  # 43 caracteres base64url
    return f"{CREDENTIAL_PREFIX}{agent_id.hex}.{secret}", sha256(secret)


def current_authorization(
    db: DbSession, authorization_id: uuid.UUID, now: datetime
) -> OperatorAuthorization | None:
    row = db.get(OperatorAuthorization, authorization_id)
    return row if row is not None and row.is_current(now) else None


def create_agent(
    db: DbSession,
    *,
    created_by: uuid.UUID,
    name: str,
    module: str,
    tenant_id: str | None,
    authorization_id: uuid.UUID,
    now: datetime,
) -> tuple[Agent, str]:
    agent = Agent(
        id=uuid.uuid4(),
        name=name,
        module=module,
        tenant_id=tenant_id,
        status="pending",
        authorization_id=authorization_id,
        created_by=created_by,
        created_at=now,
    )
    db.add(agent)
    db.flush()
    token = secrets.token_urlsafe(32)
    db.add(
        AgentEnrollmentToken(
            id=uuid.uuid4(),
            agent_id=agent.id,
            token_hash=sha256(token),
            created_at=now,
            expires_at=now + timedelta(hours=ENROLLMENT_TOKEN_HOURS),
        )
    )
    db.flush()
    return agent, token


class EnrollmentRefused(Exception):
    """Token inexistente, usado, expirado ou agente que não está pendente."""


class AuthorizationLapsed(Exception):
    """Termo revogado ou vencido entre a criação e o enrolamento."""


def redeem_enrollment(
    db: DbSession, token: str, host_id: str | None, now: datetime
) -> tuple[Agent, str]:
    # Ordem de locks IGUAL à do revoke (agente, depois token): sem deadlock
    # entre enrolar e revogar ao mesmo tempo.
    agent_id = db.scalar(
        select(AgentEnrollmentToken.agent_id).where(
            AgentEnrollmentToken.token_hash == sha256(token)
        )
    )
    if agent_id is None:
        raise EnrollmentRefused
    agent = db.scalar(select(Agent).where(Agent.id == agent_id).with_for_update())
    row = db.scalar(
        select(AgentEnrollmentToken)
        .where(AgentEnrollmentToken.token_hash == sha256(token))
        .with_for_update()
    )
    if row is None or row.used_at is not None or row.expires_at <= now:
        raise EnrollmentRefused
    if agent is None or agent.status != "pending":
        raise EnrollmentRefused
    if current_authorization(db, agent.authorization_id, now) is None:
        raise AuthorizationLapsed
    row.used_at = now
    agent.status = "active"
    agent.activated_at = now
    agent.host_id = host_id
    credential, digest = make_credential(agent.id)
    db.add(
        AgentCredential(id=uuid.uuid4(), agent_id=agent.id, credential_hash=digest, issued_at=now)
    )
    db.flush()
    return agent, credential


def rotate_credential(db: DbSession, agent: Agent, now: datetime) -> str:
    """Revoga a credencial ativa e emite outra (no máximo uma ativa por agente)."""
    db.execute(
        update(AgentCredential)
        .where(AgentCredential.agent_id == agent.id, AgentCredential.revoked_at.is_(None))
        .values(revoked_at=now)
    )
    credential, digest = make_credential(agent.id)
    db.add(
        AgentCredential(id=uuid.uuid4(), agent_id=agent.id, credential_hash=digest, issued_at=now)
    )
    db.flush()
    return credential


def revoke_agent(db: DbSession, agent: Agent, now: datetime) -> None:
    """Revoga o agente, suas credenciais e tokens de enrolamento pendentes.
    Vale já na próxima requisição (a autenticação não usa cache)."""
    agent.status = "revoked"
    agent.revoked_at = agent.revoked_at or now
    db.execute(
        update(AgentCredential)
        .where(AgentCredential.agent_id == agent.id, AgentCredential.revoked_at.is_(None))
        .values(revoked_at=now)
    )
    db.execute(
        update(AgentEnrollmentToken)
        .where(AgentEnrollmentToken.agent_id == agent.id, AgentEnrollmentToken.used_at.is_(None))
        .values(used_at=now)
    )
    db.flush()
