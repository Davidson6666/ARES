"""Modelos de agentes, credenciais e termo de autorização (espelham a 0005)."""

import uuid
from datetime import datetime

from sqlalchemy import CheckConstraint, DateTime, ForeignKey, Index, LargeBinary, String, Text, text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db_base import Base


class OperatorAuthorization(Base):
    __tablename__ = "operator_authorizations"
    __table_args__ = (CheckConstraint("valid_until > valid_from", name="validity_order"),)

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    reference: Mapped[str] = mapped_column(Text)
    description: Mapped[str] = mapped_column(Text)
    valid_from: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    valid_until: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    recorded_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))

    def is_current(self, now: datetime) -> bool:
        return self.revoked_at is None and self.valid_from <= now < self.valid_until


class Agent(Base):
    __tablename__ = "agents"
    __table_args__ = (
        CheckConstraint("status IN ('pending', 'active', 'revoked')", name="status"),
        CheckConstraint(r"module ~ '^[a-z][a-z0-9_]{0,63}$'", name="module_format"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(Text)
    module: Mapped[str] = mapped_column(Text)
    tenant_id: Mapped[str | None] = mapped_column(Text)
    host_id: Mapped[str | None] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(16))
    authorization_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("operator_authorizations.id", ondelete="RESTRICT"), index=True
    )
    created_by: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="RESTRICT"), index=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    activated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class AgentEnrollmentToken(Base):
    __tablename__ = "agent_enrollment_tokens"
    __table_args__ = (CheckConstraint("octet_length(token_hash) = 32", name="token_hash_length"),)

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    agent_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("agents.id", ondelete="RESTRICT"), index=True
    )
    token_hash: Mapped[bytes] = mapped_column(LargeBinary, unique=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class AgentCredential(Base):
    __tablename__ = "agent_credentials"
    __table_args__ = (
        CheckConstraint("octet_length(credential_hash) = 32", name="credential_hash_length"),
        Index(
            "uq_agent_credentials_one_active",
            "agent_id",
            unique=True,
            postgresql_where=text("revoked_at IS NULL"),
        ),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    agent_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("agents.id", ondelete="RESTRICT"), index=True
    )
    credential_hash: Mapped[bytes] = mapped_column(LargeBinary, unique=True)
    issued_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
