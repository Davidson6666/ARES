"""Modelos de eventos, resultado de ingestão e idempotência (espelham a 0005)."""

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    text,
)
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db_base import Base


class Event(Base):
    __tablename__ = "events"
    __table_args__ = (
        CheckConstraint("schema_version >= 1", name="schema_version"),
        CheckConstraint(
            "severity IS NULL OR severity IN ('info', 'low', 'medium', 'high', 'critical')",
            name="severity",
        ),
        CheckConstraint(
            "data_classification IN ('public', 'internal', 'personal', 'sensitive')",
            name="data_classification",
        ),
        CheckConstraint(
            r"event_type ~ '^[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*$'", name="event_type_format"
        ),
        CheckConstraint("octet_length(data::text) <= 16384", name="data_size"),
    )

    event_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True)
    event_type: Mapped[str] = mapped_column(Text)
    schema_version: Mapped[int] = mapped_column(Integer)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    source_module: Mapped[str] = mapped_column(Text)
    source_instance_id: Mapped[str] = mapped_column(Text)
    agent_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("agents.id", ondelete="RESTRICT"), index=True
    )
    tenant_id: Mapped[str | None] = mapped_column(Text)
    device_id: Mapped[str | None] = mapped_column(Text)
    correlation_id: Mapped[str | None] = mapped_column(Text)
    severity: Mapped[str | None] = mapped_column(String(16))
    data_classification: Mapped[str] = mapped_column(String(16))
    data: Mapped[dict[str, Any]] = mapped_column(JSONB)
    flags: Mapped[list[str]] = mapped_column(ARRAY(Text), server_default=text("'{}'::text[]"))


class IngestRecord(Base):
    __tablename__ = "ingest_records"
    __table_args__ = (
        CheckConstraint("outcome IN ('accepted', 'duplicate', 'rejected')", name="outcome"),
    )

    event_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True)
    received_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    source_id: Mapped[str] = mapped_column(Text)
    outcome: Mapped[str] = mapped_column(String(16))
    error_code: Mapped[str | None] = mapped_column(Text)
