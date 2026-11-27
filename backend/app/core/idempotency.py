"""Idempotency-Key (complemento 3.3; ADR 0006).

Retenção de 24 h. Mesma chave e mesmo pedido: repete a resposta guardada.
Mesma chave e pedido diferente: 409. Requisições simultâneas com a mesma chave
são serializadas por advisory lock (até o commit de quem chama).
"""

import hashlib
import re
import struct
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from fastapi import Request
from sqlalchemy import CheckConstraint, DateTime, Integer, LargeBinary, String, Text, select, text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.orm import Session as DbSession

from app.core.db_base import Base
from app.core.errors import ApiError


class IdempotencyKey(Base):
    __tablename__ = "idempotency_keys"
    __table_args__ = (
        CheckConstraint("principal_type IN ('user', 'agent')", name="principal_type"),
        CheckConstraint("octet_length(request_hash) = 32", name="request_hash_length"),
    )

    principal_type: Mapped[str] = mapped_column(String(8), primary_key=True)
    principal_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True)
    key: Mapped[str] = mapped_column(Text, primary_key=True)
    request_hash: Mapped[bytes] = mapped_column(LargeBinary)
    response_status: Mapped[int] = mapped_column(Integer)
    response_body: Mapped[dict[str, Any]] = mapped_column(JSONB)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)


HEADER = "Idempotency-Key"
RETENTION = timedelta(hours=24)
_KEY_FORMAT = re.compile(r"^[A-Za-z0-9._~:-]{1,128}$")


def read_key(request: Request) -> str:
    key = request.headers.get(HEADER)
    if key is None:
        raise ApiError(
            400, "idempotency_key_required", "O cabeçalho Idempotency-Key é obrigatório."
        )
    if not _KEY_FORMAT.fullmatch(key):
        raise ApiError(
            400, "idempotency_key_invalid", "Idempotency-Key inválida (1 a 128 caracteres)."
        )
    return key


def request_hash(*parts: bytes) -> bytes:
    h = hashlib.sha256()
    for part in parts:
        h.update(struct.pack(">I", len(part)))
        h.update(part)
    return h.digest()


@dataclass(frozen=True)
class Stored:
    status: int
    body: dict[str, Any]


def lock_and_lookup(
    db: DbSession,
    principal_type: str,
    principal_id: uuid.UUID,
    key: str,
    digest: bytes,
    now: datetime,
) -> Stored | None:
    """Trava a chave e devolve a resposta guardada, se houver. Levanta 409 se a
    chave já foi usada com outro pedido."""
    lock_id = int.from_bytes(
        hashlib.sha256(f"{principal_type}:{principal_id}:{key}".encode()).digest()[:8],
        "big",
        signed=True,
    )
    db.execute(text("SELECT pg_advisory_xact_lock(:k)"), {"k": lock_id})
    row = db.scalar(
        select(IdempotencyKey).where(
            IdempotencyKey.principal_type == principal_type,
            IdempotencyKey.principal_id == principal_id,
            IdempotencyKey.key == key,
            IdempotencyKey.expires_at > now,
        )
    )
    if row is None:
        return None
    if row.request_hash != digest:
        raise ApiError(409, "idempotency_key_reused", "Idempotency-Key já usada com outro pedido.")
    return Stored(status=row.response_status, body=row.response_body)


def store(
    db: DbSession,
    principal_type: str,
    principal_id: uuid.UUID,
    key: str,
    digest: bytes,
    status: int,
    body: dict[str, Any],
    now: datetime,
) -> None:
    existing = db.get(IdempotencyKey, (principal_type, principal_id, key))
    if existing is not None:
        # Só chega aqui com chave vencida (lock_and_lookup devolveria a guardada):
        # regrava no lugar, porque o ares_app não tem DELETE.
        existing.request_hash = digest
        existing.response_status = status
        existing.response_body = body
        existing.created_at = now
        existing.expires_at = now + RETENTION
    else:
        db.add(
            IdempotencyKey(
                principal_type=principal_type,
                principal_id=principal_id,
                key=key,
                request_hash=digest,
                response_status=status,
                response_body=body,
                created_at=now,
                expires_at=now + RETENTION,
            )
        )
    db.flush()
