"""Gravação e verificação da trilha de auditoria (ADR 0004; v1.1, seção 14.8).

``record`` adiciona a entrada à transação corrente e NÃO faz commit: quem
chama grava a ação e a auditoria juntas. Se a auditoria falhar, a ação
também não é gravada.

Encadeamento: ``entry_hash = SHA-256(prev_hash || JSON canônico da entrada)``.
A verificação detecta mudança em qualquer entrada antes da cabeça; a remoção
das últimas entradas só é detectada com uma âncora externa (``verify_chain``).
Um advisory lock serializa as gravações (do lock ao commit), então a ordem
de ``id`` é a ordem da cadeia e não há bifurcação.

Nunca coloque em ``details`` senha, token, segredo ou dado pessoal
desnecessário. IP e e-mail de conta desconhecida não são gravados (decisão
do autor, 26/11/2026).
"""

import hashlib
import json
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Literal

from sqlalchemy import select, text
from sqlalchemy.orm import Session as DbSession

from app.audit.models import AuditLog

GENESIS_HASH = b"\x00" * 32
AUDIT_LOCK_KEY = 0x41554454  # "AUDT"

ActorType = Literal["user", "system", "anonymous"]
Result = Literal["success", "failure", "denied"]


def _canonical(entry: AuditLog) -> bytes:
    payload = {
        "occurred_at": entry.occurred_at.astimezone(UTC).isoformat(timespec="microseconds"),
        "actor_type": entry.actor_type,
        "actor_user_id": str(entry.actor_user_id) if entry.actor_user_id else None,
        "action": entry.action,
        "resource_type": entry.resource_type,
        "resource_id": entry.resource_id,
        "result": entry.result,
        "reason": entry.reason,
        "request_id": str(entry.request_id) if entry.request_id else None,
        "correlation_id": entry.correlation_id,
        "details": entry.details,
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def compute_hash(prev_hash: bytes, entry: AuditLog) -> bytes:
    return hashlib.sha256(prev_hash + _canonical(entry)).digest()


def _check_details(value: Any, depth: int = 0) -> None:
    """JSONB reescreve floats (1e16 vira int, -0.0 vira 0.0) e exige chaves
    str: o hash calculado aqui não conferiria na releitura. Só str, int,
    bool, None, listas e dicts com chave str."""
    if depth > 8:
        raise ValueError("details aninhado demais")
    if value is None or isinstance(value, str | bool | int):
        return
    if isinstance(value, list):
        for item in value:
            _check_details(item, depth + 1)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise TypeError("chave de details precisa ser str")
            _check_details(item, depth + 1)
        return
    raise TypeError(f"tipo não permitido em details: {type(value).__name__}")


def record(
    db: DbSession,
    *,
    action: str,
    result: Result,
    actor_type: ActorType,
    actor_user_id: uuid.UUID | None = None,
    resource_type: str | None = None,
    resource_id: str | None = None,
    reason: str | None = None,
    request_id: str | uuid.UUID | None = None,
    correlation_id: str | None = None,
    details: dict[str, Any] | None = None,
    now: datetime | None = None,
) -> AuditLog:
    _check_details(details or {})
    db.execute(text("SELECT pg_advisory_xact_lock(:k)"), {"k": AUDIT_LOCK_KEY})
    prev = db.scalar(select(AuditLog.entry_hash).order_by(AuditLog.id.desc()).limit(1))
    occurred = (now or datetime.now(UTC)).astimezone(UTC)
    # Precisão de microssegundo, igual à do timestamptz: o hash confere na releitura.
    entry = AuditLog(
        occurred_at=occurred,
        actor_type=actor_type,
        actor_user_id=actor_user_id,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        result=result,
        reason=reason,
        request_id=uuid.UUID(str(request_id)) if request_id else None,
        correlation_id=correlation_id,
        details=details or {},
        prev_hash=prev or GENESIS_HASH,
    )
    entry.entry_hash = compute_hash(entry.prev_hash, entry)
    db.add(entry)
    db.flush()
    return entry


@dataclass(frozen=True)
class VerifyResult:
    ok: bool
    checked: int
    first_bad_id: int | None = None
    problem: str | None = None
    # Cabeça da cadeia (última entrada). Guarde fora do servidor: é a âncora
    # que permite detectar a remoção das últimas entradas.
    head_id: int | None = None
    head_hash: bytes | None = None


def verify_chain(
    db: DbSession,
    batch_size: int = 1000,
    expected_head: tuple[int, bytes] | None = None,
) -> VerifyResult:
    """Confere o encadeamento do início ao fim.

    Sozinha, a verificação detecta alteração, remoção ou inserção em qualquer
    ponto ANTES da última entrada. Remover as últimas entradas deixa uma
    cadeia válida e mais curta: para detectar isso, passe ``expected_head``
    (id e entry_hash de uma cabeça anotada antes, fora do servidor). A
    verificação falha se essa entrada não existir ou tiver outro hash.
    """
    expected_prev = GENESIS_HASH
    checked = 0
    last_id = 0
    head: AuditLog | None = None
    anchor_seen = expected_head is None
    while True:
        rows = db.scalars(
            select(AuditLog).where(AuditLog.id > last_id).order_by(AuditLog.id).limit(batch_size)
        ).all()
        if not rows:
            if not anchor_seen:
                return VerifyResult(
                    False,
                    checked,
                    expected_head[0] if expected_head else None,
                    "âncora ausente: entradas finais removidas?",
                    head.id if head else None,
                    head.entry_hash if head else None,
                )
            return VerifyResult(
                True,
                checked,
                head_id=head.id if head else None,
                head_hash=head.entry_hash if head else None,
            )
        for entry in rows:
            if entry.prev_hash != expected_prev:
                return VerifyResult(False, checked, entry.id, "prev_hash não confere")
            if compute_hash(entry.prev_hash, entry) != entry.entry_hash:
                return VerifyResult(False, checked, entry.id, "entry_hash não confere")
            if expected_head is not None and entry.id == expected_head[0]:
                if entry.entry_hash != expected_head[1]:
                    return VerifyResult(False, checked, entry.id, "âncora não confere")
                anchor_seen = True
            expected_prev = entry.entry_hash
            checked += 1
            last_id = entry.id
            head = entry
