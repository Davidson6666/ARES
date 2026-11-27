"""Leitura da trilha de auditoria (v1.1, seção 15: GET /api/v1/audit-logs).

Exige ``audit.read``. Paginação por cursor, da entrada mais recente para a
mais antiga. Não há rota de escrita, alteração ou exclusão.
"""

import base64
import binascii
import uuid
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession

from app.audit.models import AuditLog
from app.auth.dependencies import allow_query, get_db, require_permission
from app.auth.service import AuthContext
from app.core.errors import ApiError

router = APIRouter(prefix="/api/v1")

_require_audit_read = require_permission("audit.read")
_MAX_CURSOR_LENGTH = 32


class AuditItem(BaseModel):
    id: int
    occurred_at: datetime
    actor_type: str
    actor_user_id: uuid.UUID | None
    action: str
    resource_type: str | None
    resource_id: str | None
    result: str
    reason: str | None
    request_id: uuid.UUID | None
    correlation_id: str | None
    details: dict[str, Any]
    entry_hash: str


class AuditPage(BaseModel):
    items: list[AuditItem]
    next_cursor: str | None


def _encode_cursor(entry_id: int) -> str:
    return base64.urlsafe_b64encode(str(entry_id).encode("ascii")).rstrip(b"=").decode("ascii")


def _decode_cursor(cursor: str) -> int:
    # Opaco por contrato; contém o id da última entrada da página (ADR 0003).
    try:
        if len(cursor) > _MAX_CURSOR_LENGTH:
            raise ValueError
        raw = base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4)).decode("ascii")
        if not raw.isdigit():
            raise ValueError
        return int(raw)
    except binascii.Error, UnicodeDecodeError, ValueError:
        raise ApiError(400, "invalid_cursor", "Cursor inválido.") from None


@router.get(
    "/audit-logs",
    response_model=AuditPage,
    dependencies=[Depends(allow_query("limit", "cursor"))],
)
def list_audit_logs(
    limit: int = Query(default=50, ge=1, le=200),
    cursor: str | None = Query(default=None),
    _: AuthContext = Depends(_require_audit_read),
    db: DbSession = Depends(get_db),
) -> AuditPage:
    query = select(AuditLog).order_by(AuditLog.id.desc()).limit(limit + 1)
    if cursor is not None:
        query = query.where(AuditLog.id < _decode_cursor(cursor))
    rows = list(db.scalars(query))
    page, more = rows[:limit], len(rows) > limit
    return AuditPage(
        items=[
            AuditItem(
                id=e.id,
                occurred_at=e.occurred_at,
                actor_type=e.actor_type,
                actor_user_id=e.actor_user_id,
                action=e.action,
                resource_type=e.resource_type,
                resource_id=e.resource_id,
                result=e.result,
                reason=e.reason,
                request_id=e.request_id,
                correlation_id=e.correlation_id,
                details=e.details,
                entry_hash=e.entry_hash.hex(),
            )
            for e in page
        ],
        next_cursor=_encode_cursor(page[-1].id) if more and page else None,
    )
