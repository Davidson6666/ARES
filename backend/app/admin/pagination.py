"""Paginação por cursor das listas de administração (CLAUDE.md, seção 7.2).

O cursor é opaco para o cliente, mas NÃO assinado: ele só guarda a posição (os valores
da chave de ordenação). Nenhuma decisão de acesso depende dele, porque o escopo do
usuário é aplicado na consulta; um cursor forjado só muda de onde a lista continua.
Cursor malformado é 400 (complemento 3.4).
"""

import base64
import binascii
import json
from collections.abc import Sequence

from fastapi import Query

from app.core.errors import ApiError

DEFAULT_LIMIT = 50
MAX_LIMIT = 200


def limit_param(limit: int = Query(DEFAULT_LIMIT, ge=1, le=MAX_LIMIT)) -> int:
    return limit


def encode(values: Sequence[str]) -> str:
    raw = json.dumps(list(values), separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def decode(cursor: str | None, size: int) -> list[str] | None:
    """Valores da posição, ``None`` se não há cursor. Malformado: 400."""
    if cursor is None:
        return None
    try:
        padded = cursor + "=" * (-len(cursor) % 4)
        values = json.loads(base64.urlsafe_b64decode(padded.encode()))
    except ValueError, binascii.Error, RecursionError:
        raise _invalid() from None
    if (
        not isinstance(values, list)
        or len(values) != size
        or not all(isinstance(v, str) and len(v) <= 128 for v in values)
    ):
        raise _invalid()
    return [str(v) for v in values]


def _invalid() -> ApiError:
    return ApiError(400, "invalid_cursor", "Cursor inválido.")
