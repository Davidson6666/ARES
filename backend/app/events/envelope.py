"""Envelope de evento v1: validação por evento (complemento, seção 6; ADR 0006).

Cada evento do lote é validado à parte: um evento inválido vira ``rejected``
com um ``error_code`` estável e **não derruba** os demais. O código e o nome do
campo nunca repetem o valor enviado.

Dados enviados por agentes são conteúdo NÃO CONFIÁVEL (CLAUDE.md, 9.1): aqui
só se valida forma e limites; nada é interpretado nem executado.
"""

import json
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, StrictInt, ValidationError, field_validator

from app.agents.models import Agent

MAX_BODY_BYTES = 2 * 1024 * 1024
MAX_EVENT_BYTES = 64 * 1024
MAX_DATA_BYTES = 16 * 1024
MAX_BATCH = 100
SUPPORTED_SCHEMA_VERSION = 1
_MAX_DEPTH = 32

_EVENT_TYPE = r"^[a-z][a-z0-9_]*\.[a-z][a-z0-9_]*$"
_MODULE = r"^[a-z][a-z0-9_]{0,63}$"


def _text(value: Any) -> str:
    if not isinstance(value, str):
        raise ValueError("deve ser texto")  # noqa: TRY004  (pydantic só converte ValueError)
    if any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise ValueError("caractere de controle")
    return value


class Source(BaseModel):
    model_config = ConfigDict(extra="forbid")
    module: str = Field(pattern=_MODULE)
    instance_id: str = Field(min_length=1, max_length=128)

    _instance = field_validator("instance_id", mode="before")(_text)


class Envelope(BaseModel):
    # Campo desconhecido no topo é rejeitado (complemento, seção 6). Isso inclui
    # ``observed_at``: o servidor é quem o define.
    model_config = ConfigDict(extra="forbid")

    event_id: uuid.UUID
    event_type: str = Field(pattern=_EVENT_TYPE, max_length=128)
    schema_version: StrictInt = Field(ge=1)
    occurred_at: datetime
    source: Source
    data_classification: Literal["public", "internal", "personal", "sensitive"]
    data: dict[str, Any]
    tenant_id: str | None = Field(default=None, min_length=1, max_length=128)
    device_id: str | None = Field(default=None, min_length=1, max_length=128)
    correlation_id: str | None = Field(default=None, min_length=1, max_length=128)
    severity: Literal["info", "low", "medium", "high", "critical"] | None = None

    @field_validator("event_id", "occurred_at", mode="before")
    @classmethod
    def _only_text(cls, value: Any) -> Any:
        # RFC 3339 e UUID chegam como texto: número, lista etc. não valem.
        if not isinstance(value, str):
            raise ValueError("deve ser texto")  # noqa: TRY004  (pydantic só converte ValueError)
        return value

    @field_validator("occurred_at")
    @classmethod
    def _aware(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("faltou o fuso (RFC 3339 UTC)")
        return value.astimezone(UTC)

    _ids = field_validator("tenant_id", "device_id", "correlation_id", mode="before")(
        lambda v: v if v is None else _text(v)
    )


@dataclass(frozen=True)
class Parsed:
    envelope: Envelope
    tenant_id: str | None
    flags: list[str]


@dataclass(frozen=True)
class Rejected:
    event_id: str | None
    code: str
    field: str | None = None


def reject_constant(name: str) -> Any:
    """json.loads: NaN e Infinity não são JSON e o JSONB do PostgreSQL os recusa."""
    raise ValueError(f"constante não permitida: {name}")


def _size(value: Any) -> int:
    return len(json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))


def _unsafe(value: Any, depth: int = 0) -> bool:
    """NUL (o JSONB o recusa) ou aninhamento profundo demais."""
    if depth > _MAX_DEPTH:
        return True
    if isinstance(value, str):
        return "\x00" in value
    if isinstance(value, list):
        return any(_unsafe(v, depth + 1) for v in value)
    if isinstance(value, dict):
        return any(_unsafe(k, depth + 1) or _unsafe(v, depth + 1) for k, v in value.items())
    return False


def _event_id_text(raw: dict[str, Any]) -> str | None:
    value = raw.get("event_id")
    try:
        return str(uuid.UUID(value)) if isinstance(value, str) else None
    except ValueError:
        return None


def _map_error(exc: ValidationError) -> Rejected | tuple[str, str | None]:
    err = exc.errors()[0]
    loc = [str(p) for p in err.get("loc", ())]
    field = ".".join(loc) or None
    kind = err.get("type", "")
    if kind == "extra_forbidden":
        return ("observed_at_not_allowed" if loc == ["observed_at"] else "unknown_field", field)
    if kind == "missing":
        return ("missing_field", field)
    return ("invalid_field", field)


def validate_event(raw: Any, agent: Agent, now: datetime, future_seconds: int) -> Parsed | Rejected:
    if not isinstance(raw, dict):
        return Rejected(None, "invalid_event")
    event_id = _event_id_text(raw)
    if _size(raw) > MAX_EVENT_BYTES:
        return Rejected(event_id, "event_too_large")
    data = raw.get("data")
    if isinstance(data, dict) and _size(data) > MAX_DATA_BYTES:
        return Rejected(event_id, "data_too_large", "data")
    if _unsafe(raw):
        return Rejected(event_id, "invalid_data")
    try:
        envelope = Envelope.model_validate(raw)
    except ValidationError as exc:
        code, field = _map_error(exc)  # type: ignore[misc]
        return Rejected(event_id, code, field)
    if envelope.schema_version != SUPPORTED_SCHEMA_VERSION:
        return Rejected(event_id, "unsupported_schema_version", "schema_version")
    # Vínculo de origem: o agente só fala por si (ADR 0006).
    if envelope.source.instance_id != str(agent.id) or envelope.source.module != agent.module:
        return Rejected(event_id, "source_mismatch", "source")
    if envelope.tenant_id is not None and envelope.tenant_id != agent.tenant_id:
        return Rejected(event_id, "tenant_mismatch", "tenant_id")
    flags: list[str] = []
    if envelope.occurred_at > now + timedelta(seconds=future_seconds):
        flags.append("occurred_at_future")  # aceito e marcado (teste 9.2)
    return Parsed(envelope=envelope, tenant_id=agent.tenant_id, flags=flags)
