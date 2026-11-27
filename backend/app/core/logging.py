"""Logs operacionais estruturados (v1.1, seção 14.8; CLAUDE.md, seção 9.1).

- Uma linha JSON por evento. O JSON escapa ``\\n``, ``\\r`` e demais
  caracteres de controle: um valor com quebra de linha não gera linha
  forjada (teste de aceitação da seção 9.2).
- Timestamp UTC, nível, serviço, logger e request_id quando houver.
- Chaves sensíveis são redigidas antes de serializar, em qualquer nível de
  aninhamento: senha, token, cookie, segredo, autorização, CSRF.

Limites: valor sensível sob chave inocente não é redigido; texto de
exceção e mensagens stdlib formatadas com ``%s`` também não. Não passe
segredos para o log.

Logs operacionais não substituem a auditoria (tabela ``audit_logs``).
"""

import logging
import sys
from collections.abc import Mapping, MutableMapping
from typing import Any, TextIO

import structlog

REDACTED = "[redigido]"
SERVICE = "ares-core"
_SENSITIVE_PARTS = (
    "password",
    "passwd",
    "pwd",
    "senha",
    "token",
    "secret",
    "cookie",
    "authorization",
    "csrf",
    "credential",
    "otp",
    "mfa",
    "recovery",
    "api_key",
    "apikey",
    "private_key",
)


def _is_sensitive(key: str) -> bool:
    lowered = key.lower()
    return any(part in lowered for part in _SENSITIVE_PARTS)


def _redact(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {k: REDACTED if _is_sensitive(str(k)) else _redact(v) for k, v in value.items()}
    if isinstance(value, list | tuple):
        return [_redact(v) for v in value]
    return value


def redact_sensitive(
    _logger: Any, _method: str, event_dict: MutableMapping[str, Any]
) -> MutableMapping[str, Any]:
    for key in list(event_dict):
        if _is_sensitive(key):
            event_dict[key] = REDACTED
        else:
            event_dict[key] = _redact(event_dict[key])
    return event_dict


def _opaque(value: Any) -> str:
    return f"<{type(value).__name__}>"


def add_service(
    _logger: Any, _method: str, event_dict: MutableMapping[str, Any]
) -> MutableMapping[str, Any]:
    event_dict.setdefault("service", SERVICE)
    return event_dict


def configure_logging(level: str = "INFO", stream: TextIO | None = None) -> None:
    """Configura structlog e o logging padrão (uvicorn, sqlalchemy) para
    saírem no mesmo formato JSON."""
    shared: list[Any] = [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_log_level,
        structlog.stdlib.add_logger_name,
        add_service,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        redact_sensitive,
        structlog.processors.format_exc_info,
    ]
    structlog.configure(
        processors=[*shared, structlog.stdlib.ProcessorFormatter.wrap_for_formatter],
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=False,
    )
    formatter = structlog.stdlib.ProcessorFormatter(
        foreign_pre_chain=shared,
        processors=[
            structlog.stdlib.ProcessorFormatter.remove_processors_meta,
            # Objeto desconhecido vira só o nome do tipo: um modelo com senha
            # não vai para o log pelo repr.
            structlog.processors.JSONRenderer(ensure_ascii=True, default=_opaque),
        ],
    )
    handler = logging.StreamHandler(stream or sys.stdout)
    handler.setFormatter(formatter)
    root = logging.getLogger()
    root.handlers = [handler]
    root.setLevel(level)
    # Uvicorn: o log de acesso é feito pelo middleware (com request_id).
    for name in ("uvicorn", "uvicorn.error", "uvicorn.access"):
        logging.getLogger(name).handlers = []
        logging.getLogger(name).propagate = True
    logging.getLogger("uvicorn.access").disabled = True
    # Clientes HTTP registram a URL completa (com query) em INFO.
    for name in ("httpx", "httpcore"):
        logging.getLogger(name).setLevel(logging.WARNING)
