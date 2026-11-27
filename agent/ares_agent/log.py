"""Log estruturado do agente: JSON, uma linha por registro (ADR 0007).

Caracteres de controle saem escapados (``json.dumps``), então um valor com ``\\n``
não vira linha nova. O log só leva contagens, códigos e motivos: nunca conteúdo de
evento nem credencial. Por garantia extra, qualquer coisa com o formato de
credencial de agente é mascarada.
"""

import json
import logging
import re
from datetime import UTC, datetime
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any

NAME = "ares.agent"
_CREDENTIAL = re.compile(r"ares_agent_[0-9a-f]{32}\.[A-Za-z0-9_-]{43}")
MAX_LOG_BYTES = 1024 * 1024
BACKUPS = 3


def redact(text: str) -> str:
    return _CREDENTIAL.sub("[credencial]", text)


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "time": datetime.fromtimestamp(record.created, UTC).isoformat(timespec="milliseconds"),
            "level": record.levelname.lower(),
            "event": record.getMessage(),
            "service": "ares-agent",
            **getattr(record, "fields", {}),
        }
        return redact(json.dumps(payload, ensure_ascii=True, default=str))


def setup(log_path: Path | None = None, *, stderr: bool = True) -> logging.Logger:
    logger = logging.getLogger(NAME)
    logger.setLevel(logging.INFO)
    logger.propagate = False
    for handler in list(logger.handlers):
        logger.removeHandler(handler)
        handler.close()
    formatter = JsonFormatter()
    handlers: list[logging.Handler] = []
    if log_path is not None:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        handlers.append(
            RotatingFileHandler(
                log_path, maxBytes=MAX_LOG_BYTES, backupCount=BACKUPS, encoding="utf-8"
            )
        )
    if stderr:
        handlers.append(logging.StreamHandler())
    for handler in handlers:
        handler.setFormatter(formatter)
        logger.addHandler(handler)
    return logger


def emit(logger: logging.Logger, level: int, event: str, **fields: Any) -> None:
    logger.log(level, event, extra={"fields": fields})
