"""Formatos de identificadores, sem dependências (usado pelo cliente e pelo cofre)."""

import re
import uuid

CREDENTIAL = re.compile(r"^ares_agent_([0-9a-f]{32})\.[A-Za-z0-9_-]{43}$")
MODULE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")


def agent_id_from_credential(credential: str) -> str | None:
    """UUID (com hífens) embutido na credencial, ou ``None`` se o formato não bate."""
    match = CREDENTIAL.fullmatch(credential)
    return str(uuid.UUID(match.group(1))) if match else None


def is_ascii_number(value: str, max_digits: int = 18) -> bool:
    """Só dígitos ASCII (``str.isdigit`` aceita "²" e outros, que quebram ``int``)."""
    return value.isascii() and value.isdecimal() and 0 < len(value) <= max_digits
