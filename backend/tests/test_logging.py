"""Logs estruturados (v1.1, seção 14.8; CLAUDE.md, seção 9.2)."""

import io
import json
import logging
from collections.abc import Iterator

import pytest
import structlog
from fastapi.testclient import TestClient

from app.core.config import Settings
from app.core.logging import REDACTED, configure_logging
from app.main import create_app


@pytest.fixture
def stream() -> Iterator[io.StringIO]:
    buf = io.StringIO()
    configure_logging("INFO", stream=buf)
    yield buf
    configure_logging("INFO")


def lines(buf: io.StringIO) -> list[dict[str, object]]:
    return [json.loads(line) for line in buf.getvalue().splitlines() if line]


def test_newline_in_value_produces_single_line(stream: io.StringIO) -> None:
    # 9.2: "Evento com \n gera uma linha."
    structlog.get_logger("t").info("evento", campo='a\n{"level":"critical"}\r\nb\x1b[31m')
    raw = stream.getvalue()
    assert raw.count("\n") == 1
    [entry] = lines(stream)
    assert entry["campo"] == 'a\n{"level":"critical"}\r\nb\x1b[31m'
    assert entry["level"] == "info"
    assert entry["service"] == "ares-core"
    assert str(entry["timestamp"]).endswith("Z")


def test_sensitive_keys_are_redacted(stream: io.StringIO) -> None:
    structlog.get_logger("t").info(
        "evento",
        password="p1",
        session_token="t1",
        nested={"Authorization": "Bearer x", "ok": 1, "deep": [{"csrf": "c"}]},
    )
    [entry] = lines(stream)
    assert entry["password"] == REDACTED
    assert entry["session_token"] == REDACTED
    assert entry["nested"] == {"Authorization": REDACTED, "ok": 1, "deep": [{"csrf": REDACTED}]}
    assert "p1" not in stream.getvalue() and "Bearer x" not in stream.getvalue()


def test_stdlib_logs_use_same_json_format(stream: io.StringIO) -> None:
    logging.getLogger("sqlalchemy.engine").warning("linha\nforjada")
    [entry] = lines(stream)
    assert entry["event"] == "linha\nforjada"
    assert entry["logger"] == "sqlalchemy.engine"


def test_access_log_has_request_id_and_no_query(stream: io.StringIO) -> None:
    app = create_app(Settings(_env_file=None, env="test"))
    configure_logging("INFO", stream=stream)  # create_app reconfigura
    r = TestClient(app).get("/health", params={"token": "segredo"})
    access = [e for e in lines(stream) if e.get("event") == "request"]
    assert len(access) == 1
    assert access[0]["request_id"] == r.headers["X-Request-ID"]
    assert access[0]["path"] == "/health"
    assert access[0]["status"] == 200
    assert "segredo" not in stream.getvalue()


def test_unknown_objects_are_not_rendered_by_repr(stream: io.StringIO) -> None:
    class Login:
        def __repr__(self) -> str:
            return "Login(password='p-secreta')"

    structlog.get_logger("t").info("evento", body=Login(), api_key="k", totp_code="123456")
    [entry] = lines(stream)
    assert entry["body"] == "<Login>"
    assert entry["api_key"] == REDACTED
    assert entry["totp_code"] == REDACTED
    assert "p-secreta" not in stream.getvalue()
