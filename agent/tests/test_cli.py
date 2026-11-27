import io
import json
import logging
import sys
from collections.abc import Callable
from pathlib import Path

import httpx
import pytest

from ares_agent import cli, collector, credentials, log
from ares_agent import client as api
from ares_agent.store import Store
from tests.conftest import MemoryKeyring
from tests.helpers import AGENT_ID, CREDENTIAL


def stub_server(
    monkeypatch: pytest.MonkeyPatch, handler: Callable[[httpx.Request], httpx.Response]
) -> None:
    def build_http(base_url: str, ca_file: Path | None) -> httpx.Client:
        return httpx.Client(base_url=base_url, transport=httpx.MockTransport(handler))

    monkeypatch.setattr(api, "build_http", build_http)


def feed_token(monkeypatch: pytest.MonkeyPatch, token: str) -> None:
    monkeypatch.setattr(sys, "stdin", io.StringIO(token + "\n"))


ENROLLED = {"agent_id": AGENT_ID, "module": "endpoint", "credential": CREDENTIAL}


def test_the_token_is_never_a_command_line_argument() -> None:
    parser = cli.build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(["enroll", "--server", "https://x.test", "--token", "abc"])
    with pytest.raises(SystemExit):
        parser.parse_args(["enroll", "--server", "https://x.test", "abc"])


def test_enroll_stores_credential_in_the_vault_and_not_on_disk(
    monkeypatch: pytest.MonkeyPatch,
    memory_keyring: MemoryKeyring,
    agent_home: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    stub_server(monkeypatch, lambda r: httpx.Response(201, json=ENROLLED))
    feed_token(monkeypatch, "token-de-enrolamento-xyz")
    assert cli.main(["enroll", "--server", "https://core.test"]) == 0
    assert memory_keyring.items[("ares-agent", "credential")] == CREDENTIAL
    out = capsys.readouterr().out
    assert f"agent_id={AGENT_ID}" in out
    assert CREDENTIAL not in out and "token-de-enrolamento-xyz" not in out
    # Nada de segredo em arquivo: só config.toml (URL) e state.db (ids públicos).
    for path in agent_home.iterdir():
        content = path.read_bytes()
        assert CREDENTIAL.encode() not in content and b"token-de-enrolamento-xyz" not in content
    store = Store(agent_home / "state.db", 100, 10_000_000)
    assert store.get("agent_id") == AGENT_ID and store.get("module") == "endpoint"


def test_enroll_refuses_a_second_enrollment_without_force(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    calls: list[int] = []

    def handler(req: httpx.Request) -> httpx.Response:
        calls.append(1)
        return httpx.Response(201, json=ENROLLED)

    stub_server(monkeypatch, handler)
    feed_token(monkeypatch, "token-1-xxxxxxxxxxxxxxxxxxxx")
    assert cli.main(["enroll", "--server", "https://core.test"]) == 0
    feed_token(monkeypatch, "token-2-xxxxxxxxxxxxxxxxxxxx")
    assert cli.main(["enroll", "--server", "https://core.test"]) == cli.EXIT_ERROR
    assert "--force" in capsys.readouterr().out and len(calls) == 1
    feed_token(monkeypatch, "token-3-xxxxxxxxxxxxxxxxxxxx")
    assert cli.main(["enroll", "--server", "https://core.test", "--force"]) == 0
    assert len(calls) == 2


def test_enroll_failure_leaves_nothing_behind(
    monkeypatch: pytest.MonkeyPatch,
    memory_keyring: MemoryKeyring,
    capsys: pytest.CaptureFixture[str],
) -> None:
    stub_server(monkeypatch, lambda r: httpx.Response(401, json={"code": "invalid_enrollment"}))
    feed_token(monkeypatch, "token-errado-xxxxxxxxxxxxxxxx")
    assert cli.main(["enroll", "--server", "https://core.test"]) == cli.EXIT_ERROR
    out = capsys.readouterr().out
    assert "inválido ou expirado" in out and "token-errado" not in out
    assert memory_keyring.items == {}


def test_enroll_validates_the_server_url_before_anything(
    monkeypatch: pytest.MonkeyPatch, agent_home: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    called: list[int] = []

    def handler(req: httpx.Request) -> httpx.Response:
        called.append(1)
        return httpx.Response(201, json=ENROLLED)

    stub_server(monkeypatch, handler)
    feed_token(monkeypatch, "token-xxxxxxxxxxxxxxxxxxxxxxxx")
    assert cli.main(["enroll", "--server", "http://core.lab.example"]) == cli.EXIT_ERROR
    assert "https://" in capsys.readouterr().out and called == []
    assert not (agent_home / "config.toml").exists()


def test_enroll_empty_token(monkeypatch: pytest.MonkeyPatch) -> None:
    stub_server(monkeypatch, lambda r: httpx.Response(201, json=ENROLLED))
    feed_token(monkeypatch, "")
    assert cli.main(["enroll", "--server", "https://core.test"]) == cli.EXIT_ERROR


def test_enroll_fails_closed_when_the_vault_fails(
    monkeypatch: pytest.MonkeyPatch, memory_keyring: MemoryKeyring
) -> None:
    from keyring.errors import KeyringError

    def broken(*a: object) -> None:
        raise KeyringError("cofre indisponível")

    monkeypatch.setattr(memory_keyring, "set_password", broken)
    stub_server(monkeypatch, lambda r: httpx.Response(201, json=ENROLLED))
    feed_token(monkeypatch, "token-xxxxxxxxxxxxxxxxxxxxxxxx")
    assert cli.main(["enroll", "--server", "https://core.test"]) == cli.EXIT_ERROR


def test_status_has_no_secrets(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    stub_server(monkeypatch, lambda r: httpx.Response(201, json=ENROLLED))
    feed_token(monkeypatch, "token-xxxxxxxxxxxxxxxxxxxxxxxx")
    cli.main(["enroll", "--server", "https://core.test"])
    capsys.readouterr()
    assert cli.main(["status"]) == 0
    out = capsys.readouterr().out
    report = json.loads(out)
    assert report["agent_id"] == AGENT_ID and report["queued_events"] == 0
    assert CREDENTIAL not in out and "A" * 43 not in out


def test_run_exits_2_when_the_server_rejects_the_credential(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    stub_server(monkeypatch, lambda r: httpx.Response(201, json=ENROLLED))
    feed_token(monkeypatch, "token-xxxxxxxxxxxxxxxxxxxxxxxx")
    cli.main(["enroll", "--server", "https://core.test"])
    stub_server(monkeypatch, lambda r: httpx.Response(401, json={"code": "unauthenticated"}))
    monkeypatch.setattr(collector, "check_access", lambda: None)
    monkeypatch.setattr(collector, "latest_record_id", lambda: 0)
    monkeypatch.setattr(collector, "query", lambda after, limit: "")
    capsys.readouterr()
    assert cli.main(["run"]) == cli.EXIT_REJECTED
    assert "revogada" in capsys.readouterr().out
    log.setup(None, stderr=False)


def test_run_explains_missing_security_log_access(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    stub_server(monkeypatch, lambda r: httpx.Response(201, json=ENROLLED))
    feed_token(monkeypatch, "token-xxxxxxxxxxxxxxxxxxxxxxxx")
    cli.main(["enroll", "--server", "https://core.test"])

    def denied() -> None:
        raise collector.AccessDenied("Sem acesso ao Security log. Adicione ... 'Event Log Readers'")

    monkeypatch.setattr(collector, "check_access", denied)
    capsys.readouterr()
    assert cli.main(["run"]) == cli.EXIT_ERROR
    assert "Event Log Readers" in capsys.readouterr().out


def test_run_and_status_need_enrollment(capsys: pytest.CaptureFixture[str]) -> None:
    assert cli.main(["run"]) == cli.EXIT_ERROR
    assert cli.main(["status"]) == cli.EXIT_ERROR
    assert "enroll" in capsys.readouterr().out


def test_a_corrupted_vault_entry_is_refused() -> None:
    with pytest.raises(credentials.CredentialStoreError):
        credentials.parse_agent_id("não é credencial")
    with pytest.raises(credentials.CredentialStoreError):
        credentials.save("ares_agent_zz.xx")


# --- log ---------------------------------------------------------------------------


def test_log_lines_escape_control_characters_and_mask_credentials() -> None:
    stream = io.StringIO()
    logger = log.setup(None, stderr=False)
    handler = logging.StreamHandler(stream)
    handler.setFormatter(log.JsonFormatter())
    logger.addHandler(handler)
    log.emit(logger, logging.WARNING, "teste\nlinha-falsa", reason="a\r\nb", token=CREDENTIAL)
    lines = stream.getvalue().splitlines()
    assert len(lines) == 1  # quebra de linha não vira linha nova
    record = json.loads(lines[0])
    assert record["event"] == "teste\nlinha-falsa" and record["level"] == "warning"
    assert CREDENTIAL not in lines[0] and "[credencial]" in lines[0]
    assert record["service"] == "ares-agent"


def test_log_file_rotates(tmp_path: Path) -> None:
    logger = log.setup(tmp_path / "agent.log", stderr=False)
    log.emit(logger, logging.INFO, "um")
    handler = logger.handlers[0]
    assert getattr(handler, "maxBytes", 0) == log.MAX_LOG_BYTES
    assert getattr(handler, "backupCount", 0) == log.BACKUPS
    assert json.loads((tmp_path / "agent.log").read_text("utf-8").strip())["event"] == "um"
