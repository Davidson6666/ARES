"""Endurecimento apontado na revisão de segurança da fase 04a (ADR 0007)."""

import io
import json
import sys
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx
import keyring
import pytest

from ares_agent import cli, collector, credentials, mapping
from ares_agent import client as api
from ares_agent.client import BatchRefused, EnrollmentError, RetryLater, ServerClient
from ares_agent.config import ConfigError, normalize_server_url
from ares_agent.store import Store
from tests.conftest import MemoryKeyring
from tests.helpers import AGENT_ID, CREDENTIAL, event_xml, logon_failure

Handler = Callable[[httpx.Request], httpx.Response]


def make(handler: Handler) -> ServerClient:
    http = httpx.Client(base_url="https://core.test", transport=httpx.MockTransport(handler))
    return ServerClient(http, CREDENTIAL)


def events(n: int = 1) -> list[dict[str, Any]]:
    return [{"event_id": f"00000000-0000-4000-8000-00000000000{i}"} for i in range(n)]


# --- servidor hostil: nada disto pode derrubar o agente ------------------------------


@pytest.mark.parametrize("value", ["²", "9" * 5000, "-5", "1e3", " ", "١٢٣", ""])
def test_hostile_retry_after_never_raises(value: str) -> None:
    raw = [(b"Retry-After", value.encode("utf-8"))]  # bytes crus, como chegam pela rede
    client = make(lambda r: httpx.Response(429, headers=raw))
    with pytest.raises(RetryLater) as slow:
        client.post_events(events())
    assert slow.value.delay is None


def test_deeply_nested_json_is_handled_everywhere() -> None:
    bomb = b"[" * 200_000
    with pytest.raises(BatchRefused) as refused:
        make(lambda r: httpx.Response(422, content=bomb)).post_events(events())
    assert refused.value.code == "unknown"
    with pytest.raises(RetryLater, match="invalid_response"):
        make(lambda r: httpx.Response(202, content=bomb)).post_events(events())
    with pytest.raises(EnrollmentError):
        make(lambda r: httpx.Response(201, content=bomb)).enroll("t", "h")


@pytest.mark.parametrize("bad_code", [["x"], {"a": 1}, "a" * 5000, "com espaço", 7, "ação"])
def test_hostile_error_codes_are_dropped(bad_code: Any) -> None:
    evs = events()
    item = {"event_id": evs[0]["event_id"], "outcome": "rejected", "error_code": bad_code}
    (result,) = make(lambda r: httpx.Response(202, json={"results": [item]})).post_events(evs)
    assert result.outcome == "rejected" and result.error_code is None


def test_environment_proxy_is_not_inherited(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"):
        monkeypatch.setenv(name, "http://127.0.0.1:9")
    http = api.build_http("http://127.0.0.1:8000", None)
    assert http.trust_env is False
    http.close()


def test_response_has_a_total_deadline(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(api, "RESPONSE_DEADLINE_SECONDS", -1.0)
    with pytest.raises(RetryLater, match="response_too_slow"):
        make(lambda r: httpx.Response(202, content=b"{}")).post_events(events())


@pytest.mark.parametrize(
    "body",
    [
        {"agent_id": AGENT_ID, "module": "BAD\nMODULE", "credential": CREDENTIAL},
        {"agent_id": AGENT_ID, "module": "m" * 500, "credential": CREDENTIAL},
        {
            "agent_id": "11111111-1111-4111-8111-111111111111",
            "module": "endpoint",
            "credential": CREDENTIAL,
        },
        {"agent_id": AGENT_ID, "module": "endpoint", "credential": "ares_agent_zz.xx"},
        {"agent_id": "\x1b[31mX", "module": "endpoint", "credential": CREDENTIAL},
        [],
    ],
)
def test_enrollment_response_is_validated(body: Any) -> None:
    with pytest.raises(EnrollmentError):
        make(lambda r: httpx.Response(201, json=body)).enroll("t", "h")


# --- config, coleta e mapeamento -------------------------------------------------------


@pytest.mark.parametrize("value", ['https://a"b.example', "https://a\\b.example"])
def test_quotes_and_backslashes_cannot_break_the_toml(value: str) -> None:
    with pytest.raises(ConfigError):
        normalize_server_url(value)


def test_non_ascii_digits_in_ids_are_ignored_not_fatal() -> None:
    bad = logon_failure(7).replace("<EventRecordID>7<", "<EventRecordID>²<")
    assert [e.record_id for e in collector.parse_events(bad + logon_failure(8))] == [8]


def test_wevtutil_path_is_absolute_and_under_the_windows_directory() -> None:
    path = collector.wevtutil_path()
    assert path.is_absolute() and path.name == "wevtutil.exe" and path.parent.name == "System32"


def test_epoch_changes_the_event_id_but_epoch_zero_keeps_it_stable() -> None:
    assert mapping.make_event_id(AGENT_ID, 5, 0) == mapping.make_event_id(AGENT_ID, 5)
    assert mapping.make_event_id(AGENT_ID, 5, 1) != mapping.make_event_id(AGENT_ID, 5, 0)


def test_non_ascii_digit_in_logon_type_never_raises() -> None:
    (raw,) = collector.parse_events(event_xml(4624, 1, {"LogonType": "²"}))
    env = mapping.to_envelope(raw, AGENT_ID, "endpoint")
    assert env is not None and env["data"]["logon_type"] is None


def test_priority_protects_account_and_group_events() -> None:
    assert mapping.priority(4625) == mapping.priority(4624) == 0
    assert all(mapping.priority(i) == 1 for i in (4648, 4672, 4720, 4732))
    assert mapping.OVERFLOW_PRIORITY > 1


def test_log_reset_event() -> None:
    now = datetime(2026, 11, 27, 20, 0, 0, tzinfo=UTC)
    env = mapping.log_reset_envelope(AGENT_ID, "endpoint", 2, 900, now)
    other = mapping.log_reset_envelope(AGENT_ID, "endpoint", 3, 900, now)
    assert env["event_type"] == "agent.log_reset"
    assert env["data"] == {"epoch": 2, "previous_record_id": 900}
    assert env["event_id"] != other["event_id"]


# --- CLI e cofre ---------------------------------------------------------------------


ENROLLED = {"agent_id": AGENT_ID, "module": "endpoint", "credential": CREDENTIAL}


def stub_server(monkeypatch: pytest.MonkeyPatch, handler: Handler) -> None:
    def build_http(base_url: str, ca_file: Path | None) -> httpx.Client:
        return httpx.Client(base_url=base_url, transport=httpx.MockTransport(handler))

    monkeypatch.setattr(api, "build_http", build_http)


def feed_token(monkeypatch: pytest.MonkeyPatch, token: str) -> None:
    monkeypatch.setattr(sys, "stdin", io.StringIO(token + "\n"))


def test_force_discards_the_old_queue_and_says_so(
    monkeypatch: pytest.MonkeyPatch, agent_home: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    stub_server(monkeypatch, lambda r: httpx.Response(201, json=ENROLLED))
    feed_token(monkeypatch, "token-1-xxxxxxxxxxxxxxxxxxxx")
    cli.main(["enroll", "--server", "https://core.test"])
    store = Store(agent_home / "state.db", 100, 10_000_000)
    store.enqueue([("a", "x", 1), ("b", "x", 1)], collected_record_id=40)
    store.close()
    feed_token(monkeypatch, "token-2-xxxxxxxxxxxxxxxxxxxx")
    capsys.readouterr()
    assert cli.main(["enroll", "--server", "https://core.test", "--force"]) == 0
    assert "2 evento(s)" in capsys.readouterr().out
    store = Store(agent_home / "state.db", 100, 10_000_000)
    assert store.stats()["queued_events"] == 0 and store.get("collected_record_id") is None


def test_failure_after_the_token_is_spent_tells_the_operator_what_to_do(
    monkeypatch: pytest.MonkeyPatch,
    memory_keyring: MemoryKeyring,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from keyring.errors import KeyringError

    def broken(*a: object) -> None:
        raise KeyringError("cofre indisponível")

    monkeypatch.setattr(memory_keyring, "set_password", broken)
    stub_server(monkeypatch, lambda r: httpx.Response(201, json=ENROLLED))
    feed_token(monkeypatch, "token-xxxxxxxxxxxxxxxxxxxxxxxx")
    assert cli.main(["enroll", "--server", "https://core.test"]) == cli.EXIT_ERROR
    out = capsys.readouterr().out
    assert AGENT_ID in out and "revogue" in out.lower() and "novo token" in out


def test_a_plaintext_keyring_backend_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    class PlaintextKeyring(MemoryKeyring):
        pass

    monkeypatch.setattr(credentials, "TRUSTED_BACKENDS", {"WinVaultKeyring"})
    keyring.set_keyring(PlaintextKeyring())
    with pytest.raises(credentials.CredentialStoreError, match="não grava credencial em arquivo"):
        credentials.save(CREDENTIAL)
    with pytest.raises(credentials.CredentialStoreError):
        credentials.load()


def test_status_shows_the_collection_lag(
    monkeypatch: pytest.MonkeyPatch, agent_home: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    stub_server(monkeypatch, lambda r: httpx.Response(201, json=ENROLLED))
    feed_token(monkeypatch, "token-xxxxxxxxxxxxxxxxxxxxxxxx")
    cli.main(["enroll", "--server", "https://core.test"])
    store = Store(agent_home / "state.db", 100, 10_000_000)
    store.put("collected_record_id", "100")
    store.put("log_latest_record_id", "350")
    store.close()
    capsys.readouterr()
    cli.main(["status"])
    assert json.loads(capsys.readouterr().out)["collection_lag"] == 250
