from pathlib import Path

import pytest

from ares_agent.config import (
    ConfigError,
    default_home,
    load_config,
    normalize_server_url,
    write_initial_config,
)


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("https://core.lab.example", "https://core.lab.example"),
        ("https://core.lab.example:8443/", "https://core.lab.example:8443"),
        ("http://localhost:8000", "http://localhost:8000"),
        ("http://127.0.0.1:8000", "http://127.0.0.1:8000"),
        ("http://[::1]:8000", "http://[::1]:8000"),
    ],
)
def test_valid_server_urls(value: str, expected: str) -> None:
    assert normalize_server_url(value) == expected


@pytest.mark.parametrize(
    "value",
    [
        "http://core.lab.example",  # http fora de loopback
        "http://10.0.0.5:8000",
        "http://localhost.evil.example",
        "ftp://core.lab.example",
        "core.lab.example",
        "https://",
        "https://user:pw@core.lab.example",
        "https://core.lab.example/api",
        "https://core.lab.example/?a=1",
        "https://core.lab.example/#x",
        "https://core.lab.example:99999",
        "https://core.lab.example\n",
        "https://core .lab.example",
        "",
        None,
        42,
    ],
)
def test_invalid_server_urls_are_refused(value: object) -> None:
    with pytest.raises(ConfigError):
        normalize_server_url(value)


def test_load_config_defaults_and_overrides(agent_home: Path) -> None:
    agent_home.mkdir(parents=True)
    (agent_home / "config.toml").write_text(
        'server_url = "https://core.lab.example"\npoll_interval_seconds = 30\n', encoding="utf-8"
    )
    cfg = load_config()
    assert cfg.server_url == "https://core.lab.example"
    assert cfg.poll_interval_seconds == 30
    assert cfg.batch_size == 100 and cfg.ca_file is None
    assert cfg.store_path == agent_home / "state.db"


@pytest.mark.parametrize(
    "line",
    [
        "verify = false",  # não existe opção que desligue a verificação de certificado
        "verify_tls = false",
        "typo_key = 1",
        "poll_interval_seconds = 1",
        "poll_interval_seconds = true",
        'poll_interval_seconds = "15"',
        "batch_size = 101",
        "batch_size = 0",
        'ca_file = "C:/nao/existe.pem"',
    ],
)
def test_invalid_config_is_refused(agent_home: Path, line: str) -> None:
    agent_home.mkdir(parents=True)
    (agent_home / "config.toml").write_text(
        f'server_url = "https://core.lab.example"\n{line}\n', encoding="utf-8"
    )
    with pytest.raises(ConfigError):
        load_config()


def test_missing_or_broken_config(agent_home: Path) -> None:
    with pytest.raises(ConfigError):
        load_config()
    agent_home.mkdir(parents=True)
    (agent_home / "config.toml").write_text("isto não é toml [[[", encoding="utf-8")
    with pytest.raises(ConfigError):
        load_config()
    (agent_home / "config.toml").write_text("batch_size = 10\n", encoding="utf-8")
    with pytest.raises(ConfigError, match="server_url"):
        load_config()


def test_ca_file_must_exist_and_is_loaded(agent_home: Path, tmp_path: Path) -> None:
    ca = tmp_path / "ca.pem"
    ca.write_text("-----BEGIN CERTIFICATE-----\n", encoding="utf-8")
    agent_home.mkdir(parents=True)
    (agent_home / "config.toml").write_text(
        f'server_url = "https://core.lab.example"\nca_file = "{ca.as_posix()}"\n', encoding="utf-8"
    )
    assert load_config().ca_file == ca


def test_write_initial_config_is_idempotent_and_refuses_other_server(agent_home: Path) -> None:
    first = write_initial_config(agent_home, "https://core.lab.example/")
    assert first.server_url == "https://core.lab.example"
    again = write_initial_config(agent_home, "https://core.lab.example")
    assert again == first
    with pytest.raises(ConfigError, match="outro servidor"):
        write_initial_config(agent_home, "https://outro.lab.example")
    with pytest.raises(ConfigError):
        write_initial_config(agent_home / "x", "http://core.lab.example")


def test_default_home_uses_override_then_localappdata(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.delenv("ARES_AGENT_HOME")
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    assert default_home() == tmp_path / "ARES" / "agent"
    monkeypatch.delenv("LOCALAPPDATA")
    with pytest.raises(ConfigError):
        default_home()
