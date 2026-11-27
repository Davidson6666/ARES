"""Configuração local do agente (ADR 0007).

Arquivo ``config.toml`` na pasta do agente (``%LOCALAPPDATA%/ARES/agent`` ou ``ARES_AGENT_HOME``).
Chave desconhecida é erro (evita erro de digitação silencioso). Não existe opção
que desligue a verificação de certificado.
"""

import ipaddress
import os
import tomllib
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

HOME_ENV = "ARES_AGENT_HOME"
CONFIG_NAME = "config.toml"
_LOOPBACK_NAMES = {"localhost"}


class ConfigError(ValueError):
    """Configuração inválida; a mensagem é segura para exibir."""


@dataclass(frozen=True)
class Config:
    server_url: str
    home: Path
    poll_interval_seconds: int = 15
    batch_size: int = 100
    queue_max_events: int = 50_000
    queue_max_bytes: int = 64 * 1024 * 1024
    heartbeat_interval_seconds: int = 60
    ca_file: Path | None = None

    @property
    def store_path(self) -> Path:
        return self.home / "state.db"

    @property
    def log_path(self) -> Path:
        return self.home / "agent.log"


_RANGES: dict[str, tuple[int, int]] = {
    "poll_interval_seconds": (5, 3600),
    "batch_size": (1, 100),
    "queue_max_events": (100, 1_000_000),
    "queue_max_bytes": (1024 * 1024, 1024 * 1024 * 1024),
    "heartbeat_interval_seconds": (10, 3600),
}
_ALLOWED = {"server_url", "ca_file", *_RANGES}


def default_home() -> Path:
    override = os.environ.get(HOME_ENV)
    if override:
        return Path(override)
    base = os.environ.get("LOCALAPPDATA")
    if not base:
        raise ConfigError("LOCALAPPDATA não definido; defina ARES_AGENT_HOME.")
    return Path(base) / "ARES" / "agent"


def _is_loopback(host: str) -> bool:
    if host in _LOOPBACK_NAMES:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def normalize_server_url(value: object) -> str:
    """Aceita só ``https://host[:porta]``; ``http://`` apenas para loopback."""
    if not isinstance(value, str) or not value or len(value) > 512:
        raise ConfigError("server_url deve ser um texto com a URL do servidor.")
    if any(ord(c) < 33 or ord(c) == 127 or c in ('"', "\\") for c in value):
        raise ConfigError("server_url tem caractere inválido.")
    try:
        parts = urlsplit(value)
        host = parts.hostname
        parts.port  # noqa: B018  (valida a porta)
    except ValueError:
        raise ConfigError("server_url inválida.") from None
    if parts.scheme not in {"https", "http"} or not host:
        raise ConfigError("server_url deve começar com https://.")
    if parts.username is not None or parts.password is not None:
        raise ConfigError("server_url não pode ter usuário nem senha.")
    if parts.query or parts.fragment or parts.path not in {"", "/"}:
        raise ConfigError("server_url deve ser só o endereço do servidor, sem caminho.")
    if parts.scheme == "http" and not _is_loopback(host):
        raise ConfigError("http:// só é aceito para localhost, 127.0.0.1 e ::1; use https://.")
    return f"{parts.scheme}://{parts.netloc}"


def _int(name: str, value: object) -> int:
    low, high = _RANGES[name]
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
        raise ConfigError(f"{name} deve ser um inteiro entre {low} e {high}.")
    return value


def load_config(home: Path | None = None) -> Config:
    home = home or default_home()
    path = home / CONFIG_NAME
    try:
        raw = tomllib.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise ConfigError(f"Sem {CONFIG_NAME} em {home}. Rode `enroll` primeiro.") from None
    except tomllib.TOMLDecodeError, UnicodeDecodeError, OSError:
        raise ConfigError(f"{CONFIG_NAME} ilegível ou inválido.") from None
    unknown = sorted(set(raw) - _ALLOWED)
    if unknown:
        raise ConfigError(f"Chave desconhecida em {CONFIG_NAME}: {', '.join(unknown)}.")
    if "server_url" not in raw:
        raise ConfigError("server_url é obrigatória.")
    ints = {k: _int(k, v) for k, v in raw.items() if k in _RANGES}
    ca_file: Path | None = None
    if "ca_file" in raw:
        if not isinstance(raw["ca_file"], str) or not Path(raw["ca_file"]).is_file():
            raise ConfigError("ca_file deve apontar para um arquivo existente.")
        ca_file = Path(raw["ca_file"])
    return Config(
        server_url=normalize_server_url(raw["server_url"]), home=home, ca_file=ca_file, **ints
    )


def write_initial_config(home: Path, server_url: str) -> Config:
    """Cria o ``config.toml`` no enrolamento. Se já existe, o servidor tem de ser o mesmo."""
    url = normalize_server_url(server_url)
    home.mkdir(parents=True, exist_ok=True)
    path = home / CONFIG_NAME
    if path.exists():
        existing = load_config(home)
        if existing.server_url != url:
            raise ConfigError(f"{CONFIG_NAME} já aponta para outro servidor.")
        return existing
    path.write_text(f'server_url = "{url}"\n', encoding="utf-8")
    return load_config(home)
