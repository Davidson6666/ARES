"""Fixtures comuns. Nenhum teste toca o Gerenciador de Credenciais real do Windows."""

from collections.abc import Iterator
from pathlib import Path

import keyring
import pytest
from keyring.backend import KeyringBackend
from keyring.backends.fail import Keyring as FailKeyring


class MemoryKeyring(KeyringBackend):
    priority = 1

    def __init__(self) -> None:
        self.items: dict[tuple[str, str], str] = {}

    def set_password(self, service: str, username: str, password: str) -> None:
        self.items[(service, username)] = password

    def get_password(self, service: str, username: str) -> str | None:
        return self.items.get((service, username))

    def delete_password(self, service: str, username: str) -> None:
        self.items.pop((service, username), None)


@pytest.fixture(autouse=True)
def memory_keyring(monkeypatch: pytest.MonkeyPatch) -> Iterator[MemoryKeyring]:
    """Cofre em memória em TODOS os testes: o cofre real do usuário nunca é tocado."""
    from ares_agent import credentials

    monkeypatch.setattr(credentials, "TRUSTED_BACKENDS", {"MemoryKeyring"})
    previous = keyring.get_keyring()
    backend = MemoryKeyring()
    keyring.set_keyring(backend)
    yield backend
    keyring.set_keyring(previous if not isinstance(previous, FailKeyring) else backend)


@pytest.fixture(autouse=True)
def agent_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    home = tmp_path / "agent-home"
    monkeypatch.setenv("ARES_AGENT_HOME", str(home))
    return home
