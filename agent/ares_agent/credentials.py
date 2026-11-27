"""Credencial do agente no Gerenciador de Credenciais do Windows (ADR 0007).

Fora do ``config.toml`` e sem plano B em arquivo: se o cofre falhar, o agente
falha fechado. O backend do ``keyring`` é conferido: um backend em texto puro (por
exemplo ``keyrings.alt``, ou ``PYTHON_KEYRING_BACKEND`` apontando para outro) é
recusado. A credencial nunca é registrada em log.
"""

import keyring
from keyring.errors import KeyringError

from ares_agent import ids

SERVICE = "ares-agent"
USERNAME = "credential"
# Só o cofre do Windows. (Os testes acrescentam o cofre em memória.)
TRUSTED_BACKENDS: set[str] = {"WinVaultKeyring"}


class CredentialStoreError(RuntimeError):
    """O cofre de credenciais falhou ou a credencial guardada é inválida."""


def parse_agent_id(credential: str) -> str:
    """UUID (com hífens) do agente embutido na credencial."""
    agent_id = ids.agent_id_from_credential(credential)
    if agent_id is None:
        raise CredentialStoreError("Credencial em formato inesperado.")
    return agent_id


def _check_backend() -> None:
    name = type(keyring.get_keyring()).__name__
    if name not in TRUSTED_BACKENDS:
        raise CredentialStoreError(
            "O cofre de credenciais do sistema não está disponível "
            f"(backend inesperado: {name[:40]}). O agente não grava credencial em arquivo."
        )


def save(credential: str) -> None:
    parse_agent_id(credential)
    _check_backend()
    try:
        keyring.set_password(SERVICE, USERNAME, credential)
    except KeyringError:
        raise CredentialStoreError("Não foi possível gravar a credencial no cofre.") from None


def load() -> str:
    _check_backend()
    try:
        value = keyring.get_password(SERVICE, USERNAME)
    except KeyringError:
        raise CredentialStoreError("Não foi possível ler a credencial do cofre.") from None
    if value is None:
        raise CredentialStoreError("Sem credencial guardada. Rode `enroll` primeiro.")
    parse_agent_id(value)
    return value
