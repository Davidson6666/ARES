"""Configuração do Core.

Lida de variáveis de ambiente com prefixo ``ARES_`` e, opcionalmente, de um
arquivo ``.env`` local (fora do Git; ver ``.gitignore``). Só valores não
secretos podem ter valor padrão. Segredos são ``SecretStr`` e nunca aparecem
em ``repr`` nem em respostas da API.
"""

from typing import Literal

from pydantic import SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="ARES_",
        env_file=".env",
        extra="forbid",
    )

    env: Literal["dev", "test", "prod"] = "dev"
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"

    # Usado a partir do item 3 (conexão PostgreSQL). Obrigatório só quando
    # o banco for necessário; ausente hoje.
    database_url: SecretStr | None = None
