"""Configuração do Core.

Lida de variáveis de ambiente com prefixo ``ARES_`` e, opcionalmente, do
arquivo ``.env`` na raiz do repositório (fora do Git; ver ``.gitignore`` e
``.env.example``). Só valores não secretos podem ter valor padrão. Segredos
são ``SecretStr`` e nunca aparecem em ``repr`` nem em respostas da API.
"""

from pathlib import Path
from typing import Literal

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict

# backend/app/core/config.py -> raiz do repositório
REPO_ROOT = Path(__file__).resolve().parents[3]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="ARES_",
        env_file=REPO_ROOT / ".env",
        # O .env é compartilhado com o docker-compose (chaves POSTGRES_*), e o
        # pydantic-settings trataria essas chaves como campos extras. Por isso
        # chaves desconhecidas são ignoradas. Consequência: erro de digitação
        # em ARES_* não é detectado; o campo fica com o valor padrão.
        extra="ignore",
    )

    env: Literal["dev", "test", "prod"] = "dev"
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"

    # Usuário da aplicação (ares_app): só leitura e escrita de dados.
    database_url: SecretStr | None = None
    # Usuário administrador: só para migrações. Nunca usado pela API.
    migration_database_url: SecretStr | None = None

    # Chave AES-GCM (32 bytes em base64) que cifra os segredos TOTP (ADR 0005).
    # Gere com: uv run python -m app.cli generate-mfa-key. Sem ela, o MFA não
    # funciona e o login de papéis administrativos é recusado (503).
    mfa_key: SecretStr | None = None

    # Sessão web (ADR 0003): 30 min de inatividade, 12 h no máximo.
    session_idle_minutes: int = Field(default=30, ge=1, le=24 * 60)
    session_absolute_hours: int = Field(default=12, ge=1, le=7 * 24)

    # Login (ADR 0003): limite por IP em memória e bloqueio progressivo por conta.
    login_rate_limit_per_minute: int = Field(default=10, ge=1, le=1000)
    login_max_failures: int = Field(default=5, ge=1, le=100)
    login_lockout_base_seconds: int = Field(default=60, ge=1)
    login_lockout_max_seconds: int = Field(default=15 * 60, ge=1)

    # Agentes e eventos (ADR 0006). Limites por agente, em memória.
    agent_requests_per_minute: int = Field(default=120, ge=1, le=100_000)
    agent_events_per_minute: int = Field(default=6000, ge=1, le=10_000_000)
    enroll_rate_limit_per_minute: int = Field(default=10, ge=1, le=1000)
    # Evento com occurred_at além disto no futuro é aceito e marcado.
    occurred_at_future_seconds: int = Field(default=300, ge=0)

    # Recuperação de conta (ADR 0005): limite por IP, em memória.
    recovery_rate_limit_per_minute: int = Field(default=5, ge=1, le=1000)
