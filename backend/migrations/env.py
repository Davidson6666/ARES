"""Ambiente do Alembic.

A URL vem, em ordem:
1. ``config.attributes["url"]`` (usado pelos testes, sem passar pelo .ini,
   para não sofrer interpolação de ``%`` em senhas);
2. ``ARES_MIGRATION_DATABASE_URL`` (usuário administrador).

Migrações nunca usam ``ARES_DATABASE_URL`` (usuário da aplicação, sem DDL).
"""

from logging.config import fileConfig

from alembic import context
from sqlalchemy import create_engine, pool

from app.core.config import Settings

config = context.config

if config.config_file_name is not None and not config.attributes.get("skip_logging"):
    fileConfig(config.config_file_name)

# Metadados dos modelos: permite conferir migração × modelo (alembic check).
from app.audit import models as _audit_models  # noqa: F401  (registra as tabelas)
from app.auth import models as _models  # noqa: F401
from app.core.db_base import Base

target_metadata = Base.metadata


def _url() -> str:
    url = config.attributes.get("url")
    if url:
        return str(url)
    settings = Settings()
    if settings.migration_database_url is None:
        raise RuntimeError("ARES_MIGRATION_DATABASE_URL não definido (ver .env.example).")
    return settings.migration_database_url.get_secret_value()


def run_migrations_offline() -> None:
    context.configure(url=_url(), target_metadata=target_metadata, literal_binds=True)
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    engine = create_engine(_url(), poolclass=pool.NullPool)
    with engine.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata)
        with context.begin_transaction():
            context.run_migrations()
    engine.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
