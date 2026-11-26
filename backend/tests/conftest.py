"""Fixtures de banco para testes de integração.

Testes marcados com ``db`` precisam de ``ARES_TEST_ADMIN_DATABASE_URL``
(usuário com permissão de criar bancos e papéis). Cada teste recebe um banco
novo, apagado ao final (v1.1, seção 16.1). Sem a variável, são pulados.
"""

import os
import uuid
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import Engine, create_engine, event, make_url, text

from app.auth import passwords

TEST_ADMIN_URL_ENV = "ARES_TEST_ADMIN_DATABASE_URL"
APP_ROLE = "ares_app"
BACKEND_DIR = Path(__file__).resolve().parents[1]


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line("markers", "db: precisa de PostgreSQL de teste")
    # Argon2 barato na suíte; os parâmetros reais têm teste próprio.
    passwords.configure_for_tests()


@pytest.fixture(scope="session")
def admin_url() -> str:
    url = os.environ.get(TEST_ADMIN_URL_ENV)
    if not url:
        pytest.skip(f"{TEST_ADMIN_URL_ENV} não definido")
    return url


@pytest.fixture(scope="session")
def app_role(admin_url: str) -> Iterator[str]:
    """Garante que o papel ares_app exista no cluster de teste.

    Se já existir (ex.: contêiner de dev), não é alterado. Se não existir, é
    criado NOLOGIN e removido no fim. Nunca usa DROP OWNED: isso revogaria
    privilégios reais do papel em outros bancos.
    """
    engine = create_engine(admin_url, isolation_level="AUTOCOMMIT")
    with engine.connect() as conn:
        exists = conn.execute(
            text("SELECT 1 FROM pg_roles WHERE rolname = :r"), {"r": APP_ROLE}
        ).scalar()
        if not exists:
            conn.execute(text(f"CREATE ROLE {APP_ROLE} NOLOGIN"))
    try:
        yield APP_ROLE
    finally:
        if not exists:
            with engine.connect() as conn:
                conn.execute(text(f"DROP ROLE IF EXISTS {APP_ROLE}"))
        engine.dispose()


@pytest.fixture
def temp_database_url(admin_url: str) -> Iterator[str]:
    name = f"ares_test_{uuid.uuid4().hex[:12]}"
    admin = create_engine(admin_url, isolation_level="AUTOCOMMIT")
    with admin.connect() as conn:
        conn.execute(text(f'CREATE DATABASE "{name}"'))
    try:
        yield make_url(admin_url).set(database=name).render_as_string(hide_password=False)
    finally:
        with admin.connect() as conn:
            conn.execute(text(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)'))
        admin.dispose()


def alembic_config(url: str) -> Config:
    cfg = Config(str(BACKEND_DIR / "alembic.ini"))
    cfg.attributes["url"] = url
    cfg.attributes["skip_logging"] = True
    return cfg


@pytest.fixture
def migrated_database_url(temp_database_url: str, app_role: str) -> str:
    command.upgrade(alembic_config(temp_database_url), "head")
    return temp_database_url


@pytest.fixture
def admin_engine(migrated_database_url: str) -> Iterator[Engine]:
    """Engine com o usuário administrador, para preparar dados de teste."""
    engine = create_engine(migrated_database_url)
    yield engine
    engine.dispose()


@pytest.fixture
def app_engine(migrated_database_url: str, app_role: str) -> Iterator[Engine]:
    """Engine que roda como ares_app (SET ROLE): a API nos testes tem só os
    privilégios reais do usuário da aplicação."""
    engine = create_engine(migrated_database_url)

    @event.listens_for(engine, "connect")
    def _set_role(dbapi_conn: Any, _record: Any) -> None:
        with dbapi_conn.cursor() as cur:
            cur.execute(f"SET ROLE {app_role}")
        dbapi_conn.commit()

    yield engine
    engine.dispose()
