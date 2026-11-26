"""Fixtures de banco para testes de integração.

Testes marcados com ``db`` precisam de ``ARES_TEST_ADMIN_DATABASE_URL``
(usuário com permissão de criar bancos). Cada teste recebe um banco novo,
apagado ao final (v1.1, seção 16.1). Sem a variável, os testes são pulados.
"""

import os
import uuid
from collections.abc import Iterator

import pytest
from sqlalchemy import create_engine, make_url, text

TEST_ADMIN_URL_ENV = "ARES_TEST_ADMIN_DATABASE_URL"


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line("markers", "db: precisa de PostgreSQL de teste")


@pytest.fixture(scope="session")
def admin_url() -> str:
    url = os.environ.get(TEST_ADMIN_URL_ENV)
    if not url:
        pytest.skip(f"{TEST_ADMIN_URL_ENV} não definido")
    return url


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
