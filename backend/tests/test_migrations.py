from collections.abc import Iterator
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect, text

BACKEND_DIR = Path(__file__).resolve().parents[1]
APP_ROLE = "ares_app"

# Privilégios esperados do usuário da API, por tabela, após `upgrade head`.
# Toda migração que criar tabela ou conceder acesso atualiza esta matriz.
# Tabela nova sem entrada aqui => o teste falha se ares_app ganhar acesso a ela.
EXPECTED_APP_GRANTS: set[tuple[str, str]] = set()

pytestmark = pytest.mark.db


def _alembic_config(url: str) -> Config:
    cfg = Config(str(BACKEND_DIR / "alembic.ini"))
    cfg.attributes["url"] = url
    cfg.attributes["skip_logging"] = True
    return cfg


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


def test_upgrade_and_downgrade_cycle(temp_database_url: str) -> None:
    cfg = _alembic_config(temp_database_url)
    engine = create_engine(temp_database_url)
    try:
        command.upgrade(cfg, "head")
        with engine.connect() as conn:
            version = conn.execute(text("SELECT version_num FROM alembic_version")).scalar_one()
        assert version == "0001"

        command.downgrade(cfg, "base")
        # Na base, o Alembic mantém a tabela alembic_version, mas sem linhas.
        if "alembic_version" in inspect(engine).get_table_names():
            with engine.connect() as conn:
                rows = conn.execute(text("SELECT count(*) FROM alembic_version")).scalar_one()
            assert rows == 0

        # Repetir o upgrade depois do downgrade prova que a migração é reaplicável.
        command.upgrade(cfg, "head")
    finally:
        engine.dispose()


def test_app_role_privileges_match_matrix(temp_database_url: str, app_role: str) -> None:
    command.upgrade(_alembic_config(temp_database_url), "head")
    engine = create_engine(temp_database_url)
    try:
        with engine.connect() as conn:
            grants = {
                (row.table_name, row.privilege_type)
                for row in conn.execute(
                    text(
                        "SELECT table_name, privilege_type "
                        "FROM information_schema.role_table_grants "
                        "WHERE grantee = :r AND table_schema = 'public'"
                    ),
                    {"r": app_role},
                )
            }
            alembic_access = conn.execute(
                text("SELECT has_table_privilege(:r, 'alembic_version', 'SELECT,UPDATE')"),
                {"r": app_role},
            ).scalar_one()
        assert grants == EXPECTED_APP_GRANTS
        assert alembic_access is False
    finally:
        engine.dispose()
