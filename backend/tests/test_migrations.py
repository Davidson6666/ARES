import pytest
from alembic import command
from sqlalchemy import create_engine, inspect, text

from tests.conftest import alembic_config as _alembic_config

# Privilégios esperados do usuário da API, por tabela, após `upgrade head`.
# Toda migração que criar tabela ou conceder acesso atualiza esta matriz.
# Tabela nova sem entrada aqui => o teste falha se ares_app ganhar acesso a ela.
# Nenhum DELETE em users nem em sessions (usuário nunca é apagado; sessão é revogada).
EXPECTED_APP_GRANTS: set[tuple[str, str]] = {
    # UPDATE em users e agents é por COLUNA (ver test_app_role_column_updates).
    ("users", "SELECT"),
    ("roles", "SELECT"),
    ("permissions", "SELECT"),
    ("user_roles", "SELECT"),
    ("role_permissions", "SELECT"),
    *{("sessions", p) for p in ("SELECT", "INSERT", "UPDATE")},
    # Auditoria append-only: nunca UPDATE nem DELETE.
    *{("audit_logs", p) for p in ("SELECT", "INSERT")},
    # MFA e recuperação: revogar/marcar como usado, nunca DELETE.
    *{
        (t, p)
        for t in ("mfa_factors", "mfa_challenges", "recovery_codes", "recovery_tokens")
        for p in ("SELECT", "INSERT", "UPDATE")
    },
    # Agentes (ADR 0006): o termo de autorização só se grava pelo CLI.
    ("operator_authorizations", "SELECT"),
    *{
        (t, p)
        for t in ("agent_enrollment_tokens", "agent_credentials", "ingest_records")
        for p in ("SELECT", "INSERT", "UPDATE")
    },
    *{("agents", p) for p in ("SELECT", "INSERT")},
    # Eventos: a API só insere e lê. Idempotência: regrava chave vencida (sem DELETE).
    *{("events", p) for p in ("SELECT", "INSERT")},
    *{("idempotency_keys", p) for p in ("SELECT", "INSERT", "UPDATE")},
}

pytestmark = pytest.mark.db


def test_upgrade_and_downgrade_cycle(temp_database_url: str) -> None:
    cfg = _alembic_config(temp_database_url)
    engine = create_engine(temp_database_url)
    try:
        command.upgrade(cfg, "head")
        with engine.connect() as conn:
            version = conn.execute(text("SELECT version_num FROM alembic_version")).scalar_one()
        assert version == "0005"

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


def test_models_match_migrations(migrated_database_url: str) -> None:
    """Modelos ORM e migrações não podem divergir (alembic check)."""
    command.check(_alembic_config(migrated_database_url))


def test_app_role_column_updates(temp_database_url: str, app_role: str) -> None:
    """A API só atualiza as colunas de estado: não muda module, tenant_id, name,
    authorization_id de um agente, nem o escopo (tenant_id) de um usuário."""
    command.upgrade(_alembic_config(temp_database_url), "head")
    engine = create_engine(temp_database_url)
    try:
        with engine.connect() as conn:
            granted = {
                (row.table_name, row.column_name)
                for row in conn.execute(
                    text(
                        "SELECT table_name, column_name FROM information_schema.column_privileges "
                        "WHERE grantee = :r AND privilege_type = 'UPDATE' AND table_schema = 'public'"
                    ),
                    {"r": app_role},
                )
            }
        assert {c for t, c in granted if t == "agents"} == {
            "status",
            "host_id",
            "activated_at",
            "last_seen_at",
            "revoked_at",
        }
        assert {c for t, c in granted if t == "users"} == {
            "failed_login_count",
            "locked_until",
            "password_hash",
            "updated_at",
        }
        assert ("users", "tenant_id") not in granted and ("users", "status") not in granted
        assert ("agents", "tenant_id") not in granted and ("agents", "module") not in granted
    finally:
        engine.dispose()
