import pytest
from alembic import command
from sqlalchemy import Engine, create_engine, inspect, text
from sqlalchemy.exc import DBAPIError

from tests.conftest import alembic_config as _alembic_config

# Privilégios esperados do usuário da API, por tabela, após `upgrade head`.
# Toda migração que criar tabela ou conceder acesso atualiza esta matriz.
# Tabela nova sem entrada aqui => o teste falha se ares_app ganhar acesso a ela.
# Nenhum DELETE em users nem em sessions (usuário nunca é apagado; sessão é revogada).
EXPECTED_APP_GRANTS: set[tuple[str, str]] = {
    # UPDATE em users e agents é por COLUNA (ver test_app_role_column_updates).
    # Administração do Core (ADR 0008): cria usuário e papel personalizado; nunca DELETE
    # em users nem em roles. Vínculos de papel e permissão podem ser removidos.
    *{("users", p) for p in ("SELECT", "INSERT")},
    ("roles", "SELECT"),
    ("permissions", "SELECT"),
    *{("user_roles", p) for p in ("SELECT", "INSERT", "DELETE")},
    *{("role_permissions", p) for p in ("SELECT", "INSERT", "DELETE")},
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
        assert version == "0006"

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
            "display_name",  # 01c: PATCH /users/{id}
            "status",  # 01c: desativar
            "tenant_id",  # 01c: escopo, só por quem não tem escopo
        }
        assert ("users", "email") not in granted and ("users", "id") not in granted
        # INSERT em roles é por coluna: is_system nunca (a API não cria papel de sistema).
        with engine.connect() as conn:
            role_insert = {
                row.column_name
                for row in conn.execute(
                    text(
                        "SELECT column_name FROM information_schema.column_privileges "
                        "WHERE grantee = :r AND privilege_type = 'INSERT' "
                        "AND table_name = 'roles' AND table_schema = 'public'"
                    ),
                    {"r": app_role},
                )
            }
        assert role_insert == {"id", "name", "description"}
        assert ("agents", "tenant_id") not in granted and ("agents", "module") not in granted
    finally:
        engine.dispose()


def test_app_role_cannot_create_system_roles(app_engine: Engine) -> None:
    """INSERT em roles é só de id, name e description: is_system fica falso."""
    with app_engine.begin() as conn:
        conn.execute(
            text("INSERT INTO roles (id, name, description) VALUES (gen_random_uuid(), 'x', '')")
        )
        assert (
            conn.execute(text("SELECT is_system FROM roles WHERE name = 'x'")).scalar_one() is False
        )
    with pytest.raises(DBAPIError, match="permission denied"), app_engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO roles (id, name, description, is_system) "
                "VALUES (gen_random_uuid(), 'y', '', true)"
            )
        )


def test_system_roles_are_immutable_even_for_the_owner(admin_engine: Engine) -> None:
    """Gatilho no banco: nem o dono altera papel de sistema ou suas permissões."""
    with admin_engine.connect() as conn:
        system_role = conn.execute(
            text("SELECT id FROM roles WHERE is_system ORDER BY name LIMIT 1")
        ).scalar_one()
    for statement in (
        "UPDATE roles SET description = 'x' WHERE id = :r",
        "DELETE FROM roles WHERE id = :r",
        "DELETE FROM role_permissions WHERE role_id = :r",
        (
            "INSERT INTO role_permissions (role_id, permission_id) "
            "SELECT :r, id FROM permissions WHERE id NOT IN "
            "(SELECT permission_id FROM role_permissions WHERE role_id = :r) LIMIT 1"
        ),
    ):
        with pytest.raises(DBAPIError, match="imutáve"), admin_engine.begin() as conn:
            conn.execute(text(statement), {"r": system_role})


def test_custom_roles_are_editable_by_the_app(app_engine: Engine) -> None:
    with app_engine.begin() as conn:
        conn.execute(
            text(
                "INSERT INTO roles (id, name, description) "
                "VALUES ('00000000-0000-4000-8000-0000000000aa', 'custom', '')"
            )
        )
        conn.execute(
            text(
                "INSERT INTO role_permissions (role_id, permission_id) "
                "SELECT '00000000-0000-4000-8000-0000000000aa', id FROM permissions "
                "WHERE name = 'events.read'"
            )
        )
    with app_engine.begin() as conn:
        deleted = conn.execute(
            text(
                "DELETE FROM role_permissions "
                "WHERE role_id = '00000000-0000-4000-8000-0000000000aa'"
            )
        ).rowcount
    assert deleted == 1
    # Mas a API não renomeia nem apaga o papel (sem UPDATE/DELETE em roles).
    for statement in (
        "UPDATE roles SET description = 'x' WHERE name = 'custom'",
        "DELETE FROM roles WHERE name = 'custom'",
        "DELETE FROM users",
    ):
        with pytest.raises(DBAPIError, match="permission denied"), app_engine.begin() as conn:
            conn.execute(text(statement))
