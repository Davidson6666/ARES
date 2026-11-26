"""identity: usuários, papéis, permissões e sessões

Item 4 da seção 21.13. Ver ADR 0003 e CLAUDE.md, seção 6.1.

- E-mail sempre em minúsculas (CHECK) e único.
- Status com CHECK de lista fechada.
- Usuário nunca é apagado: FKs para users usam ON DELETE RESTRICT.
- Sessão guarda só hashes (token e user-agent). O token CSRF é derivado do
  token de sessão e não é gravado. IP não é persistido.
- Catálogo de permissões e papéis de sistema semeados aqui.
- ares_app recebe, tabela por tabela, só o necessário. Nenhum DELETE em
  users nem em sessions.

Revision ID: 0002
Revises: 0001
Create Date: 2026-11-26
"""

import uuid
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import UUID

revision: str = "0002"
down_revision: str | None = "0001"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

# Catálogo inicial (v1.1, seção 14.5; complemento, seção 3.2).
PERMISSIONS: dict[str, str] = {
    "users.read": "Consultar usuários.",
    "users.write": "Criar, alterar e desativar usuários.",
    "roles.manage": "Gerenciar papéis e permissões.",
    "modules.read": "Consultar módulos e estados.",
    "modules.configure": "Configurar módulos e agentes.",
    "events.read": "Consultar eventos.",
    "alerts.read": "Consultar alertas.",
    "alerts.triage": "Triar alertas.",
    "incidents.read": "Consultar incidentes.",
    "incidents.write": "Gerenciar incidentes.",
    "evidence.read": "Consultar evidências autorizadas.",
    "evidence.export": "Exportar evidências.",
    "audit.read": "Consultar a trilha de auditoria.",
    "reports.generate": "Gerar relatórios.",
    "settings.manage": "Alterar configurações globais.",
}

_VIEWER = {"modules.read", "events.read", "alerts.read", "incidents.read"}

# Papéis de sistema (v1.1, seção 14.5). Matriz proposta; ver ADR 0003.
ROLES: dict[str, tuple[str, set[str]]] = {
    "super_admin": ("Gerencia usuários, papéis, configuração global e módulos.", set(PERMISSIONS)),
    "security_admin": (
        "Configura motores, políticas e fontes de telemetria.",
        _VIEWER | {"modules.configure"},
    ),
    "security_analyst": (
        "Investiga alertas, gerencia incidentes e consulta evidências autorizadas.",
        _VIEWER | {"alerts.triage", "incidents.write", "evidence.read"},
    ),
    "auditor": ("Consulta trilhas, relatórios e histórico.", _VIEWER | {"audit.read"}),
    "viewer": ("Consulta painéis e informações liberadas.", set(_VIEWER)),
}

# Privilégios do usuário da API por tabela (espelhados em tests/test_migrations.py).
APP_GRANTS: dict[str, str] = {
    # Sem INSERT: nenhuma rota cria usuário ou concede papel ainda; o
    # bootstrap usa ares_owner. Entram com POST /users e PUT /users/{id}/roles.
    "users": "SELECT, UPDATE",
    "roles": "SELECT",
    "permissions": "SELECT",
    "user_roles": "SELECT",
    "role_permissions": "SELECT",
    "sessions": "SELECT, INSERT, UPDATE",
}


def _ts(name: str, nullable: bool = False, default_now: bool = False) -> sa.Column[object]:
    return sa.Column(
        name,
        sa.DateTime(timezone=True),
        nullable=nullable,
        server_default=sa.func.now() if default_now else None,
    )


def upgrade() -> None:
    op.create_table(
        "users",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("email", sa.Text, nullable=False),
        sa.Column("display_name", sa.Text, nullable=False),
        sa.Column("password_hash", sa.Text, nullable=False),
        sa.Column("status", sa.String(16), nullable=False, server_default="active"),
        sa.Column("failed_login_count", sa.Integer, nullable=False, server_default="0"),
        _ts("locked_until", nullable=True),
        _ts("created_at", default_now=True),
        _ts("updated_at", default_now=True),
        sa.CheckConstraint("status IN ('active', 'disabled')", name="status"),
        sa.CheckConstraint("email = lower(email)", name="email_lowercase"),
        sa.CheckConstraint("failed_login_count >= 0", name="failed_login_count"),
        sa.UniqueConstraint("email"),
    )
    op.create_table(
        "roles",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("name", sa.Text, nullable=False),
        sa.Column("description", sa.Text, nullable=False, server_default=""),
        sa.Column("is_system", sa.Boolean, nullable=False, server_default=sa.false()),
        sa.UniqueConstraint("name"),
    )
    op.create_table(
        "permissions",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("name", sa.Text, nullable=False),
        sa.Column("description", sa.Text, nullable=False, server_default=""),
        sa.CheckConstraint("name ~ '^[a-z]+\\.[a-z]+$'", name="name_format"),
        sa.UniqueConstraint("name"),
    )
    op.create_table(
        "user_roles",
        sa.Column(
            "user_id",
            UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="RESTRICT"),
            primary_key=True,
        ),
        sa.Column(
            "role_id",
            UUID(as_uuid=True),
            sa.ForeignKey("roles.id", ondelete="RESTRICT"),
            primary_key=True,
        ),
        sa.Column(
            "granted_by",
            UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="RESTRICT"),
            nullable=True,
        ),
        _ts("granted_at", default_now=True),
    )
    op.create_table(
        "role_permissions",
        sa.Column(
            "role_id",
            UUID(as_uuid=True),
            sa.ForeignKey("roles.id", ondelete="RESTRICT"),
            primary_key=True,
        ),
        sa.Column(
            "permission_id",
            UUID(as_uuid=True),
            sa.ForeignKey("permissions.id", ondelete="RESTRICT"),
            primary_key=True,
        ),
    )
    op.create_table(
        "sessions",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "user_id",
            UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="RESTRICT"),
            nullable=False,
        ),
        sa.Column("token_hash", sa.LargeBinary, nullable=False),
        sa.Column("ua_hash", sa.LargeBinary, nullable=True),
        _ts("created_at"),
        _ts("last_seen_at"),
        _ts("idle_expires_at"),
        _ts("absolute_expires_at"),
        _ts("revoked_at", nullable=True),
        sa.CheckConstraint("idle_expires_at <= absolute_expires_at", name="idle_within_absolute"),
        sa.UniqueConstraint("token_hash"),
    )
    op.create_index("ix_sessions_user_id", "sessions", ["user_id"])

    _seed()

    op.execute(
        """
        DO $$
        BEGIN
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'ares_app') THEN
        """
        + "".join(
            f"GRANT {privs} ON TABLE {table} TO ares_app;\n" for table, privs in APP_GRANTS.items()
        )
        + """
            END IF;
        END
        $$;
        """
    )


def _seed() -> None:
    permissions = sa.table(
        "permissions",
        sa.column("id", UUID(as_uuid=True)),
        sa.column("name", sa.Text),
        sa.column("description", sa.Text),
    )
    roles = sa.table(
        "roles",
        sa.column("id", UUID(as_uuid=True)),
        sa.column("name", sa.Text),
        sa.column("description", sa.Text),
        sa.column("is_system", sa.Boolean),
    )
    role_permissions = sa.table(
        "role_permissions",
        sa.column("role_id", UUID(as_uuid=True)),
        sa.column("permission_id", UUID(as_uuid=True)),
    )
    perm_ids = {name: uuid.uuid4() for name in PERMISSIONS}
    role_ids = {name: uuid.uuid4() for name in ROLES}
    op.bulk_insert(
        permissions,
        [{"id": perm_ids[n], "name": n, "description": d} for n, d in PERMISSIONS.items()],
    )
    op.bulk_insert(
        roles,
        [
            {"id": role_ids[n], "name": n, "description": d, "is_system": True}
            for n, (d, _) in ROLES.items()
        ],
    )
    op.bulk_insert(
        role_permissions,
        [
            {"role_id": role_ids[r], "permission_id": perm_ids[p]}
            for r, (_, perms) in ROLES.items()
            for p in sorted(perms)
        ],
    )


def downgrade() -> None:
    for table in ("sessions", "role_permissions", "user_roles", "permissions", "roles", "users"):
        op.drop_table(table)
