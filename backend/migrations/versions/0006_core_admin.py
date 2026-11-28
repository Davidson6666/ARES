"""administração do Core: usuários, papéis e permissões (ADR 0008)

Sem tabela nova. Concede ao ``ares_app`` só o que as rotas da 01c precisam:

- ``users``: INSERT; UPDATE também em ``display_name``, ``status`` e ``tenant_id``
  (as colunas de estado de login continuam como na 0005). Nunca DELETE.
- ``roles``: INSERT só de ``id``, ``name`` e ``description`` (``is_system`` fica no
  padrão, falso: a API não consegue criar papel de sistema). Sem UPDATE nem DELETE.
- ``user_roles`` e ``role_permissions``: INSERT e DELETE (remover vínculo precisa existir).

Papel de sistema é protegido também no banco, não só no aplicativo: gatilhos recusam
UPDATE e DELETE de ``roles`` com ``is_system`` e INSERT/DELETE em ``role_permissions``
de papel de sistema, para qualquer usuário (inclusive o dono).

Revision ID: 0006
Revises: 0005
Create Date: 2026-11-28
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0006"
down_revision: str | None = "0005"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

GRANTS = (
    "GRANT INSERT ON TABLE users TO ares_app",
    "GRANT UPDATE (display_name, status, tenant_id) ON TABLE users TO ares_app",
    "GRANT INSERT (id, name, description) ON TABLE roles TO ares_app",
    "GRANT INSERT, DELETE ON TABLE user_roles TO ares_app",
    "GRANT INSERT, DELETE ON TABLE role_permissions TO ares_app",
)
REVOKES = (
    "REVOKE INSERT ON TABLE users FROM ares_app",
    "REVOKE UPDATE (display_name, status, tenant_id) ON TABLE users FROM ares_app",
    "REVOKE INSERT (id, name, description) ON TABLE roles FROM ares_app",
    "REVOKE INSERT, DELETE ON TABLE user_roles FROM ares_app",
    "REVOKE INSERT, DELETE ON TABLE role_permissions FROM ares_app",
)


def _for_app_role(statements: Sequence[str]) -> str:
    body = "".join(f"{s};\n" for s in statements)
    return f"""
        DO $$
        BEGIN
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'ares_app') THEN
        {body}
            END IF;
        END
        $$;
        """


def upgrade() -> None:
    op.execute(_for_app_role(GRANTS))
    op.execute(
        """
        CREATE FUNCTION ares_protect_system_roles() RETURNS trigger
        LANGUAGE plpgsql AS $$
        BEGIN
            IF TG_TABLE_NAME = 'roles' THEN
                IF OLD.is_system THEN
                    RAISE EXCEPTION 'papel de sistema é imutável'
                        USING ERRCODE = 'check_violation';
                END IF;
            ELSIF TG_TABLE_NAME = 'role_permissions' THEN
                IF EXISTS (
                    SELECT 1 FROM roles
                    WHERE id = COALESCE(NEW.role_id, OLD.role_id) AND is_system
                ) THEN
                    RAISE EXCEPTION 'permissões de papel de sistema são imutáveis'
                        USING ERRCODE = 'check_violation';
                END IF;
            END IF;
            RETURN COALESCE(NEW, OLD);
        END
        $$;
        """
    )
    op.execute(
        """
        CREATE TRIGGER roles_protect_system
            BEFORE UPDATE OR DELETE ON roles
            FOR EACH ROW EXECUTE FUNCTION ares_protect_system_roles();
        """
    )
    op.execute(
        """
        CREATE TRIGGER role_permissions_protect_system
            BEFORE INSERT OR UPDATE OR DELETE ON role_permissions
            FOR EACH ROW EXECUTE FUNCTION ares_protect_system_roles();
        """
    )


def downgrade() -> None:
    op.execute("DROP TRIGGER role_permissions_protect_system ON role_permissions")
    op.execute("DROP TRIGGER roles_protect_system ON roles")
    op.execute("DROP FUNCTION ares_protect_system_roles()")
    op.execute(_for_app_role(REVOKES))
