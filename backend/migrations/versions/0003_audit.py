"""audit: trilha de auditoria append-only com encadeamento de hash

Item 5 da seção 21.13. Ver ADR 0004 e CLAUDE.md, seções 6.1 e 6.2.

- ``prev_hash``/``entry_hash`` (SHA-256) encadeiam as entradas: alterar ou
  remover uma entrada quebra a verificação (``python -m app.cli verify-audit``).
- Trigger recusa UPDATE, DELETE e TRUNCATE de qualquer papel, mas o dono
  da tabela (ares_owner) ou um superusuário pode desligá-lo, trocar a
  função ou apagar a tabela. O trigger evita alteração acidental; não
  protege contra quem tem essas credenciais (CLAUDE.md, 9.3). Garantia
  forte exige âncora/cópia externa.
- FK para users com ON DELETE RESTRICT.
- Sem IP e sem e-mail de conta desconhecida (decisão do autor, 26/11/2026).
- ares_app: só SELECT e INSERT.

Revision ID: 0003
Revises: 0002
Create Date: 2026-11-26
"""

import os
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import JSONB, UUID

revision: str = "0003"
down_revision: str | None = "0002"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "audit_logs",
        sa.Column("id", sa.BigInteger, sa.Identity(always=True), primary_key=True),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("actor_type", sa.String(16), nullable=False),
        sa.Column(
            "actor_user_id",
            UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="RESTRICT"),
            nullable=True,
        ),
        sa.Column("action", sa.Text, nullable=False),
        sa.Column("resource_type", sa.Text, nullable=True),
        sa.Column("resource_id", sa.Text, nullable=True),
        sa.Column("result", sa.String(16), nullable=False),
        sa.Column("reason", sa.Text, nullable=True),
        sa.Column("request_id", UUID(as_uuid=True), nullable=True),
        # Agrupa ações relacionadas entre requisições (v1.1, 14.8 e 16).
        # request_id identifica uma requisição; correlation_id, um fluxo.
        sa.Column("correlation_id", sa.Text, nullable=True),
        sa.Column("details", JSONB, nullable=False, server_default=sa.text("'{}'::jsonb")),
        sa.Column("prev_hash", sa.LargeBinary, nullable=False),
        sa.Column("entry_hash", sa.LargeBinary, nullable=False),
        sa.CheckConstraint("actor_type IN ('user', 'system', 'anonymous')", name="actor_type"),
        sa.CheckConstraint("result IN ('success', 'failure', 'denied')", name="result"),
        sa.CheckConstraint("action ~ '^[a-z_]+\\.[a-z_]+$'", name="action_format"),
        sa.CheckConstraint("octet_length(prev_hash) = 32", name="prev_hash_length"),
        sa.CheckConstraint("octet_length(entry_hash) = 32", name="entry_hash_length"),
        sa.CheckConstraint(
            "(actor_type = 'user') = (actor_user_id IS NOT NULL)", name="actor_user_consistent"
        ),
        sa.UniqueConstraint("entry_hash"),
    )
    op.create_index("ix_audit_logs_actor_user_id", "audit_logs", ["actor_user_id"])

    op.execute(
        """
        CREATE FUNCTION audit_logs_append_only() RETURNS trigger
        LANGUAGE plpgsql AS $$
        BEGIN
            RAISE EXCEPTION 'audit_logs é append-only (%)', TG_OP
                USING ERRCODE = 'insufficient_privilege';
        END
        $$;
        CREATE TRIGGER audit_logs_no_update_delete
            BEFORE UPDATE OR DELETE ON audit_logs
            FOR EACH ROW EXECUTE FUNCTION audit_logs_append_only();
        CREATE TRIGGER audit_logs_no_truncate
            BEFORE TRUNCATE ON audit_logs
            FOR EACH STATEMENT EXECUTE FUNCTION audit_logs_append_only();
        """
    )
    op.execute(
        """
        DO $$
        BEGIN
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'ares_app') THEN
                GRANT SELECT, INSERT ON TABLE audit_logs TO ares_app;
            END IF;
        END
        $$;
        """
    )


def downgrade() -> None:
    # Não destruir a trilha por um downgrade comum. Exporte antes e defina
    # ARES_ALLOW_AUDIT_DROP=1 se for mesmo essa a intenção.
    has_rows = op.get_bind().execute(sa.text("SELECT EXISTS (SELECT 1 FROM audit_logs)")).scalar()
    if has_rows and os.environ.get("ARES_ALLOW_AUDIT_DROP") != "1":
        raise RuntimeError(
            "audit_logs tem entradas; downgrade recusado. Exporte a trilha e "
            "defina ARES_ALLOW_AUDIT_DROP=1 para prosseguir."
        )
    op.execute("DROP TRIGGER audit_logs_no_truncate ON audit_logs")
    op.execute("DROP TRIGGER audit_logs_no_update_delete ON audit_logs")
    op.drop_table("audit_logs")
    op.execute("DROP FUNCTION audit_logs_append_only()")
