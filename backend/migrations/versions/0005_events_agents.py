"""eventos, agentes, termo de autorização e idempotência (ADR 0006)

- operator_authorizations: termo do operador (CLAUDE.md, 9.4), só pelo CLI.
- agents / agent_enrollment_tokens / agent_credentials: identidade do agente.
  No máximo uma credencial ativa por agente (índice único parcial).
- events: eventos aceitos (append-only para a API: sem UPDATE nem DELETE).
- ingest_records: último resultado por event_id (retenção de 7 dias).
- idempotency_keys: retenção de 24 h (chave vencida é regravada; sem DELETE).
- users.tenant_id: escopo mínimo de leitura (ADR 0006).

Revision ID: 0005
Revises: 0004
Create Date: 2026-11-27
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import ARRAY, JSONB, UUID

revision: str = "0005"
down_revision: str | None = "0004"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

APP_GRANTS: dict[str, str] = {
    "operator_authorizations": "SELECT",
    "agents": "SELECT, INSERT",
    "agent_enrollment_tokens": "SELECT, INSERT, UPDATE",
    "agent_credentials": "SELECT, INSERT, UPDATE",
    "events": "SELECT, INSERT",
    "ingest_records": "SELECT, INSERT, UPDATE",
    "idempotency_keys": "SELECT, INSERT, UPDATE",
}


def _ts(name: str, nullable: bool = False) -> sa.Column[object]:
    return sa.Column(name, sa.DateTime(timezone=True), nullable=nullable)


def _fk(name: str, table: str, nullable: bool = False) -> sa.Column[object]:
    return sa.Column(
        name,
        UUID(as_uuid=True),
        sa.ForeignKey(f"{table}.id", ondelete="RESTRICT"),
        nullable=nullable,
    )


def upgrade() -> None:
    op.add_column("users", sa.Column("tenant_id", sa.Text, nullable=True))

    op.create_table(
        "operator_authorizations",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("reference", sa.Text, nullable=False),
        sa.Column("description", sa.Text, nullable=False),
        _ts("valid_from"),
        _ts("valid_until"),
        _ts("recorded_at"),
        _ts("revoked_at", nullable=True),
        sa.CheckConstraint("valid_until > valid_from", name="validity_order"),
    )

    op.create_table(
        "agents",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("name", sa.Text, nullable=False),
        sa.Column("module", sa.Text, nullable=False),
        sa.Column("tenant_id", sa.Text, nullable=True),
        sa.Column("host_id", sa.Text, nullable=True),
        sa.Column("status", sa.String(16), nullable=False),
        _fk("authorization_id", "operator_authorizations"),
        _fk("created_by", "users"),
        _ts("created_at"),
        _ts("activated_at", nullable=True),
        _ts("last_seen_at", nullable=True),
        _ts("revoked_at", nullable=True),
        sa.CheckConstraint("status IN ('pending', 'active', 'revoked')", name="status"),
        sa.CheckConstraint("module ~ '^[a-z][a-z0-9_]{0,63}$'", name="module_format"),
    )
    op.create_index("ix_agents_authorization_id", "agents", ["authorization_id"])
    op.create_index("ix_agents_created_by", "agents", ["created_by"])

    op.create_table(
        "agent_enrollment_tokens",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        _fk("agent_id", "agents"),
        sa.Column("token_hash", sa.LargeBinary, nullable=False, unique=True),
        _ts("created_at"),
        _ts("expires_at"),
        _ts("used_at", nullable=True),
        sa.CheckConstraint("octet_length(token_hash) = 32", name="token_hash_length"),
    )
    op.create_index("ix_agent_enrollment_tokens_agent_id", "agent_enrollment_tokens", ["agent_id"])

    op.create_table(
        "agent_credentials",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        _fk("agent_id", "agents"),
        sa.Column("credential_hash", sa.LargeBinary, nullable=False, unique=True),
        _ts("issued_at"),
        _ts("expires_at", nullable=True),
        _ts("revoked_at", nullable=True),
        sa.CheckConstraint("octet_length(credential_hash) = 32", name="credential_hash_length"),
    )
    op.create_index("ix_agent_credentials_agent_id", "agent_credentials", ["agent_id"])
    # Uma credencial ativa por agente (complemento 2.1).
    op.create_index(
        "uq_agent_credentials_one_active",
        "agent_credentials",
        ["agent_id"],
        unique=True,
        postgresql_where=sa.text("revoked_at IS NULL"),
    )

    op.create_table(
        "events",
        sa.Column("event_id", UUID(as_uuid=True), primary_key=True),
        sa.Column("event_type", sa.Text, nullable=False),
        sa.Column("schema_version", sa.Integer, nullable=False),
        _ts("occurred_at"),
        _ts("observed_at"),
        sa.Column("source_module", sa.Text, nullable=False),
        sa.Column("source_instance_id", sa.Text, nullable=False),
        _fk("agent_id", "agents"),
        sa.Column("tenant_id", sa.Text, nullable=True),
        sa.Column("device_id", sa.Text, nullable=True),
        sa.Column("correlation_id", sa.Text, nullable=True),
        sa.Column("severity", sa.String(16), nullable=True),
        sa.Column("data_classification", sa.String(16), nullable=False),
        sa.Column("data", JSONB, nullable=False),
        sa.Column("flags", ARRAY(sa.Text), nullable=False, server_default=sa.text("'{}'::text[]")),
        sa.CheckConstraint("schema_version >= 1", name="schema_version"),
        sa.CheckConstraint(
            "severity IS NULL OR severity IN ('info', 'low', 'medium', 'high', 'critical')",
            name="severity",
        ),
        sa.CheckConstraint(
            "data_classification IN ('public', 'internal', 'personal', 'sensitive')",
            name="data_classification",
        ),
        sa.CheckConstraint(
            "event_type ~ '^[a-z][a-z0-9_]*\\.[a-z][a-z0-9_]*$'", name="event_type_format"
        ),
        sa.CheckConstraint("octet_length(data::text) <= 16384", name="data_size"),
    )
    op.create_index("ix_events_agent_id", "events", ["agent_id"])
    op.create_index("ix_events_observed_at", "events", ["observed_at"])

    op.create_table(
        "ingest_records",
        sa.Column("event_id", UUID(as_uuid=True), primary_key=True),
        _ts("received_at"),
        sa.Column("source_id", sa.Text, nullable=False),
        sa.Column("outcome", sa.String(16), nullable=False),
        sa.Column("error_code", sa.Text, nullable=True),
        sa.CheckConstraint("outcome IN ('accepted', 'duplicate', 'rejected')", name="outcome"),
    )
    op.create_index("ix_ingest_records_received_at", "ingest_records", ["received_at"])

    op.create_table(
        "idempotency_keys",
        sa.Column("principal_type", sa.String(8), primary_key=True),
        sa.Column("principal_id", UUID(as_uuid=True), primary_key=True),
        sa.Column("key", sa.Text, primary_key=True),
        sa.Column("request_hash", sa.LargeBinary, nullable=False),
        sa.Column("response_status", sa.Integer, nullable=False),
        sa.Column("response_body", JSONB, nullable=False),
        _ts("created_at"),
        _ts("expires_at"),
        sa.CheckConstraint("principal_type IN ('user', 'agent')", name="principal_type"),
        sa.CheckConstraint("octet_length(request_hash) = 32", name="request_hash_length"),
    )
    op.create_index("ix_idempotency_keys_expires_at", "idempotency_keys", ["expires_at"])

    op.execute(
        """
        DO $$
        BEGIN
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'ares_app') THEN
        """
        + "".join(f"GRANT {p} ON TABLE {t} TO ares_app;\n" for t, p in APP_GRANTS.items())
        + """
            -- UPDATE por coluna: um bug ou injeção na API não consegue mudar
            -- module, tenant_id, name ou authorization_id de um agente, nem o
            -- escopo (tenant_id) de um usuário.
            GRANT UPDATE (status, host_id, activated_at, last_seen_at, revoked_at)
                ON TABLE agents TO ares_app;
            REVOKE UPDATE ON TABLE users FROM ares_app;
            GRANT UPDATE (failed_login_count, locked_until, password_hash, updated_at)
                ON TABLE users TO ares_app;
            END IF;
        END
        $$;
        """
    )


def downgrade() -> None:
    for table in (
        "idempotency_keys",
        "ingest_records",
        "events",
        "agent_credentials",
        "agent_enrollment_tokens",
        "agents",
        "operator_authorizations",
    ):
        op.drop_table(table)
    op.drop_column("users", "tenant_id")
