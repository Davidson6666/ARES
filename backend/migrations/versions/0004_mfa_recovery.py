"""mfa e recuperação de conta (ADR 0005)

- mfa_factors: segredo TOTP cifrado (AES-GCM), um fator ativo por tipo,
  last_used_step contra reuso de código.
- mfa_challenges: desafio entre a senha e o segundo fator (token só como hash).
- recovery_codes: códigos de backup com hash Argon2id, uso único.
- recovery_tokens: token de recuperação do CLI, hash SHA-256, 15 min, uso único.

Nenhuma tabela recebe DELETE do ares_app: fatores e códigos são revogados
ou marcados como usados.

Revision ID: 0004
Revises: 0003
Create Date: 2026-11-27
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.postgresql import UUID

revision: str = "0004"
down_revision: str | None = "0003"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

APP_GRANTS: dict[str, str] = {
    "mfa_factors": "SELECT, INSERT, UPDATE",
    "mfa_challenges": "SELECT, INSERT, UPDATE",
    "recovery_codes": "SELECT, INSERT, UPDATE",
    "recovery_tokens": "SELECT, INSERT, UPDATE",
}


def _uuid_pk() -> sa.Column[object]:
    return sa.Column("id", UUID(as_uuid=True), primary_key=True)


def _user_fk(name: str = "user_id") -> sa.Column[object]:
    return sa.Column(
        name, UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="RESTRICT"), nullable=False
    )


def _ts(name: str, nullable: bool = False) -> sa.Column[object]:
    return sa.Column(name, sa.DateTime(timezone=True), nullable=nullable)


def upgrade() -> None:
    op.create_table(
        "mfa_factors",
        _uuid_pk(),
        _user_fk(),
        sa.Column("type", sa.String(16), nullable=False),
        sa.Column("secret_ciphertext", sa.LargeBinary, nullable=False),
        sa.Column("secret_ref", sa.Text, nullable=False),
        sa.Column("status", sa.String(16), nullable=False),
        sa.Column("last_used_step", sa.BigInteger, nullable=True),
        _ts("created_at", nullable=False),
        _ts("last_used_at", nullable=True),
        _ts("revoked_at", nullable=True),
        sa.CheckConstraint("type IN ('totp')", name="type"),
        sa.CheckConstraint("status IN ('pending', 'active', 'revoked')", name="status"),
        sa.CheckConstraint("secret_ref ~ '^env:v[0-9]+$'", name="secret_ref_format"),
    )
    op.create_index("ix_mfa_factors_user_id", "mfa_factors", ["user_id"])
    # Um fator ativo por tipo e por conta (CLAUDE.md, 6.1).
    op.create_index(
        "uq_mfa_factors_one_active",
        "mfa_factors",
        ["user_id", "type"],
        unique=True,
        postgresql_where=sa.text("status = 'active'"),
    )

    op.create_table(
        "mfa_challenges",
        _uuid_pk(),
        _user_fk(),
        sa.Column("token_hash", sa.LargeBinary, nullable=False, unique=True),
        sa.Column("purpose", sa.String(16), nullable=False),
        sa.Column("attempts", sa.Integer, nullable=False, server_default="0"),
        _ts("created_at", nullable=False),
        _ts("expires_at", nullable=False),
        _ts("used_at", nullable=True),
        sa.CheckConstraint("purpose IN ('verify', 'enroll')", name="purpose"),
        sa.CheckConstraint("attempts >= 0", name="attempts"),
        sa.CheckConstraint("octet_length(token_hash) = 32", name="token_hash_length"),
    )
    op.create_index("ix_mfa_challenges_user_id", "mfa_challenges", ["user_id"])

    op.create_table(
        "recovery_codes",
        _uuid_pk(),
        _user_fk(),
        sa.Column("code_hash", sa.Text, nullable=False),
        _ts("created_at", nullable=False),
        _ts("used_at", nullable=True),
    )
    op.create_index("ix_recovery_codes_user_id", "recovery_codes", ["user_id"])

    op.create_table(
        "recovery_tokens",
        _uuid_pk(),
        _user_fk(),
        sa.Column("token_hash", sa.LargeBinary, nullable=False, unique=True),
        _ts("created_at", nullable=False),
        _ts("expires_at", nullable=False),
        _ts("used_at", nullable=True),
        sa.CheckConstraint("octet_length(token_hash) = 32", name="token_hash_length"),
    )
    op.create_index("ix_recovery_tokens_user_id", "recovery_tokens", ["user_id"])

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


def downgrade() -> None:
    for table in ("recovery_tokens", "recovery_codes", "mfa_challenges", "mfa_factors"):
        op.drop_table(table)
