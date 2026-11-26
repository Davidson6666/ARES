"""baseline: protege a tabela de controle de migrações

Primeira migração (item 3 da seção 21.13). Ainda não cria tabelas de
domínio: elas entram no item 4 (identidade), com desenho próprio.

O usuário da API (ares_app) não recebe privilégio padrão em tabelas; cada
migração concede, tabela por tabela, só o que for necessário. Mesmo assim,
esta migração revoga explicitamente o acesso de ares_app a
``alembic_version`` (defesa em profundidade: a API nunca deve alterar a
versão do schema). Em bancos sem o papel ``ares_app``, nada é feito.

Revision ID: 0001
Revises:
Create Date: 2026-11-26
"""

from collections.abc import Sequence

from alembic import op

revision: str = "0001"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute(
        """
        DO $$
        BEGIN
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'ares_app') THEN
                REVOKE ALL ON TABLE alembic_version FROM ares_app;
            END IF;
        END
        $$;
        """
    )


def downgrade() -> None:
    # Nada a desfazer. Na base, o Alembic mantém alembic_version, sem linhas.
    pass
