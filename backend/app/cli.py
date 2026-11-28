"""Linha de comando do Core.

Bootstrap do primeiro administrador (complemento, seção 3.3): só por este
comando, executado no servidor. Não existe rota HTTP para isso.

Uso:
    uv run python -m app.cli create-admin --email admin@exemplo.local --display-name "Admin"
    uv run python -m app.cli verify-audit [--expect-head <id>:<hash>]
    uv run python -m app.cli generate-mfa-key
    uv run python -m app.cli record-authorization --reference X --description Y --days 30
    uv run python -m app.cli revoke-authorization --id <uuid>
    uv run python -m app.cli purge-expired
    uv run python -m app.cli issue-recovery --email voce@exemplo.local

Conecta como ``ares_owner`` (ARES_MIGRATION_DATABASE_URL). A senha é
pedida no terminal (sem eco), duas vezes. ``--password-stdin``
lê uma linha da entrada padrão (para automação e testes).
"""

import argparse
import getpass
import sys
import uuid
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta

from sqlalchemy import Engine, select, text
from sqlalchemy.orm import Session as DbSession

from app.agents.models import OperatorAuthorization
from app.audit import service as audit
from app.auth import crypto, mfa, passwords
from app.auth.models import MfaFactor, Role, User, UserRole
from app.auth.service import normalize_email
from app.core.config import Settings
from app.core.database import build_engine

SUPER_ADMIN = "super_admin"
# Chave do advisory lock que serializa execuções simultâneas do bootstrap.
BOOTSTRAP_LOCK_KEY = 0x41524553  # "ARES"


class CliError(Exception):
    pass


def create_admin(engine: Engine, email: str, display_name: str, password: str) -> uuid.UUID:
    email = normalize_email(email)
    # Só ASCII: lower() do Python e do PostgreSQL podem divergir fora dele,
    # e o CHECK email = lower(email) recusaria o INSERT.
    if not email.isascii() or "@" not in email or len(email) > 254:
        raise CliError("E-mail inválido (use apenas caracteres ASCII).")
    if not display_name.strip():
        raise CliError("Nome de exibição obrigatório.")
    violation = passwords.policy_violation(password, email)
    if violation is not None:
        raise CliError(f"Senha recusada: {violation}.")

    with DbSession(engine) as db:
        # Duas execuções simultâneas não podem criar dois administradores.
        db.execute(text("SELECT pg_advisory_xact_lock(:k)"), {"k": BOOTSTRAP_LOCK_KEY})
        role_id = db.scalar(select(Role.id).where(Role.name == SUPER_ADMIN))
        if role_id is None:
            raise CliError("Papel super_admin não encontrado. Rode as migrações antes.")
        if db.scalar(select(UserRole.user_id).where(UserRole.role_id == role_id).limit(1)):
            raise CliError("Já existe um administrador. O bootstrap só cria o primeiro.")
        if db.scalar(select(User.id).where(User.email == email)):
            raise CliError("Já existe usuário com este e-mail.")
        user = User(
            id=uuid.uuid4(),
            email=email,
            display_name=display_name.strip(),
            password_hash=passwords.hash_password(password),
            status="active",
            failed_login_count=0,
        )
        db.add(user)
        db.flush()
        now = datetime.now(UTC)
        db.add(UserRole(user_id=user.id, role_id=role_id, granted_by=None, granted_at=now))
        audit.record(
            db,
            action="user.bootstrap_admin",
            result="success",
            actor_type="system",
            resource_type="user",
            resource_id=str(user.id),
            details={"role": SUPER_ADMIN},
            now=now,
        )
        db.commit()
        return user.id


def issue_recovery(engine: Engine, email: str) -> str:
    """Emite o token de recuperação (15 min, uso único). O token só existe
    em claro aqui; no banco fica o SHA-256. Auditado como ``system``."""
    email = normalize_email(email)
    now = datetime.now(UTC)
    with DbSession(engine) as db:
        user = db.scalar(select(User).where(User.email == email))
        if user is None or user.status != "active":
            raise CliError("Conta inexistente ou desativada.")
        token = mfa.issue_recovery_token(db, user.id, now)
        audit.record(
            db,
            action="auth.recovery_issued",
            result="success",
            actor_type="system",
            resource_type="user",
            resource_id=str(user.id),
            now=now,
        )
        db.commit()
        return token


def revoke_mfa(engine: Engine, email: str) -> None:
    """Revoga o MFA ativo de uma conta e encerra as sessões dela (ADR 0008).

    Para o caso de o único administrador perder o TOTP e os códigos de recuperação. Só
    pelo CLI, no servidor (quem tem acesso ao host já está fora da proteção do Core,
    CLAUDE.md 9.3). A conta recadastra o TOTP no próximo login. Auditado como ``system``.
    """
    email = normalize_email(email)
    now = datetime.now(UTC)
    with DbSession(engine) as db:
        user = db.scalar(select(User).where(User.email == email).with_for_update())
        factor = (
            db.scalar(
                select(MfaFactor)
                .where(MfaFactor.user_id == user.id, MfaFactor.status == "active")
                .with_for_update()
            )
            if user is not None
            else None
        )
        if user is None or factor is None:
            raise CliError("Conta inexistente ou sem MFA ativo.")
        factor.status = "revoked"
        factor.revoked_at = now
        mfa.revoke_all_sessions(db, user.id, now)
        audit.record(
            db,
            action="user.mfa_reset",
            result="success",
            actor_type="system",
            resource_type="user",
            resource_id=str(user.id),
            reason="cli",
            now=now,
        )
        db.commit()


def record_authorization(engine: Engine, reference: str, description: str, days: int) -> uuid.UUID:
    """Registra o termo de autorização do operador (CLAUDE.md 9.4). Só pelo CLI,
    no servidor: não existe rota HTTP para isso. Auditado como ``system``."""
    if not 1 <= days <= 365:
        raise CliError("--days deve ficar entre 1 e 365.")
    if not reference.strip() or not description.strip():
        raise CliError("Referência e descrição são obrigatórias.")
    if any(ord(c) < 32 or ord(c) == 127 for c in reference + description):
        raise CliError("Referência e descrição não aceitam caracteres de controle.")
    now = datetime.now(UTC)
    with DbSession(engine) as db:
        row = OperatorAuthorization(
            id=uuid.uuid4(),
            reference=reference.strip(),
            description=description.strip(),
            valid_from=now,
            valid_until=now + timedelta(days=days),
            recorded_at=now,
        )
        db.add(row)
        db.flush()
        audit.record(
            db,
            action="authorization.recorded",
            result="success",
            actor_type="system",
            resource_type="authorization",
            resource_id=str(row.id),
            details={"days": days},
            now=now,
        )
        db.commit()
        return row.id


def revoke_authorization(engine: Engine, authorization_id: uuid.UUID) -> None:
    now = datetime.now(UTC)
    with DbSession(engine) as db:
        row = db.get(OperatorAuthorization, authorization_id, with_for_update=True)
        if row is None:
            raise CliError("Termo não encontrado.")
        if row.revoked_at is not None:
            raise CliError("Termo já estava revogado.")
        row.revoked_at = now
        audit.record(
            db,
            action="authorization.revoked",
            result="success",
            actor_type="system",
            resource_type="authorization",
            resource_id=str(row.id),
            now=now,
        )
        db.commit()


def purge_expired(engine: Engine) -> dict[str, int]:
    """Remove dados vencidos (complemento 2.1): ingest_records com mais de 7
    dias, idempotency_keys vencidas e tokens de enrolamento vencidos e NÃO usados. Roda como
    ``ares_owner``; o ``ares_app`` não tem DELETE."""
    now = datetime.now(UTC)
    removed: dict[str, int] = {}
    with engine.begin() as conn:
        for table, column, limit, extra in (
            ("ingest_records", "received_at", now - timedelta(days=7), ""),
            ("idempotency_keys", "expires_at", now, ""),
            # Só os NÃO usados: o token usado fica como rastro do enrolamento.
            ("agent_enrollment_tokens", "expires_at", now, " AND used_at IS NULL"),
        ):
            # Nomes de tabela, coluna e condição são constantes acima, nunca entrada.
            result = conn.execute(
                text(f"DELETE FROM {table} WHERE {column} < :limit{extra}"), {"limit": limit}
            )
            removed[table] = result.rowcount
    return removed


def verify_audit(
    engine: Engine, expected_head: tuple[int, bytes] | None = None
) -> audit.VerifyResult:
    with DbSession(engine) as db:
        return audit.verify_chain(db, expected_head=expected_head)


def parse_head(value: str) -> tuple[int, bytes]:
    try:
        raw_id, raw_hash = value.split(":", 1)
        digest = bytes.fromhex(raw_hash)
        if len(digest) != 32:
            raise ValueError
        return int(raw_id), digest
    except ValueError:
        raise CliError("--expect-head deve ser <id>:<entry_hash em hex>.") from None


def _read_password(from_stdin: bool) -> str:
    if from_stdin:
        return sys.stdin.readline().rstrip("\r\n")
    first = getpass.getpass("Senha: ")
    if getpass.getpass("Repita a senha: ") != first:
        raise CliError("As senhas não conferem.")
    return first


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="app.cli")
    sub = parser.add_subparsers(dest="command", required=True)
    create = sub.add_parser("create-admin", help="Cria o primeiro administrador.")
    create.add_argument("--email", required=True)
    create.add_argument("--display-name", required=True)
    create.add_argument("--password-stdin", action="store_true")
    sub.add_parser("generate-mfa-key", help="Gera uma chave para ARES_MFA_KEY.")
    recovery = sub.add_parser("issue-recovery", help="Emite um token de recuperação de conta.")
    recovery.add_argument("--email", required=True)
    revoke_mfa_cmd = sub.add_parser(
        "revoke-mfa", help="Revoga o MFA de uma conta (administrador sem TOTP nem códigos)."
    )
    revoke_mfa_cmd.add_argument("--email", required=True)
    authz = sub.add_parser(
        "record-authorization", help="Registra o termo de autorização do operador."
    )
    authz.add_argument("--reference", required=True, help="Documento ou identificador do termo.")
    authz.add_argument(
        "--description", required=True, help="Escopo: o que e onde pode ser monitorado."
    )
    authz.add_argument("--days", type=int, required=True, help="Validade em dias (1 a 365).")
    revoke_authz = sub.add_parser("revoke-authorization", help="Revoga um termo de autorização.")
    revoke_authz.add_argument("--id", required=True)
    sub.add_parser("purge-expired", help="Remove dados vencidos (ingest_records etc.).")
    verify = sub.add_parser("verify-audit", help="Confere o encadeamento da auditoria.")
    verify.add_argument(
        "--expect-head",
        help="Âncora <id>:<entry_hash> anotada antes, fora do servidor. Detecta "
        "remoção das últimas entradas.",
    )
    args = parser.parse_args(argv)

    if args.command == "generate-mfa-key":
        # Só imprime; nada é gravado. Coloque em ARES_MFA_KEY no .env.
        print(crypto.generate_key())
        return 0

    # Usa o dono do schema (ares_owner), não o usuário da API: o ares_app não
    # tem INSERT em users nem em user_roles (ADR 0003).
    settings = Settings()
    if settings.migration_database_url is None:
        print("ARES_MIGRATION_DATABASE_URL não definido (ver .env.example).", file=sys.stderr)
        return 2
    engine = build_engine(settings.migration_database_url.get_secret_value())
    if args.command == "verify-audit":
        try:
            anchor = parse_head(args.expect_head) if args.expect_head else None
            result = verify_audit(engine, anchor)
        except CliError as exc:
            print(f"Erro: {exc}", file=sys.stderr)
            return 1
        finally:
            engine.dispose()
        if result.ok:
            print(f"Auditoria íntegra: {result.checked} entradas conferidas.")
            if result.head_id is not None and result.head_hash is not None:
                print(
                    f"Cabeça (guarde fora do servidor): {result.head_id}:{result.head_hash.hex()}"
                )
            if anchor is None:
                print("Sem --expect-head: remoção das últimas entradas não é detectada.")
            return 0
        print(
            f"FALHA na auditoria: entrada {result.first_bad_id} ({result.problem}); "
            f"{result.checked} entradas anteriores conferem.",
            file=sys.stderr,
        )
        return 3
    if args.command in ("record-authorization", "revoke-authorization", "purge-expired"):
        try:
            if args.command == "record-authorization":
                new_id = record_authorization(engine, args.reference, args.description, args.days)
                print(f"Termo registrado: {new_id}")
            elif args.command == "revoke-authorization":
                try:
                    target = uuid.UUID(args.id)
                except ValueError:
                    raise CliError("--id deve ser um UUID.") from None
                revoke_authorization(engine, target)
                print("Termo revogado.")
            else:
                for table, count in purge_expired(engine).items():
                    print(f"{table}: {count} removidos")
        except CliError as exc:
            print(f"Erro: {exc}", file=sys.stderr)
            return 1
        finally:
            engine.dispose()
        return 0
    if args.command == "revoke-mfa":
        try:
            revoke_mfa(engine, args.email)
        except CliError as exc:
            print(f"Erro: {exc}", file=sys.stderr)
            return 1
        finally:
            engine.dispose()
        print("MFA revogado e sessões encerradas. A conta recadastra o TOTP no próximo login.")
        return 0
    if args.command == "issue-recovery":
        try:
            token = issue_recovery(engine, args.email)
        except CliError as exc:
            print(f"Erro: {exc}", file=sys.stderr)
            return 1
        finally:
            engine.dispose()
        print(f"Token de recuperação (válido por {mfa.RECOVERY_TOKEN_MINUTES} min, uso único):")
        print(token)
        return 0
    try:
        user_id = create_admin(
            engine, args.email, args.display_name, _read_password(args.password_stdin)
        )
    except CliError as exc:
        print(f"Erro: {exc}", file=sys.stderr)
        return 1
    finally:
        engine.dispose()
    print(f"Administrador criado: {user_id}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
