"""Linha de comando do Core.

Bootstrap do primeiro administrador (complemento, seção 3.3): só por este
comando, executado no servidor. Não existe rota HTTP para isso.

Uso:
    uv run python -m app.cli create-admin --email admin@exemplo.local --display-name "Admin"
    uv run python -m app.cli verify-audit [--expect-head <id>:<hash>]
    uv run python -m app.cli generate-mfa-key
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
from datetime import UTC, datetime

from sqlalchemy import Engine, select, text
from sqlalchemy.orm import Session as DbSession

from app.audit import service as audit
from app.auth import crypto, mfa, passwords
from app.auth.models import Role, User, UserRole
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
