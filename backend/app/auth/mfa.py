"""MFA (TOTP) e recuperação de conta (ADR 0005).

Sem dependência de HTTP. NÃO faz commit: quem chama grava a ação e a
auditoria na mesma transação (ADR 0004).
"""

import hashlib
import hmac
import secrets
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta

import pyotp
from sqlalchemy import select, update
from sqlalchemy.orm import Session as DbSession

from app.auth import crypto, passwords
from app.auth.models import (
    MfaChallenge,
    MfaFactor,
    RecoveryCode,
    RecoveryToken,
    Role,
    Session,
    User,
    UserRole,
)

ADMIN_ROLES = frozenset({"super_admin", "security_admin"})
TOTP_PERIOD = 30
TOTP_WINDOW = 1  # ±1 step de tolerância para relógio
CHALLENGE_MINUTES = 5
CHALLENGE_MAX_ATTEMPTS = 5
RECOVERY_TOKEN_MINUTES = 15
RECOVERY_CODE_COUNT = 10
ISSUER = "ARES"


class MfaUnavailable(Exception):
    """ARES_MFA_KEY ausente ou inválida."""


def _sha256(value: str) -> bytes:
    return hashlib.sha256(value.encode("utf-8")).digest()


def load_key(raw: str | None) -> bytes:
    if raw is None:
        raise MfaUnavailable
    try:
        return crypto.parse_key(raw)
    except crypto.MfaCryptoError:
        raise MfaUnavailable from None


def is_admin(db: DbSession, user_id: uuid.UUID) -> bool:
    names = db.scalars(
        select(Role.name)
        .join(UserRole, UserRole.role_id == Role.id)
        .where(UserRole.user_id == user_id)
    )
    return any(n in ADMIN_ROLES for n in names)


def active_factor(db: DbSession, user_id: uuid.UUID, lock: bool = False) -> MfaFactor | None:
    query = select(MfaFactor).where(
        MfaFactor.user_id == user_id, MfaFactor.type == "totp", MfaFactor.status == "active"
    )
    if lock:
        query = query.with_for_update()
    return db.scalar(query)


# --- TOTP -------------------------------------------------------------------


def match_step(secret: str, code: str, now: datetime) -> int | None:
    """Step TOTP em que ``code`` confere (janela ±1), ou ``None``."""
    code = code.strip()
    if not (code.isascii() and code.isdigit() and len(code) == 6):
        return None
    totp = pyotp.TOTP(secret, interval=TOTP_PERIOD)
    base = int(now.timestamp() // TOTP_PERIOD)
    for step in (base - TOTP_WINDOW, base, base + TOTP_WINDOW):
        if hmac.compare_digest(totp.at(step * TOTP_PERIOD), code):
            return step
    return None


def accept_code(key: bytes, factor: MfaFactor, code: str, now: datetime) -> bool:
    """Confere o código e consome o step (reuso é recusado). ``factor`` deve
    estar travado (``FOR UPDATE``) por quem chama."""
    secret = crypto.decrypt_secret(key, factor.user_id, factor.type, factor.secret_ciphertext)
    step = match_step(secret, code, now)
    if step is None:
        return False
    if factor.last_used_step is not None and step <= factor.last_used_step:
        return False  # mesmo código (ou anterior) já usado
    factor.last_used_step = step
    factor.last_used_at = now
    return True


# --- cadastro ---------------------------------------------------------------


@dataclass(frozen=True)
class Enrollment:
    # repr=False: o segredo não pode aparecer em log, traceback ou exceção.
    secret: str = field(repr=False)
    otpauth_uri: str = field(repr=False)


def start_enrollment(db: DbSession, key: bytes, user: User, now: datetime) -> Enrollment:
    # Cadastro novo descarta cadastros pendentes anteriores.
    db.execute(
        update(MfaFactor)
        .where(MfaFactor.user_id == user.id, MfaFactor.status == "pending")
        .values(status="revoked", revoked_at=now)
    )
    secret = pyotp.random_base32()
    db.add(
        MfaFactor(
            id=uuid.uuid4(),
            user_id=user.id,
            type="totp",
            secret_ciphertext=crypto.encrypt_secret(key, user.id, "totp", secret),
            secret_ref=crypto.KEY_REF,
            status="pending",
            created_at=now,
        )
    )
    db.flush()
    uri = pyotp.TOTP(secret, interval=TOTP_PERIOD).provisioning_uri(
        name=user.email, issuer_name=ISSUER
    )
    return Enrollment(secret=secret, otpauth_uri=uri)


def confirm_enrollment(
    db: DbSession, key: bytes, user_id: uuid.UUID, code: str, now: datetime
) -> bool:
    """Ativa o fator pendente se ``code`` confere. Também grava o step usado,
    para que o mesmo código não valha de novo no login."""
    factor = db.scalar(
        select(MfaFactor)
        .where(
            MfaFactor.user_id == user_id, MfaFactor.type == "totp", MfaFactor.status == "pending"
        )
        .order_by(MfaFactor.created_at.desc())
        .limit(1)  # dois enroll concorrentes podem deixar dois pendentes: vale o mais novo
        .with_for_update()
    )
    if factor is None or not accept_code(key, factor, code, now):
        return False
    # Um fator ativo por tipo (CLAUDE.md 6.1): o anterior, se houver, é revogado.
    db.execute(
        update(MfaFactor)
        .where(
            MfaFactor.user_id == user_id,
            MfaFactor.type == "totp",
            MfaFactor.status == "active",
            MfaFactor.id != factor.id,
        )
        .values(status="revoked", revoked_at=now)
    )
    factor.status = "active"
    db.flush()
    return True


# --- códigos de recuperação -------------------------------------------------


def _format_code(raw: str) -> str:
    return f"{raw[:5]}-{raw[5:]}"


def _normalize_code(code: str) -> str:
    return code.replace("-", "").replace(" ", "").lower()


def issue_recovery_codes(db: DbSession, user_id: uuid.UUID, now: datetime) -> list[str]:
    """Gera um lote novo e invalida o anterior. Devolve os códigos em claro
    (única vez em que existem)."""
    db.execute(
        update(RecoveryCode)
        .where(RecoveryCode.user_id == user_id, RecoveryCode.used_at.is_(None))
        .values(used_at=now)
    )
    codes: list[str] = []
    for _ in range(RECOVERY_CODE_COUNT):
        raw = secrets.token_hex(5)  # 10 caracteres, 40 bits
        codes.append(_format_code(raw))
        db.add(
            RecoveryCode(
                id=uuid.uuid4(),
                user_id=user_id,
                code_hash=passwords.hash_password(raw),
                created_at=now,
            )
        )
    db.flush()
    return codes


def consume_recovery_code(db: DbSession, user_id: uuid.UUID, code: str, now: datetime) -> bool:
    raw = _normalize_code(code)
    if len(raw) != 10 or not all(c in "0123456789abcdef" for c in raw):
        return False
    rows = db.scalars(
        select(RecoveryCode)
        .where(RecoveryCode.user_id == user_id, RecoveryCode.used_at.is_(None))
        .with_for_update()
    ).all()
    for row in rows:
        if passwords.verify_password(row.code_hash, raw):
            row.used_at = now
            return True
    return False


# --- desafio entre a senha e o segundo fator --------------------------------


def create_challenge(db: DbSession, user_id: uuid.UUID, purpose: str, now: datetime) -> str:
    # Um desafio por vez: os anteriores deixam de valer.
    db.execute(
        update(MfaChallenge)
        .where(MfaChallenge.user_id == user_id, MfaChallenge.used_at.is_(None))
        .values(used_at=now)
    )
    token = secrets.token_urlsafe(32)
    db.add(
        MfaChallenge(
            id=uuid.uuid4(),
            user_id=user_id,
            token_hash=_sha256(token),
            purpose=purpose,
            attempts=0,
            created_at=now,
            expires_at=now + timedelta(minutes=CHALLENGE_MINUTES),
        )
    )
    db.flush()
    return token


def load_challenge(db: DbSession, token: str, purpose: str, now: datetime) -> MfaChallenge | None:
    challenge = db.scalar(
        select(MfaChallenge).where(MfaChallenge.token_hash == _sha256(token)).with_for_update()
    )
    if (
        challenge is None
        or challenge.used_at is not None
        or challenge.expires_at <= now
        or challenge.purpose != purpose
        or challenge.attempts >= CHALLENGE_MAX_ATTEMPTS
    ):
        return None
    return challenge


def register_failure(challenge: MfaChallenge, now: datetime) -> bool:
    """Conta a falha. Devolve ``True`` se o desafio foi esgotado e queimado."""
    challenge.attempts += 1
    if challenge.attempts >= CHALLENGE_MAX_ATTEMPTS:
        challenge.used_at = now
        return True
    return False


# --- recuperação de conta ---------------------------------------------------


def issue_recovery_token(db: DbSession, user_id: uuid.UUID, now: datetime) -> str:
    db.execute(
        update(RecoveryToken)
        .where(RecoveryToken.user_id == user_id, RecoveryToken.used_at.is_(None))
        .values(used_at=now)
    )
    token = secrets.token_urlsafe(32)
    db.add(
        RecoveryToken(
            id=uuid.uuid4(),
            user_id=user_id,
            token_hash=_sha256(token),
            created_at=now,
            expires_at=now + timedelta(minutes=RECOVERY_TOKEN_MINUTES),
        )
    )
    db.flush()
    return token


def use_recovery_token(db: DbSession, token: str, now: datetime) -> User | None:
    """Consome o token (uso único). Devolve o usuário ou ``None``, sem
    distinguir inexistente, expirado, usado ou conta desativada."""
    row = db.scalar(
        select(RecoveryToken).where(RecoveryToken.token_hash == _sha256(token)).with_for_update()
    )
    if row is None or row.used_at is not None or row.expires_at <= now:
        return None
    # Trava a linha do usuário: um /verify em andamento termina antes (e sua
    # sessão nova é revogada abaixo), em vez de sobreviver à recuperação.
    user = db.scalar(select(User).where(User.id == row.user_id).with_for_update())
    if user is None or user.status != "active":
        return None
    row.used_at = now
    return user


def revoke_all_sessions(db: DbSession, user_id: uuid.UUID, now: datetime) -> None:
    db.execute(
        update(Session)
        .where(Session.user_id == user_id, Session.revoked_at.is_(None))
        .values(revoked_at=now)
    )
