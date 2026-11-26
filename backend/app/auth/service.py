"""Regras de autenticação e sessão (ADR 0003).

Sem dependência de HTTP: recebe sessão de banco e valores já validados.
"""

import base64
import hashlib
import secrets
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession

from app.auth import passwords
from app.auth.models import Permission, Role, RolePermission, Session, User, UserRole
from app.core.config import Settings

SESSION_TOKEN_BYTES = 32
# Não atualizar last_seen_at a cada requisição: só se passou este intervalo.
TOUCH_INTERVAL = timedelta(seconds=60)


def normalize_email(email: str) -> str:
    return email.strip().lower()


def _sha256(value: str) -> bytes:
    return hashlib.sha256(value.encode("utf-8")).digest()


def csrf_token_for(session_token: str) -> str:
    """Token CSRF derivado do token de sessão. Imprevisível sem o cookie, e o
    cookie não pode ser obtido a partir dele. Não precisa ser gravado."""
    digest = hashlib.sha256(b"ares-csrf:" + session_token.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def csrf_matches(session_token: str, presented: str | None) -> bool:
    if not presented:
        return False
    # Comparação em bytes: com str, compare_digest lança TypeError para
    # caracteres fora de ASCII (cabeçalhos chegam decodificados em latin-1).
    return secrets.compare_digest(
        csrf_token_for(session_token).encode("ascii"), presented.encode("utf-8", "replace")
    )


def authenticate(
    db: DbSession, settings: Settings, email: str, password: str, now: datetime
) -> User | None:
    """Devolve o usuário se a credencial é válida. Toda falha gasta o tempo
    de uma verificação Argon2 e tem o mesmo resultado (``None``).

    A linha do usuário fica travada (``FOR UPDATE``) do início ao fim:
    tentativas simultâneas contra a mesma conta são serializadas, e o
    contador de falhas não perde atualização (cada uma vê o valor anterior
    e o bloqueio já gravado).
    """
    user = db.scalar(select(User).where(User.email == normalize_email(email)).with_for_update())
    if (
        user is None
        or user.status != "active"
        or (user.locked_until is not None and user.locked_until > now)
    ):
        passwords.verify_dummy(password)
        db.commit()  # libera a trava; mesmo número de idas ao banco das outras falhas
        return None

    if not passwords.verify_password(user.password_hash, password):
        user.failed_login_count += 1
        excess = user.failed_login_count - settings.login_max_failures
        if excess >= 0:
            delay = min(
                settings.login_lockout_base_seconds * (2**excess),
                settings.login_lockout_max_seconds,
            )
            user.locked_until = now + timedelta(seconds=delay)
        user.updated_at = now
        db.commit()
        return None

    user.failed_login_count = 0
    user.locked_until = None
    if passwords.needs_rehash(user.password_hash):
        user.password_hash = passwords.hash_password(password)
    user.updated_at = now
    db.commit()
    return user


def create_session(
    db: DbSession, settings: Settings, user: User, user_agent: str | None, now: datetime
) -> str:
    """Cria uma sessão nova e devolve o token (só vai para o cookie)."""
    token = secrets.token_urlsafe(SESSION_TOKEN_BYTES)
    absolute = now + timedelta(hours=settings.session_absolute_hours)
    db.add(
        Session(
            id=uuid.uuid4(),
            user_id=user.id,
            token_hash=_sha256(token),
            ua_hash=_sha256(user_agent) if user_agent else None,
            created_at=now,
            last_seen_at=now,
            idle_expires_at=min(now + timedelta(minutes=settings.session_idle_minutes), absolute),
            absolute_expires_at=absolute,
        )
    )
    db.commit()
    return token


@dataclass(frozen=True)
class AuthContext:
    user: User
    session: Session
    token: str


def resolve_session(
    db: DbSession, settings: Settings, token: str, now: datetime
) -> AuthContext | None:
    row = db.execute(
        select(Session, User)
        .join(User, User.id == Session.user_id)
        .where(Session.token_hash == _sha256(token))
    ).first()
    if row is None:
        return None
    session, user = row
    if (
        session.revoked_at is not None
        or session.idle_expires_at <= now
        or session.absolute_expires_at <= now
        or user.status != "active"
    ):
        return None
    if now - session.last_seen_at >= TOUCH_INTERVAL:
        session.last_seen_at = now
        session.idle_expires_at = min(
            now + timedelta(minutes=settings.session_idle_minutes), session.absolute_expires_at
        )
        db.commit()
    return AuthContext(user=user, session=session, token=token)


def revoke_session_by_token(db: DbSession, token: str, now: datetime) -> None:
    session = db.scalar(select(Session).where(Session.token_hash == _sha256(token)))
    if session is not None and session.revoked_at is None:
        session.revoked_at = now
        db.commit()


def roles_and_permissions(db: DbSession, user_id: uuid.UUID) -> tuple[list[str], list[str]]:
    roles = db.scalars(
        select(Role.name)
        .join(UserRole, UserRole.role_id == Role.id)
        .where(UserRole.user_id == user_id)
    ).all()
    perms = db.scalars(
        select(Permission.name)
        .join(RolePermission, RolePermission.permission_id == Permission.id)
        .join(UserRole, UserRole.role_id == RolePermission.role_id)
        .where(UserRole.user_id == user_id)
        .distinct()
    ).all()
    return sorted(roles), sorted(perms)
