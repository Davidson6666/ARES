"""Fluxos compartilhados entre login e MFA: estabelecer sessão e resposta ``/me``.

Existe para evitar import circular entre ``router`` (login) e ``mfa_router``
(verificação do segundo fator), que terminam do mesmo jeito: sessão nova,
auditoria e cookie.
"""

import uuid
from datetime import datetime

from fastapi import Request, Response
from pydantic import BaseModel
from sqlalchemy.orm import Session as DbSession

from app.audit import service as audit
from app.auth import service
from app.auth.dependencies import SESSION_COOKIE
from app.auth.models import User
from app.core.config import Settings

# Cookie do desafio de MFA (senha já conferida, segundo fator pendente).
# Prefixo __Host-: Secure, Path=/ e sem Domain, exigidos pelo navegador.
CHALLENGE_COOKIE = "__Host-ares_mfa"


class MeResponse(BaseModel):
    id: uuid.UUID
    email: str
    display_name: str
    roles: list[str]
    permissions: list[str]
    # O cliente guarda em memória e envia em X-CSRF-Token nas mutações.
    csrf_token: str


def request_id(request: Request) -> str | None:
    rid: str | None = getattr(request.state, "request_id", None)
    return rid


def build_me(db: DbSession, user: User, token: str) -> MeResponse:
    roles, perms = service.roles_and_permissions(db, user.id)
    return MeResponse(
        id=user.id,
        email=user.email,
        display_name=user.display_name,
        roles=roles,
        permissions=perms,
        csrf_token=service.csrf_token_for(token),
    )


def establish_session(
    db: DbSession,
    settings: Settings,
    request: Request,
    response: Response,
    user: User,
    now: datetime,
    method: str | None = None,
) -> MeResponse:
    """Cria a sessão, audita ``auth.login`` e faz o commit de tudo que estiver
    pendente na transação (quem chama grava suas auditorias antes).

    Fixação de sessão: qualquer sessão anterior deste navegador é revogada e
    um identificador novo é sempre emitido.
    """
    service.clear_failures(user, now)  # login completo: zera palpites de senha e de MFA
    previous = request.cookies.get(SESSION_COOKIE)
    if previous:
        service.revoke_session_by_token(db, previous, now)
    token = service.create_session(db, settings, user, request.headers.get("user-agent"), now)
    audit.record(
        db,
        action="auth.login",
        result="success",
        actor_type="user",
        actor_user_id=user.id,
        resource_type="user",
        resource_id=str(user.id),
        request_id=request_id(request),
        details={"mfa": method} if method else None,
        now=now,
    )
    db.commit()
    response.set_cookie(
        SESSION_COOKIE,
        token,
        max_age=settings.session_absolute_hours * 3600,
        path="/",
        secure=True,
        httponly=True,
        samesite="strict",
    )
    response.delete_cookie(
        CHALLENGE_COOKIE, path="/", secure=True, httponly=True, samesite="strict"
    )
    return build_me(db, user, token)
