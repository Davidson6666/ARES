"""Rotas de identidade sob /api/v1 (complemento, seção 3.2; v1.1, seção 15)."""

import base64
import binascii
import re
import uuid

import structlog
from fastapi import APIRouter, Depends, Query, Request, Response
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession

from app.audit import service as audit
from app.auth import passwords, service
from app.auth.dependencies import (
    SESSION_COOKIE,
    allow_query,
    get_db,
    get_settings,
    require_json,
    require_permission,
    require_session,
    utcnow,
)
from app.auth.models import Permission
from app.auth.service import AuthContext
from app.core.config import Settings
from app.core.errors import ApiError
from app.core.rate_limit import client_key

router = APIRouter(prefix="/api/v1")

log = structlog.get_logger("ares.auth")


def _request_id(request: Request) -> str | None:
    rid: str | None = getattr(request.state, "request_id", None)
    return rid


_INVALID_CREDENTIALS = ApiError(401, "invalid_credentials", "E-mail ou senha inválidos.")


class LoginRequest(BaseModel):
    # Lista explícita de campos: qualquer campo extra é 422 (complemento 3.3).
    model_config = ConfigDict(extra="forbid")
    email: str = Field(min_length=3, max_length=254)
    # Sem política aqui (só no cadastro); limite para não aceitar corpo enorme.
    password: str = Field(min_length=1, max_length=1024)

    @field_validator("email")
    @classmethod
    def _no_control_chars(cls, value: str) -> str:
        if any(ord(c) < 32 or ord(c) == 127 for c in value):
            raise ValueError("caractere de controle")
        return value


class MeResponse(BaseModel):
    id: uuid.UUID
    email: str
    display_name: str
    roles: list[str]
    permissions: list[str]
    # O cliente guarda em memória e envia em X-CSRF-Token nas mutações.
    csrf_token: str


def _me(db: DbSession, ctx_user_id: uuid.UUID, email: str, name: str, token: str) -> MeResponse:
    roles, perms = service.roles_and_permissions(db, ctx_user_id)
    return MeResponse(
        id=ctx_user_id,
        email=email,
        display_name=name,
        roles=roles,
        permissions=perms,
        csrf_token=service.csrf_token_for(token),
    )


@router.post(
    "/auth/login",
    response_model=MeResponse,
    dependencies=[Depends(require_json), Depends(allow_query())],
)
def login(
    body: LoginRequest,
    request: Request,
    response: Response,
    db: DbSession = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> MeResponse:
    retry_after = request.app.state.login_limiter.hit(
        client_key(request.client.host if request.client else None)
    )
    if retry_after is not None:
        # Só log operacional: sob ataque, não gravar no banco a cada tentativa.
        log.warning("login.rate_limited", request_id=_request_id(request))
        raise ApiError(
            429,
            "rate_limited",
            "Muitas tentativas. Tente novamente mais tarde.",
            headers={"Retry-After": str(retry_after)},
        )

    now = utcnow()
    try:
        outcome = service.authenticate(db, settings, body.email, body.password, now)
    except passwords.HasherBusy:
        log.warning("login.busy", request_id=_request_id(request))
        raise ApiError(
            503, "busy", "Serviço ocupado. Tente novamente.", headers={"Retry-After": "1"}
        ) from None
    user = outcome.user
    if user is None:
        # Conta desconhecida: nenhum dado do e-mail digitado é gravado.
        audit.record(
            db,
            action="auth.login",
            result="failure",
            actor_type="user" if outcome.user_id else "anonymous",
            actor_user_id=outcome.user_id,
            resource_type="user" if outcome.user_id else None,
            resource_id=str(outcome.user_id) if outcome.user_id else None,
            reason=outcome.reason,
            request_id=_request_id(request),
            details={"locked_now": True} if outcome.locked_now else None,
            now=now,
        )
        db.commit()
        raise _INVALID_CREDENTIALS

    # Fixação de sessão: qualquer sessão anterior deste navegador é revogada
    # e um identificador novo é sempre emitido.
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
        request_id=_request_id(request),
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
    return _me(db, user.id, user.email, user.display_name, token)


@router.post("/auth/logout", status_code=204, dependencies=[Depends(allow_query())])
def logout(
    request: Request,
    response: Response,
    ctx: AuthContext = Depends(require_session),
    db: DbSession = Depends(get_db),
) -> Response:
    now = utcnow()
    session_id = service.revoke_session_by_token(db, ctx.token, now)
    audit.record(
        db,
        action="auth.logout",
        result="success",
        actor_type="user",
        actor_user_id=ctx.user.id,
        resource_type="session",
        resource_id=str(session_id) if session_id else None,
        request_id=_request_id(request),
        now=now,
    )
    db.commit()
    response.status_code = 204
    response.delete_cookie(SESSION_COOKIE, path="/", secure=True, httponly=True, samesite="strict")
    return response


@router.get("/me", response_model=MeResponse, dependencies=[Depends(allow_query())])
def me(ctx: AuthContext = Depends(require_session), db: DbSession = Depends(get_db)) -> MeResponse:
    return _me(db, ctx.user.id, ctx.user.email, ctx.user.display_name, ctx.token)


class PermissionItem(BaseModel):
    name: str
    description: str


class PermissionPage(BaseModel):
    items: list[PermissionItem]
    next_cursor: str | None


_require_roles_manage = require_permission("roles.manage")

_PERMISSION_NAME = re.compile(r"^[a-z]+\.[a-z]+$")


def _encode_cursor(name: str) -> str:
    return base64.urlsafe_b64encode(name.encode("ascii")).rstrip(b"=").decode("ascii")


_MAX_CURSOR_LENGTH = 200


def _decode_cursor(cursor: str) -> str:
    # Cursor opaco por contrato (o cliente não deve interpretar), mas não
    # cifrado: é o último nome da página em base64url (ADR 0003).
    if len(cursor) > _MAX_CURSOR_LENGTH:
        raise ApiError(400, "invalid_cursor", "Cursor inválido.")
    try:
        name = base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4)).decode("ascii")
    except binascii.Error, UnicodeDecodeError, ValueError:
        name = ""
    if not _PERMISSION_NAME.fullmatch(name):
        raise ApiError(400, "invalid_cursor", "Cursor inválido.")
    return name


@router.get(
    "/permissions",
    response_model=PermissionPage,
    dependencies=[Depends(allow_query("limit", "cursor"))],
)
def list_permissions(
    limit: int = Query(default=50, ge=1, le=200),
    cursor: str | None = Query(default=None),
    _: AuthContext = Depends(_require_roles_manage),
    db: DbSession = Depends(get_db),
) -> PermissionPage:
    query = select(Permission).order_by(Permission.name).limit(limit + 1)
    if cursor is not None:
        query = query.where(Permission.name > _decode_cursor(cursor))
    rows = list(db.scalars(query))
    page, more = rows[:limit], len(rows) > limit
    return PermissionPage(
        items=[PermissionItem(name=p.name, description=p.description) for p in page],
        next_cursor=_encode_cursor(page[-1].name) if more and page else None,
    )
