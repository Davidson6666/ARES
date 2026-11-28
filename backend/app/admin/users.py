"""Rotas de usuários, papéis (leitura) e permissões (ADR 0008; complemento 3.2).

Esta parte é a de leitura, criação e ``PATCH``. Desativar, papéis e permissões (com as
regras de escalada e do último administrador) ficam em ``app.admin.roles``.
"""

import re
import uuid
from datetime import datetime, timedelta
from typing import Any

from fastapi import APIRouter, Depends, Query, Request, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session as DbSession

from app.admin import pagination
from app.audit import service as audit
from app.auth import mfa
from app.auth.dependencies import (
    allow_query,
    get_db,
    require_any_permission,
    require_json,
    require_permission,
    utcnow,
)
from app.auth.models import Permission, Role, RolePermission, User, UserRole
from app.auth.service import AuthContext
from app.auth.session_flow import request_id
from app.core import idempotency
from app.core.errors import ApiError

router = APIRouter(prefix="/api/v1")

SETUP_TOKEN_HOURS = 24
# Hash que nenhuma senha satisfaz (não é um hash Argon2): a conta nova não tem senha
# utilizável até o usuário usar o token de configuração.
UNUSABLE_PASSWORD = "!"
_NO_STORE = {"Cache-Control": "no-store"}
_EMAIL = re.compile(r"^[^@\s\x00-\x1f\x7f]{1,64}@[^@\s\x00-\x1f\x7f]{1,255}$")

_require_users_read = require_permission("users.read")
_require_users_write = require_permission("users.write")
_require_roles_manage = require_permission("roles.manage")
_require_roles_read = require_any_permission("roles.manage", "users.read")


def _no_control(value: str) -> str:
    if any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise ValueError("caractere de controle")
    return value


class CreateUserRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    email: str = Field(min_length=3, max_length=254)
    display_name: str = Field(min_length=1, max_length=128)
    tenant_id: str | None = Field(default=None, min_length=1, max_length=128)

    @field_validator("email")
    @classmethod
    def _email(cls, value: str) -> str:
        value = value.lower()
        if not _EMAIL.fullmatch(value) or len(value) > 254:
            raise ValueError("e-mail inválido")
        return value

    _name = field_validator("display_name")(_no_control)
    _tenant = field_validator("tenant_id")(lambda v: v if v is None else _no_control(v))


class UpdateUserRequest(BaseModel):
    # Lista explícita de campos: roles, status, email etc. => 422 (atribuição em massa).
    model_config = ConfigDict(extra="forbid")
    display_name: str | None = Field(default=None, min_length=1, max_length=128)
    tenant_id: str | None = Field(default=None, min_length=1, max_length=128)

    _name = field_validator("display_name")(lambda v: v if v is None else _no_control(v))
    _tenant = field_validator("tenant_id")(lambda v: v if v is None else _no_control(v))


class UserOut(BaseModel):
    id: uuid.UUID
    email: str
    display_name: str
    status: str
    tenant_id: str | None
    roles: list[str]
    created_at: datetime


class UserCreated(UserOut):
    # Única vez em que o token existe em claro; não volta em repetição da chave.
    setup_token: str | None
    setup_expires_at: datetime
    replayed: bool = False


class UserList(BaseModel):
    items: list[UserOut]
    next_cursor: str | None


class RoleOut(BaseModel):
    id: uuid.UUID
    name: str
    description: str
    is_system: bool
    permissions: list[str]


class RoleList(BaseModel):
    items: list[RoleOut]
    next_cursor: str | None


class PermissionOut(BaseModel):
    name: str
    description: str


class PermissionList(BaseModel):
    items: list[PermissionOut]
    next_cursor: str | None


# --- apoio ---------------------------------------------------------------------------


def role_names(db: DbSession, user_ids: list[uuid.UUID]) -> dict[uuid.UUID, list[str]]:
    result: dict[uuid.UUID, list[str]] = {u: [] for u in user_ids}
    if user_ids:
        rows = db.execute(
            select(UserRole.user_id, Role.name)
            .join(Role, Role.id == UserRole.role_id)
            .where(UserRole.user_id.in_(user_ids))
            .order_by(Role.name)
        )
        for user_id, name in rows:
            result[user_id].append(name)
    return result


def user_out(user: User, roles: list[str]) -> UserOut:
    return UserOut(
        id=user.id,
        email=user.email,
        display_name=user.display_name,
        status=user.status,
        tenant_id=user.tenant_id,
        roles=roles,
        created_at=user.created_at,
    )


def visible_user(
    db: DbSession, ctx: AuthContext, user_id: uuid.UUID, *, lock: bool = False
) -> User:
    """Usuário dentro do escopo do ator; fora dele, 404 (não revela existência)."""
    query = select(User).where(User.id == user_id)
    if lock:
        query = query.with_for_update()
    user = db.scalar(query)
    tenant = ctx.user.tenant_id
    if user is None or (tenant is not None and user.tenant_id != tenant):
        raise ApiError(404, "not_found", "Recurso não encontrado.")
    return user


def audit_user(
    db: DbSession,
    request: Request,
    action: str,
    ctx: AuthContext,
    target: User,
    now: datetime,
    details: dict[str, Any] | None = None,
) -> None:
    audit.record(
        db,
        action=action,
        result="success",
        actor_type="user",
        actor_user_id=ctx.user.id,
        resource_type="user",
        resource_id=str(target.id),
        request_id=request_id(request),
        details=details,
        now=now,
    )


# --- usuários --------------------------------------------------------------------------


@router.get(
    "/users", response_model=UserList, dependencies=[Depends(allow_query("limit", "cursor"))]
)
def list_users(
    ctx: AuthContext = Depends(_require_users_read),
    db: DbSession = Depends(get_db),
    limit: int = Depends(pagination.limit_param),
    cursor: str | None = Query(default=None, max_length=512),
) -> UserList:
    position = pagination.decode(cursor, 2)
    query = select(User).order_by(User.created_at, User.id).limit(limit + 1)
    if ctx.user.tenant_id is not None:
        query = query.where(User.tenant_id == ctx.user.tenant_id)
    if position is not None:
        try:
            after_time = datetime.fromisoformat(position[0])
            after_id = uuid.UUID(position[1])
        except ValueError:
            raise ApiError(400, "invalid_cursor", "Cursor inválido.") from None
        query = query.where(
            (User.created_at > after_time)
            | ((User.created_at == after_time) & (User.id > after_id))
        )
    rows = list(db.scalars(query))
    page, more = rows[:limit], len(rows) > limit
    roles = role_names(db, [u.id for u in page])
    next_cursor = (
        pagination.encode([page[-1].created_at.isoformat(), str(page[-1].id)]) if more else None
    )
    return UserList(items=[user_out(u, roles[u.id]) for u in page], next_cursor=next_cursor)


@router.post(
    "/users",
    status_code=201,
    response_model=UserCreated,
    dependencies=[Depends(require_json), Depends(allow_query())],
)
def create_user(
    body: CreateUserRequest,
    request: Request,
    response: Response,
    ctx: AuthContext = Depends(_require_users_write),
    db: DbSession = Depends(get_db),
) -> UserCreated | Any:
    now = utcnow()
    key = idempotency.read_key(request)
    digest = idempotency.request_hash(body.model_dump_json().encode())
    stored = idempotency.lock_and_lookup(db, "user", ctx.user.id, key, digest, now)
    if stored is not None:
        return JSONResponse(
            stored.body,
            status_code=stored.status,
            headers={**_NO_STORE, "Idempotent-Replay": "true"},
        )
    tenant = ctx.user.tenant_id
    if tenant is not None and body.tenant_id not in (None, tenant):
        raise ApiError(403, "permission_denied", "A operação não é permitida.")
    user = User(
        id=uuid.uuid4(),
        email=body.email,
        display_name=body.display_name,
        password_hash=UNUSABLE_PASSWORD,
        status="active",
        tenant_id=tenant if tenant is not None else body.tenant_id,
    )
    db.add(user)
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        raise ApiError(409, "email_in_use", "Já existe um usuário com este e-mail.") from None
    token = mfa.issue_recovery_token(db, user.id, now, minutes=SETUP_TOKEN_HOURS * 60)
    expires = now + timedelta(hours=SETUP_TOKEN_HOURS)
    audit_user(db, request, "user.created", ctx, user, now)
    db.refresh(user)
    created = UserCreated(
        **user_out(user, []).model_dump(), setup_token=token, setup_expires_at=expires
    )
    # O que fica guardado para repetição NÃO tem o token.
    safe = created.model_copy(update={"setup_token": None, "replayed": True})
    idempotency.store(db, "user", ctx.user.id, key, digest, 201, safe.model_dump(mode="json"), now)
    db.commit()
    response.headers.update(_NO_STORE)
    return created


@router.patch(
    "/users/{user_id}",
    response_model=UserOut,
    dependencies=[Depends(require_json), Depends(allow_query())],
)
def update_user(
    user_id: uuid.UUID,
    body: UpdateUserRequest,
    request: Request,
    ctx: AuthContext = Depends(_require_users_write),
    db: DbSession = Depends(get_db),
) -> UserOut:
    changes = body.model_dump(exclude_unset=True)
    if not changes:
        raise ApiError(
            422,
            "validation_error",
            "Informe ao menos um campo.",
            details=[{"field": "body", "type": "empty"}],
        )
    user = visible_user(db, ctx, user_id, lock=True)
    if "tenant_id" in changes and ctx.user.tenant_id is not None:
        # Quem tem escopo não move usuário entre escopos.
        raise ApiError(403, "permission_denied", "A operação não é permitida.")
    now = utcnow()
    for field, value in changes.items():
        setattr(user, field, value)
    user.updated_at = now
    audit_user(db, request, "user.updated", ctx, user, now, details={"fields": sorted(changes)})
    db.commit()
    db.refresh(user)
    return user_out(user, role_names(db, [user.id])[user.id])


# --- papéis e permissões (leitura) -------------------------------------------------------


@router.get(
    "/roles", response_model=RoleList, dependencies=[Depends(allow_query("limit", "cursor"))]
)
def list_roles(
    _ctx: AuthContext = Depends(_require_roles_read),
    db: DbSession = Depends(get_db),
    limit: int = Depends(pagination.limit_param),
    cursor: str | None = Query(default=None, max_length=512),
) -> RoleList:
    position = pagination.decode(cursor, 1)
    query = select(Role).order_by(Role.name).limit(limit + 1)
    if position is not None:
        query = query.where(Role.name > position[0])
    rows = list(db.scalars(query))
    page, more = rows[:limit], len(rows) > limit
    perms: dict[uuid.UUID, list[str]] = {r.id: [] for r in page}
    if page:
        for role_id, name in db.execute(
            select(RolePermission.role_id, Permission.name)
            .join(Permission, Permission.id == RolePermission.permission_id)
            .where(RolePermission.role_id.in_(perms))
            .order_by(Permission.name)
        ):
            perms[role_id].append(name)
    return RoleList(
        items=[
            RoleOut(
                id=r.id,
                name=r.name,
                description=r.description,
                is_system=r.is_system,
                permissions=perms[r.id],
            )
            for r in page
        ],
        next_cursor=pagination.encode([page[-1].name]) if more else None,
    )


@router.get(
    "/permissions",
    response_model=PermissionList,
    dependencies=[Depends(allow_query("limit", "cursor"))],
)
def list_permissions(
    _ctx: AuthContext = Depends(_require_roles_manage),
    db: DbSession = Depends(get_db),
    limit: int = Depends(pagination.limit_param),
    cursor: str | None = Query(default=None, max_length=512),
) -> PermissionList:
    position = pagination.decode(cursor, 1)
    query = select(Permission).order_by(Permission.name).limit(limit + 1)
    if position is not None:
        query = query.where(Permission.name > position[0])
    rows = list(db.scalars(query))
    page, more = rows[:limit], len(rows) > limit
    return PermissionList(
        items=[PermissionOut(name=p.name, description=p.description) for p in page],
        next_cursor=pagination.encode([page[-1].name]) if more else None,
    )
