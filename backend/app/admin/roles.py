"""Papéis, permissões, desativação e reset de MFA (ADR 0008; complemento 3.2).

Duas invariantes valem aqui e são testadas inclusive sob concorrência:

1. **Sem escalada de privilégio.** O ator só concede, retira ou atinge o que já tem:
   - criar ou alterar papel: cada permissão adicionada ou removida tem de ser do ator;
   - trocar papéis de um usuário: cada papel adicionado ou removido só pode ter
     permissões que o ator tem;
   - desativar ou resetar o MFA de alguém: o alvo não pode ter permissão que o ator
     não tem (um administrador menor não derruba um maior).
2. **Último administrador.** Nunca fica sem pelo menos um usuário ATIVO com
   ``roles.manage``. Toda operação que pode quebrar isso pega a mesma trava de
   transação (``pg_advisory_xact_lock``) ANTES de ler o estado, aplica a mudança e
   conta de novo no fim; se der zero, desfaz (409). A trava serializa duas requisições
   simultâneas que, cada uma sozinha, passariam.

Ninguém altera os próprios papéis, se desativa ou reseta o próprio MFA por aqui.
Papéis de sistema são imutáveis (aqui e por gatilho no banco, migração 0006).
"""

import re
import uuid
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import delete, func, select, text, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session as DbSession

from app.admin.users import (
    RoleOut,
    UserOut,
    audit_user,
    role_names,
    user_out,
    visible_user,
)
from app.audit import service as audit
from app.auth import mfa, service
from app.auth.dependencies import (
    allow_query,
    get_db,
    get_settings,
    require_json,
    require_permission,
    utcnow,
)
from app.auth.mfa_router import _reauthenticate
from app.auth.models import (
    MfaChallenge,
    MfaFactor,
    Permission,
    RecoveryToken,
    Role,
    RolePermission,
    User,
    UserRole,
)
from app.auth.service import AuthContext
from app.auth.session_flow import request_id
from app.core.config import Settings
from app.core.errors import ApiError

router = APIRouter(prefix="/api/v1")

# Trava de transação das mudanças que podem esvaziar o grupo de administradores.
ADMIN_LOCK_KEY = 0x41444D4E  # "ADMN"
ADMIN_PERMISSION = "roles.manage"
_ROLE_NAME = re.compile(r"^[a-z][a-z0-9_]{2,63}$")

_require_roles_manage = require_permission("roles.manage")
_require_users_write = require_permission("users.write")


def _no_control(value: str) -> str:
    if any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise ValueError("caractere de controle")
    return value


class CreateRoleRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=3, max_length=64, pattern=_ROLE_NAME.pattern)
    description: str = Field(default="", max_length=256)
    permissions: list[str] = Field(default_factory=list, max_length=64)

    _description = field_validator("description")(_no_control)


class RolePermissionsRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    permissions: list[str] = Field(max_length=64)


class UserRolesRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    roles: list[str] = Field(max_length=32)


class PasswordRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    password: str = Field(min_length=1, max_length=1024)


# --- invariantes ------------------------------------------------------------------------


def lock_admin_changes(db: DbSession) -> None:
    db.execute(text("SELECT pg_advisory_xact_lock(:k)"), {"k": ADMIN_LOCK_KEY})


def active_admins(db: DbSession) -> int:
    count = db.scalar(
        select(func.count(func.distinct(User.id)))
        .join(UserRole, UserRole.user_id == User.id)
        .join(RolePermission, RolePermission.role_id == UserRole.role_id)
        .join(Permission, Permission.id == RolePermission.permission_id)
        .where(User.status == "active", Permission.name == ADMIN_PERMISSION)
    )
    return int(count or 0)


def ensure_admin_left(db: DbSession) -> None:
    """Depois da mudança (já em ``flush``): se o grupo esvaziou, 409. Quem chama não
    faz commit, e o ``get_db`` descarta a transação."""
    db.flush()
    if active_admins(db) == 0:
        db.rollback()
        raise ApiError(
            409,
            "last_admin",
            "A operação deixaria o sistema sem administrador ativo.",
        )


def permissions_of(db: DbSession, user_id: uuid.UUID) -> set[str]:
    _, perms = service.roles_and_permissions(db, user_id)
    return set(perms)


def role_permissions(db: DbSession, role_ids: list[uuid.UUID]) -> set[str]:
    if not role_ids:
        return set()
    return set(
        db.scalars(
            select(Permission.name)
            .join(RolePermission, RolePermission.permission_id == Permission.id)
            .where(RolePermission.role_id.in_(role_ids))
        )
    )


def deny_escalation(actor_perms: set[str], wanted: set[str]) -> None:
    if not wanted <= actor_perms:
        raise ApiError(
            403,
            "privilege_escalation",
            "Não é possível conceder ou retirar permissões que você não tem.",
        )


def deny_self(ctx: AuthContext, target: User) -> None:
    if target.id == ctx.user.id:
        raise ApiError(
            403, "self_modification", "Esta operação não pode ser feita na própria conta."
        )


def deny_more_powerful_target(db: DbSession, ctx: AuthContext, target: User) -> None:
    if not permissions_of(db, target.id) <= permissions_of(db, ctx.user.id):
        raise ApiError(
            403,
            "privilege_escalation",
            "O usuário alvo tem permissões que você não tem.",
        )


def _known_permissions(db: DbSession, names: list[str]) -> dict[str, uuid.UUID]:
    wanted = set(names)
    found: dict[str, uuid.UUID] = dict(
        db.execute(select(Permission.name, Permission.id).where(Permission.name.in_(wanted))).all()
    )
    unknown = sorted(wanted - set(found))
    if unknown:
        raise ApiError(
            422,
            "unknown_permission",
            "Permissão desconhecida.",
            details=[{"field": "permissions", "type": "unknown"}],
        )
    return found


def _audit(
    db: DbSession,
    request: Request,
    ctx: AuthContext,
    action: str,
    resource_type: str,
    resource_id: str,
    now: datetime,
    details: dict[str, Any] | None = None,
) -> None:
    audit.record(
        db,
        action=action,
        result="success",
        actor_type="user",
        actor_user_id=ctx.user.id,
        resource_type=resource_type,
        resource_id=resource_id,
        request_id=request_id(request),
        details=details,
        now=now,
    )


def _role_out(db: DbSession, role: Role) -> RoleOut:
    return RoleOut(
        id=role.id,
        name=role.name,
        description=role.description,
        is_system=role.is_system,
        permissions=sorted(role_permissions(db, [role.id])),
    )


# --- papéis -------------------------------------------------------------------------------


@router.post(
    "/roles",
    status_code=201,
    response_model=RoleOut,
    dependencies=[Depends(require_json), Depends(allow_query())],
)
def create_role(
    body: CreateRoleRequest,
    request: Request,
    ctx: AuthContext = Depends(_require_roles_manage),
    db: DbSession = Depends(get_db),
) -> RoleOut:
    found = _known_permissions(db, body.permissions)
    deny_escalation(permissions_of(db, ctx.user.id), set(found))
    now = utcnow()
    role = Role(id=uuid.uuid4(), name=body.name, description=body.description)
    db.add(role)
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        raise ApiError(409, "role_exists", "Já existe um papel com este nome.") from None
    for perm_id in found.values():
        db.add(RolePermission(role_id=role.id, permission_id=perm_id))
    _audit(
        db,
        request,
        ctx,
        "role.created",
        "role",
        str(role.id),
        now,
        details={"permissions": sorted(found)},
    )
    db.commit()
    return _role_out(db, role)


@router.put(
    "/roles/{role_id}/permissions",
    response_model=RoleOut,
    dependencies=[Depends(require_json), Depends(allow_query())],
)
def set_role_permissions(
    role_id: uuid.UUID,
    body: RolePermissionsRequest,
    request: Request,
    ctx: AuthContext = Depends(_require_roles_manage),
    db: DbSession = Depends(get_db),
) -> RoleOut:
    lock_admin_changes(db)
    # Sem FOR UPDATE (exigiria UPDATE em roles, que o ares_app não tem): a trava de
    # administração acima já serializa as mudanças de permissões de papel.
    role = db.get(Role, role_id)
    if role is None:
        raise ApiError(404, "not_found", "Recurso não encontrado.")
    if role.is_system:
        raise ApiError(409, "system_role_immutable", "Papéis de sistema não podem ser alterados.")
    found = _known_permissions(db, body.permissions)
    current = role_permissions(db, [role.id])
    added, removed = set(found) - current, current - set(found)
    # Mexer numa permissão (pôr ou tirar) exige tê-la.
    deny_escalation(permissions_of(db, ctx.user.id), added | removed)
    now = utcnow()
    if removed:
        removed_ids = list(db.scalars(select(Permission.id).where(Permission.name.in_(removed))))
        db.execute(
            delete(RolePermission).where(
                RolePermission.role_id == role.id,
                RolePermission.permission_id.in_(removed_ids),
            )
        )
    for name in sorted(added):
        db.add(RolePermission(role_id=role.id, permission_id=found[name]))
    ensure_admin_left(db)
    if added or removed:
        _audit(
            db,
            request,
            ctx,
            "role.permissions_changed",
            "role",
            str(role.id),
            now,
            details={"added": sorted(added), "removed": sorted(removed)},
        )
    db.commit()
    return _role_out(db, role)


# --- usuários: papéis, desativação, MFA -----------------------------------------------


@router.put(
    "/users/{user_id}/roles",
    response_model=UserOut,
    dependencies=[Depends(require_json), Depends(allow_query())],
)
def set_user_roles(
    user_id: uuid.UUID,
    body: UserRolesRequest,
    request: Request,
    ctx: AuthContext = Depends(_require_roles_manage),
    db: DbSession = Depends(get_db),
) -> UserOut:
    lock_admin_changes(db)
    target = visible_user(db, ctx, user_id, lock=True)
    deny_self(ctx, target)
    wanted = set(body.roles)
    roles = dict(db.execute(select(Role.name, Role.id).where(Role.name.in_(wanted))).all())
    if set(roles) != wanted:
        raise ApiError(
            422,
            "unknown_role",
            "Papel desconhecido.",
            details=[{"field": "roles", "type": "unknown"}],
        )
    current = dict(
        db.execute(
            select(Role.name, Role.id)
            .join(UserRole, UserRole.role_id == Role.id)
            .where(UserRole.user_id == target.id)
        ).all()
    )
    added = {n: roles[n] for n in wanted - set(current)}
    removed = {n: current[n] for n in set(current) - wanted}
    deny_escalation(
        permissions_of(db, ctx.user.id),
        role_permissions(db, [*added.values(), *removed.values()]),
    )
    now = utcnow()
    if removed:
        db.execute(
            delete(UserRole).where(
                UserRole.user_id == target.id, UserRole.role_id.in_(list(removed.values()))
            )
        )
    for role_id in added.values():
        db.add(UserRole(user_id=target.id, role_id=role_id, granted_by=ctx.user.id, granted_at=now))
    ensure_admin_left(db)
    # Uma linha de auditoria por papel concedido ou retirado (complemento 2.1).
    for name in sorted(added):
        audit_user(db, request, "user.role_granted", ctx, target, now, details={"role": name})
    for name in sorted(removed):
        audit_user(db, request, "user.role_revoked", ctx, target, now, details={"role": name})
    db.commit()
    return user_out(target, role_names(db, [target.id])[target.id])


def _kill_access(db: DbSession, user_id: uuid.UUID, now: datetime) -> None:
    """Revoga sessões, desafios de MFA e tokens de senha pendentes do usuário."""
    mfa.revoke_all_sessions(db, user_id, now)
    db.execute(
        update(MfaChallenge)
        .where(MfaChallenge.user_id == user_id, MfaChallenge.used_at.is_(None))
        .values(used_at=now)
    )
    db.execute(
        update(RecoveryToken)
        .where(RecoveryToken.user_id == user_id, RecoveryToken.used_at.is_(None))
        .values(used_at=now)
    )


@router.post(
    "/users/{user_id}/disable",
    response_model=UserOut,
    dependencies=[Depends(allow_query())],
)
def disable_user(
    user_id: uuid.UUID,
    request: Request,
    ctx: AuthContext = Depends(_require_users_write),
    db: DbSession = Depends(get_db),
) -> UserOut:
    lock_admin_changes(db)
    target = visible_user(db, ctx, user_id, lock=True)
    deny_self(ctx, target)
    deny_more_powerful_target(db, ctx, target)
    if target.status != "disabled":
        now = utcnow()
        target.status = "disabled"
        target.updated_at = now
        _kill_access(db, target.id, now)
        ensure_admin_left(db)
        audit_user(db, request, "user.disabled", ctx, target, now)
        db.commit()
    return user_out(target, role_names(db, [target.id])[target.id])


@router.post(
    "/users/{user_id}/mfa/reset",
    response_model=UserOut,
    dependencies=[Depends(require_json), Depends(allow_query())],
)
def reset_user_mfa(
    user_id: uuid.UUID,
    body: PasswordRequest,
    request: Request,
    ctx: AuthContext = Depends(_require_users_write),
    db: DbSession = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> UserOut:
    now = utcnow()
    target = visible_user(db, ctx, user_id, lock=True)
    deny_self(ctx, target)
    deny_more_powerful_target(db, ctx, target)
    # Ação sensível: a senha do ADMINISTRADOR é conferida de novo (falha conta contra ele).
    _reauthenticate(db, request, settings, ctx.user, body.password, "user.mfa_reset", now)
    factor = db.scalar(
        select(MfaFactor)
        .where(MfaFactor.user_id == target.id, MfaFactor.status == "active")
        .with_for_update()
    )
    if factor is None:
        raise ApiError(409, "mfa_not_enrolled", "Este usuário não tem MFA ativo.")
    factor.status = "revoked"
    factor.revoked_at = now
    _kill_access(db, target.id, now)
    audit_user(db, request, "user.mfa_reset", ctx, target, now)
    db.commit()
    return user_out(target, role_names(db, [target.id])[target.id])
