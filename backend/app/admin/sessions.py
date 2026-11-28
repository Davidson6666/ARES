"""Sessões: listar e revogar (complemento 3.2; ADR 0008).

``GET /auth/sessions`` lista as do próprio usuário; com ``user_id``, as de outro
usuário, para quem tem ``users.write`` (no próprio escopo; fora dele, 404).
``DELETE /auth/sessions/{id}``: própria sessão, ou de outro usuário com ``users.write``.
A resposta nunca traz hash de token nem de user-agent.
"""

import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, Query, Request, Response
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session as DbSession

from app.admin.roles import deny_more_powerful_target, permissions_of
from app.admin.users import audit_user, visible_user
from app.auth.dependencies import allow_query, get_db, require_session, utcnow
from app.auth.models import Session, User
from app.auth.service import AuthContext
from app.core.errors import ApiError

router = APIRouter(prefix="/api/v1")


class SessionOut(BaseModel):
    id: uuid.UUID
    created_at: datetime
    last_seen_at: datetime
    idle_expires_at: datetime
    absolute_expires_at: datetime
    current: bool


class SessionList(BaseModel):
    items: list[SessionOut]


def _owner(db: DbSession, ctx: AuthContext, user_id: uuid.UUID | None) -> User:
    """O dono das sessões consultadas: o próprio ator, ou outro com ``users.write``."""
    if user_id is None or user_id == ctx.user.id:
        return ctx.user
    if "users.write" not in permissions_of(db, ctx.user.id):
        raise ApiError(403, "permission_denied", "A operação não é permitida.")
    return visible_user(db, ctx, user_id)


@router.get(
    "/auth/sessions",
    response_model=SessionList,
    dependencies=[Depends(allow_query("user_id"))],
)
def list_sessions(
    ctx: AuthContext = Depends(require_session),
    db: DbSession = Depends(get_db),
    user_id: uuid.UUID | None = Query(default=None),
) -> SessionList:
    owner = _owner(db, ctx, user_id)
    now = utcnow()
    rows = db.scalars(
        select(Session)
        .where(
            Session.user_id == owner.id,
            Session.revoked_at.is_(None),
            Session.idle_expires_at > now,
            Session.absolute_expires_at > now,
        )
        .order_by(Session.created_at)
        .limit(200)
    )
    return SessionList(
        items=[
            SessionOut(
                id=s.id,
                created_at=s.created_at,
                last_seen_at=s.last_seen_at,
                idle_expires_at=s.idle_expires_at,
                absolute_expires_at=s.absolute_expires_at,
                current=s.id == ctx.session.id,
            )
            for s in rows
        ]
    )


@router.delete(
    "/auth/sessions/{session_id}",
    status_code=204,
    dependencies=[Depends(allow_query())],
)
def revoke_session(
    session_id: uuid.UUID,
    request: Request,
    ctx: AuthContext = Depends(require_session),
    db: DbSession = Depends(get_db),
) -> Response:
    session = db.scalar(select(Session).where(Session.id == session_id).with_for_update())
    not_found = ApiError(404, "not_found", "Recurso não encontrado.")
    if session is None:
        raise not_found
    if session.user_id != ctx.user.id:
        # De outro usuário: exige users.write, escopo e não atingir quem tem mais poder.
        # Sem users.write, 404 (não revela que a sessão existe).
        if "users.write" not in permissions_of(db, ctx.user.id):
            raise not_found
        target = visible_user(db, ctx, session.user_id)
        deny_more_powerful_target(db, ctx, target)
    else:
        target = ctx.user
    if session.revoked_at is None:
        now = utcnow()
        session.revoked_at = now
        audit_user(
            db,
            request,
            "auth.session_revoked",
            ctx,
            target,
            now,
            details={"session_id": str(session.id)},
        )
        db.commit()
    return Response(status_code=204)
