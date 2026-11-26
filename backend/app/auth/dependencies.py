"""Dependências FastAPI de autenticação, CSRF e autorização.

A autorização é sempre feita aqui, no backend (CLAUDE.md, seção 9.1).
"""

from collections.abc import Callable, Iterator
from datetime import UTC, datetime

from fastapi import Depends, Request
from sqlalchemy.orm import Session as DbSession

from app.auth import service
from app.auth.service import AuthContext
from app.core.config import Settings
from app.core.errors import ApiError

# Prefixo __Host-: o navegador exige Secure, Path=/ e proíbe Domain.
SESSION_COOKIE = "__Host-ares_session"
CSRF_HEADER = "X-CSRF-Token"
_MUTATING = {"POST", "PUT", "PATCH", "DELETE"}


def utcnow() -> datetime:
    return datetime.now(UTC)


def get_settings(request: Request) -> Settings:
    settings: Settings = request.app.state.settings
    return settings


def get_db(request: Request) -> Iterator[DbSession]:
    factory = request.app.state.session_factory
    if factory is None:
        raise ApiError(503, "dependency_unavailable", "O serviço ainda não está pronto.")
    with factory() as db:
        yield db


def require_json(request: Request) -> None:
    """Complemento 3.4: Content-Type errado é 400."""
    media_type = request.headers.get("content-type", "").split(";")[0].strip().lower()
    if media_type != "application/json":
        raise ApiError(400, "unsupported_content_type", "Use Content-Type: application/json.")


def require_session(
    request: Request,
    db: DbSession = Depends(get_db),
    settings: Settings = Depends(get_settings),
) -> AuthContext:
    token = request.cookies.get(SESSION_COOKIE)
    ctx = service.resolve_session(db, settings, token, utcnow()) if token else None
    if ctx is None:
        raise ApiError(401, "unauthenticated", "Autenticação necessária.")
    # Operações mutáveis autenticadas por cookie exigem o token CSRF.
    if request.method in _MUTATING and not service.csrf_matches(
        ctx.token, request.headers.get(CSRF_HEADER)
    ):
        raise ApiError(403, "csrf_failed", "Token CSRF ausente ou inválido.")
    return ctx


def require_permission(permission: str) -> Callable[..., AuthContext]:
    def dependency(
        ctx: AuthContext = Depends(require_session), db: DbSession = Depends(get_db)
    ) -> AuthContext:
        _, perms = service.roles_and_permissions(db, ctx.user.id)
        if permission not in perms:
            raise ApiError(403, "permission_denied", "A operação não é permitida.")
        return ctx

    return dependency


def allow_query(*names: str) -> Callable[[Request], None]:
    """Complemento 3.4: parâmetro de query desconhecido é 400."""
    allowed = set(names)

    def dependency(request: Request) -> None:
        unknown = set(request.query_params) - allowed
        if unknown:
            raise ApiError(400, "unknown_query_parameter", "Parâmetro de consulta não suportado.")

    return dependency
