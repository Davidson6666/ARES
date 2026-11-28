"""Gera um ``request_id`` por requisição e registra a requisição no log
(v1.1, seções 14.3 e 14.8).

O identificador é sempre gerado pelo servidor; um ``X-Request-ID`` enviado
pelo cliente é ignorado, para não permitir valores forjados nos logs.
O log de acesso não inclui query string nem cabeçalhos (podem conter dados
sensíveis), só método, caminho, status e duração.
"""

import time
import uuid
from collections.abc import Awaitable, Callable

import structlog
from fastapi import Request, Response

HEADER = "X-Request-ID"
_NO_STORE_PREFIXES = (
    "/api/v1/auth/",
    "/api/v1/agents",
    "/api/v1/events",
    "/api/v1/users",
    "/api/v1/roles",
    "/api/v1/permissions",
)
log = structlog.get_logger("ares.access")


async def request_id_middleware(
    request: Request, call_next: Callable[[Request], Awaitable[Response]]
) -> Response:
    request_id = str(uuid.uuid4())
    request.state.request_id = request_id
    structlog.contextvars.clear_contextvars()
    structlog.contextvars.bind_contextvars(request_id=request_id)
    started = time.perf_counter()
    try:
        response = await call_next(request)
    except Exception:
        log.info(
            "request",
            method=request.method,
            path=request.url.path,
            status=500,
            duration_ms=round((time.perf_counter() - started) * 1000, 1),
        )
        raise
    response.headers[HEADER] = request_id
    response.headers["X-Content-Type-Options"] = "nosniff"
    if request.url.path.startswith(_NO_STORE_PREFIXES):
        # Autenticação carrega token CSRF e segredos; agentes carregam credenciais
        # e tokens; eventos podem trazer dado pessoal ou sensível.
        response.headers["Cache-Control"] = "no-store"
    log.info(
        "request",
        method=request.method,
        path=request.url.path,
        status=response.status_code,
        duration_ms=round((time.perf_counter() - started) * 1000, 1),
    )
    return response
