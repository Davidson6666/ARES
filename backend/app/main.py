"""Fábrica da aplicação FastAPI do Core."""

from fastapi import FastAPI
from sqlalchemy import Engine

from app.admin.users import router as admin_users_router
from app.agents.router import router as agents_router
from app.api.health import router as health_router
from app.audit.router import router as audit_router
from app.auth.mfa_router import router as mfa_router
from app.auth.router import router as auth_router
from app.core.body_limit import BodyLimitMiddleware
from app.core.config import Settings
from app.core.database import build_engine, make_session_factory
from app.core.errors import register_exception_handlers
from app.core.logging import configure_logging
from app.core.rate_limit import SlidingWindowLimiter
from app.core.request_id import request_id_middleware
from app.events.bus import PostgresEventBus
from app.events.envelope import MAX_BODY_BYTES
from app.ingress.router import router as ingress_router


def create_app(settings: Settings | None = None, engine: Engine | None = None) -> FastAPI:
    # Configuração é carregada aqui e não em import, para que os testes
    # possam criar a aplicação com valores próprios. ``engine`` permite aos
    # testes injetar um engine que roda como ares_app (SET ROLE).
    settings = settings or Settings()
    configure_logging(settings.log_level)
    app = FastAPI(
        title="ARES Core",
        version="0.1.0",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    app.state.settings = settings
    # Engine é preguiçoso: não conecta aqui. Sem URL, /ready responde 503.
    if engine is None and settings.database_url is not None:
        engine = build_engine(settings.database_url.get_secret_value())
    app.state.engine = engine
    app.state.session_factory = make_session_factory(engine) if engine else None
    app.state.login_limiter = SlidingWindowLimiter(
        limit=settings.login_rate_limit_per_minute, window_seconds=60
    )
    app.state.mfa_limiter = SlidingWindowLimiter(
        limit=settings.login_rate_limit_per_minute, window_seconds=60
    )
    app.state.event_bus = PostgresEventBus()
    app.state.agent_auth_fail_limiter = SlidingWindowLimiter(
        limit=settings.agent_auth_failures_per_minute, window_seconds=60
    )
    app.state.enroll_limiter = SlidingWindowLimiter(
        limit=settings.enroll_rate_limit_per_minute, window_seconds=60
    )
    app.state.agent_request_limiter = SlidingWindowLimiter(
        limit=settings.agent_requests_per_minute, window_seconds=60
    )
    app.state.agent_event_limiter = SlidingWindowLimiter(
        limit=settings.agent_events_per_minute, window_seconds=60
    )
    app.state.recovery_limiter = SlidingWindowLimiter(
        limit=settings.recovery_rate_limit_per_minute, window_seconds=60
    )
    # Adicionado ANTES do request_id: fica por dentro dele, e a resposta 413
    # já sai com o request_id da requisição.
    app.add_middleware(
        BodyLimitMiddleware,
        default_limit=settings.max_body_bytes,
        path_limits={"/api/v1/events": MAX_BODY_BYTES},
    )
    app.middleware("http")(request_id_middleware)
    register_exception_handlers(app)
    app.include_router(health_router)
    app.include_router(auth_router)
    app.include_router(mfa_router)
    app.include_router(agents_router)
    app.include_router(ingress_router)
    app.include_router(audit_router)
    app.include_router(admin_users_router)
    return app


app = create_app()
