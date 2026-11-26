"""Fábrica da aplicação FastAPI do Core."""

from fastapi import FastAPI
from sqlalchemy import Engine

from app.api.health import router as health_router
from app.auth.router import router as auth_router
from app.core.config import Settings
from app.core.database import build_engine, make_session_factory
from app.core.errors import register_exception_handlers
from app.core.rate_limit import SlidingWindowLimiter
from app.core.request_id import request_id_middleware


def create_app(settings: Settings | None = None, engine: Engine | None = None) -> FastAPI:
    # Configuração é carregada aqui e não em import, para que os testes
    # possam criar a aplicação com valores próprios. ``engine`` permite aos
    # testes injetar um engine que roda como ares_app (SET ROLE).
    settings = settings or Settings()
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
    app.middleware("http")(request_id_middleware)
    register_exception_handlers(app)
    app.include_router(health_router)
    app.include_router(auth_router)
    return app


app = create_app()
