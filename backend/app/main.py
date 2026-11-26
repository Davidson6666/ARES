"""Fábrica da aplicação FastAPI do Core."""

from fastapi import FastAPI

from app.api.health import router as health_router
from app.core.config import Settings
from app.core.database import build_engine, make_session_factory
from app.core.errors import register_exception_handlers
from app.core.request_id import request_id_middleware


def create_app(settings: Settings | None = None) -> FastAPI:
    # Configuração é carregada aqui e não em import, para que os testes
    # possam criar a aplicação com valores próprios.
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
    engine = (
        build_engine(settings.database_url.get_secret_value()) if settings.database_url else None
    )
    app.state.engine = engine
    app.state.session_factory = make_session_factory(engine) if engine else None
    app.middleware("http")(request_id_middleware)
    register_exception_handlers(app)
    app.include_router(health_router)
    return app


app = create_app()
