"""Fábrica da aplicação FastAPI do Core."""

from fastapi import FastAPI

from app.api.health import router as health_router
from app.core.config import Settings


def create_app(settings: Settings | None = None) -> FastAPI:
    # Configuração é carregada aqui e não em import, para que os testes
    # possam criar a aplicação com valores próprios.
    app = FastAPI(
        title="ARES Core",
        version="0.1.0",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    app.state.settings = settings or Settings()
    app.include_router(health_router)
    return app


app = create_app()
