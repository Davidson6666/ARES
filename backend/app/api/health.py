"""Endpoints de saúde (v1.1, seção 14.10).

- ``/health``: o processo está vivo. Sem detalhes internos.
- ``/ready``: dependências essenciais (hoje, o banco) prontas. Em falha,
  503 com o corpo de erro padrão, sem revelar o motivo técnico.
"""

from typing import Literal

from fastapi import APIRouter, Request, Response
from pydantic import BaseModel

from app.core.database import database_is_ready
from app.core.errors import error_response

router = APIRouter()


class StatusResponse(BaseModel):
    status: Literal["ok", "ready"]


@router.get("/health", response_model=StatusResponse)
def health() -> StatusResponse:
    return StatusResponse(status="ok")


@router.get("/ready", response_model=StatusResponse)
def ready(request: Request) -> StatusResponse | Response:
    if not database_is_ready(request.app.state.engine):
        return error_response(
            request,
            status_code=503,
            code="dependency_unavailable",
            message="O serviço ainda não está pronto.",
        )
    return StatusResponse(status="ready")
