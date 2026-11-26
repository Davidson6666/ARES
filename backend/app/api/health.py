"""Endpoints de saúde (complemento e v1.1, seção 14.10).

- ``/health``: o processo está vivo. Sem detalhes internos.
- ``/ready``: o Core pode receber tráfego. Hoje só confirma a configuração;
  a verificação do banco entra no item 3 da fase 01a.
"""

from typing import Literal

from fastapi import APIRouter
from pydantic import BaseModel

router = APIRouter()


class StatusResponse(BaseModel):
    status: Literal["ok", "ready"]


@router.get("/health", response_model=StatusResponse)
def health() -> StatusResponse:
    return StatusResponse(status="ok")


@router.get("/ready", response_model=StatusResponse)
def ready() -> StatusResponse:
    return StatusResponse(status="ready")
