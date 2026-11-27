"""Corpo de erro padrão da API (complemento, seção 3.4).

Campos no topo do JSON (formato plano; ver CLAUDE.md, seção 4.3):
``code`` (snake_case, estável), ``message`` (segura para exibir),
``details`` (opcional, sem valores enviados pelo cliente) e ``request_id``.

Todo erro passa por aqui, inclusive 404/405 do roteador, falhas de
validação e exceções não tratadas, para que nenhum caminho devolva o formato
padrão do FastAPI (``{"detail": ...}``) nem detalhes internos.
"""

from collections.abc import Mapping
from typing import Any

import structlog
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from sqlalchemy.exc import DBAPIError, OperationalError
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.auth.crypto import MfaCryptoError
from app.core.request_id import HEADER as REQUEST_ID_HEADER

logger = structlog.get_logger("ares.errors")

_HTTP_CODES: dict[int, tuple[str, str]] = {
    400: ("bad_request", "A requisição não pôde ser interpretada."),
    401: ("unauthenticated", "Autenticação necessária."),
    403: ("permission_denied", "A operação não é permitida."),
    404: ("not_found", "Recurso não encontrado."),
    405: ("method_not_allowed", "Método não permitido para este recurso."),
    409: ("conflict", "Conflito com o estado atual do recurso."),
    413: ("payload_too_large", "Corpo da requisição acima do limite."),
    429: ("rate_limited", "Limite de requisições excedido."),
    503: ("dependency_unavailable", "O serviço ainda não está pronto."),
}


class ApiError(Exception):
    """Erro de negócio com código estável. Use em vez de HTTPException quando
    o ``code`` precisa ser específico (ex.: ``invalid_credentials``)."""

    def __init__(
        self,
        status_code: int,
        code: str,
        message: str,
        headers: Mapping[str, str] | None = None,
        details: list[dict[str, Any]] | None = None,
    ) -> None:
        super().__init__(code)
        self.status_code = status_code
        self.code = code
        self.message = message
        self.headers = headers
        self.details = details


def error_response(
    request: Request,
    status_code: int,
    code: str,
    message: str,
    details: list[dict[str, Any]] | None = None,
    headers: Mapping[str, str] | None = None,
) -> JSONResponse:
    request_id = getattr(request.state, "request_id", None)
    body: dict[str, Any] = {"code": code, "message": message, "request_id": request_id}
    if details:
        body["details"] = details
    response = JSONResponse(status_code=status_code, content=body, headers=headers)
    if request_id:
        response.headers[REQUEST_ID_HEADER] = request_id
    return response


async def _http_exception(request: Request, exc: Exception) -> JSONResponse:
    assert isinstance(exc, StarletteHTTPException)
    code, message = _HTTP_CODES.get(exc.status_code, ("http_error", "Erro na requisição."))
    # exc.detail não é repassado: pode conter texto interno.
    return error_response(request, exc.status_code, code, message, headers=exc.headers)


async def _validation_exception(request: Request, exc: Exception) -> JSONResponse:
    assert isinstance(exc, RequestValidationError)
    errors = exc.errors()
    # Complemento 3.4: JSON malformado é 400; JSON válido fora do esquema é 422.
    if any(e.get("type") == "json_invalid" for e in errors):
        return error_response(request, 400, "malformed_request", _HTTP_CODES[400][1])
    # Só localização e tipo do erro; nunca o valor enviado ("input").
    details = [
        {"field": ".".join(str(p) for p in e.get("loc", ())), "type": str(e.get("type"))}
        for e in errors
    ]
    return error_response(
        request, 422, "validation_error", "Dados fora do formato esperado.", details=details
    )


async def _unhandled_exception(request: Request, exc: Exception) -> JSONResponse:
    # Detalhe só no log do servidor; resposta genérica (v1.1, seção 14.9).
    logger.exception("erro não tratado")
    return error_response(request, 500, "internal_error", "Erro interno.")


async def _api_error(request: Request, exc: Exception) -> JSONResponse:
    assert isinstance(exc, ApiError)
    return error_response(
        request, exc.status_code, exc.code, exc.message, details=exc.details, headers=exc.headers
    )


async def _database_unavailable(request: Request, exc: Exception) -> JSONResponse:
    # Complemento 3.4: dependência essencial indisponível é 503.
    # OperationalError cobre conexão recusada, queda e timeout. Outros erros
    # do driver (ex.: violação de constraint) continuam 500.
    if isinstance(exc, OperationalError) or (
        isinstance(exc, DBAPIError) and exc.connection_invalidated
    ):
        logger.warning("banco indisponível", **_db_error_fields(exc))
        code, message = _HTTP_CODES[503]
        return error_response(request, 503, code, message, headers={"Retry-After": "5"})
    # Sem traceback nem mensagem: a mensagem do PostgreSQL pode conter o valor
    # enviado (ex.: 'invalid input syntax ... "<valor>"').
    logger.error("erro de banco", **_db_error_fields(exc))
    return error_response(request, 500, "internal_error", "Erro interno.")


def _db_error_fields(exc: Exception) -> dict[str, str | None]:
    orig = getattr(exc, "orig", None)
    return {
        "error_type": type(orig or exc).__name__,
        "sqlstate": getattr(orig, "sqlstate", None),
    }


async def _mfa_crypto_error(request: Request, exc: Exception) -> JSONResponse:
    # Chave trocada ou segredo corrompido: indisponibilidade, não erro do cliente.
    logger.error("segredo MFA não pôde ser decifrado")
    return error_response(
        request, 503, "mfa_unavailable", "MFA indisponível. Contate o administrador."
    )


def register_exception_handlers(app: FastAPI) -> None:
    app.add_exception_handler(MfaCryptoError, _mfa_crypto_error)
    app.add_exception_handler(ApiError, _api_error)
    app.add_exception_handler(DBAPIError, _database_unavailable)
    app.add_exception_handler(StarletteHTTPException, _http_exception)
    app.add_exception_handler(RequestValidationError, _validation_exception)
    app.add_exception_handler(Exception, _unhandled_exception)
