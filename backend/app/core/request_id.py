"""Gera um ``request_id`` por requisição (v1.1, seções 14.3 e 14.8).

O identificador é sempre gerado pelo servidor; um ``X-Request-ID`` enviado
pelo cliente é ignorado, para não permitir valores forjados nos logs.
"""

import uuid
from collections.abc import Awaitable, Callable

from fastapi import Request, Response

HEADER = "X-Request-ID"


async def request_id_middleware(
    request: Request, call_next: Callable[[Request], Awaitable[Response]]
) -> Response:
    request_id = str(uuid.uuid4())
    request.state.request_id = request_id
    response = await call_next(request)
    response.headers[HEADER] = request_id
    return response
