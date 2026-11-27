"""Limite de tamanho de corpo, antes de qualquer rota (complemento 3.4: 413).

O FastAPI lê o corpo inteiro antes de resolver dependências: sem isto, um
anônimo mandaria centenas de MB a ``POST /agents/enroll`` (pública) e esgotaria a
memória. O limite vale pelo ``Content-Length`` e pelos bytes realmente lidos
(corpo em pedaços, sem Content-Length).

``/api/v1/events`` tem limite próprio (2 MB); as demais rotas, ``default_limit``.
"""

import json
from collections.abc import Awaitable, Callable, MutableMapping
from typing import Any

Scope = MutableMapping[str, Any]
Message = MutableMapping[str, Any]
Receive = Callable[[], Awaitable[Message]]
Send = Callable[[Message], Awaitable[None]]

_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


class _TooLarge(Exception):
    pass


class BodyLimitMiddleware:
    def __init__(
        self,
        app: Callable[[Scope, Receive, Send], Awaitable[None]],
        default_limit: int,
        path_limits: dict[str, int],
    ) -> None:
        self.app = app
        self.default_limit = default_limit
        self.path_limits = path_limits

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope["method"] not in _METHODS:
            await self.app(scope, receive, send)
            return
        limit = self.path_limits.get(scope["path"], self.default_limit)
        headers = {k.lower(): v for k, v in scope["headers"]}
        declared = headers.get(b"content-length", b"")
        if declared.isdigit() and int(declared) > limit:
            await self._reject(scope, send)
            return

        seen = 0
        rejected = False

        async def limited_receive() -> Message:
            nonlocal seen, rejected
            message = await receive()
            if message["type"] == "http.request" and not rejected:
                seen += len(message.get("body", b""))
                if seen > limit:
                    # O FastAPI troca qualquer exceção na leitura do corpo por 400,
                    # então o 413 é enviado AQUI, e o que a aplicação tentar
                    # responder depois é descartado.
                    rejected = True
                    await self._reject(scope, send)
                    raise _TooLarge
            return message

        async def guarded_send(message: Message) -> None:
            if not rejected:
                await send(message)

        try:
            await self.app(scope, limited_receive, guarded_send)
        except _TooLarge:
            pass  # resposta 413 já enviada

    async def _reject(self, scope: Scope, send: Send) -> None:
        state = scope.get("state") or {}
        body = json.dumps(
            {
                "code": "payload_too_large",
                "message": "Corpo da requisição acima do limite.",
                "request_id": state.get("request_id"),
            }
        ).encode()
        await send(
            {
                "type": "http.response.start",
                "status": 413,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(body)).encode()),
                    (b"connection", b"close"),
                ],
            }
        )
        await send({"type": "http.response.body", "body": body})
