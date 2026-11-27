"""Cliente HTTPS do Core (ADR 0006 e 0007).

O agente só envia: enrolamento, heartbeat e lotes de eventos. A resposta do servidor
é NÃO CONFIÁVEL: lida só nos campos conhecidos, com tamanho e prazo totais máximos, e
qualquer formato inesperado vira falha transitória, nunca exceção que derrube o
processo. A credencial vai no cabeçalho ``Authorization`` e nunca em log ou mensagem de
erro. Não segue redirecionamento (a credencial não pode ir para outro endereço) e não
herda proxy nem CA do ambiente (``trust_env=False``).
"""

import hashlib
import json
import ssl
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx

from ares_agent import __version__, ids

MAX_RESPONSE_BYTES = 256 * 1024
RESPONSE_DEADLINE_SECONDS = 30.0  # prazo TOTAL para ler uma resposta
_RETRYABLE = {408, 500, 502, 503, 504}
_DROP_BATCH = {400, 409, 413, 422}
_OUTCOMES = {"accepted", "duplicate", "rejected"}
API = "/api/v1"


class Unauthorized(Exception):
    """401: credencial inválida ou revogada. O agente para; não repete."""


class RetryLater(Exception):
    """Falha transitória: manter os eventos e tentar de novo."""

    def __init__(self, reason: str, delay: int | None = None) -> None:
        super().__init__(reason)
        self.reason = reason
        self.delay = delay


class BatchRefused(Exception):
    """400, 409, 413 ou 422 no lote inteiro: defeito do agente; o lote é descartado."""

    def __init__(self, status: int, code: str) -> None:
        super().__init__(f"{status} {code}")
        self.status = status
        self.code = code


class EnrollmentError(Exception):
    """Enrolamento recusado; a mensagem é segura para exibir."""


@dataclass(frozen=True)
class Enrolled:
    agent_id: str
    module: str
    credential: str


@dataclass(frozen=True)
class EventResult:
    event_id: str | None
    outcome: str
    error_code: str | None


def batch_key(event_ids: list[str]) -> str:
    """``Idempotency-Key`` do lote: o mesmo conjunto de eventos repete a mesma chave."""
    return "ev-" + hashlib.sha256("|".join(event_ids).encode()).hexdigest()[:40]


def encode_batch(events: list[dict[str, Any]]) -> bytes:
    """Corpo determinístico: o reenvio do mesmo lote é idêntico byte a byte."""
    return json.dumps({"events": events}, sort_keys=True, separators=(",", ":")).encode()


def tls_context(ca_file: Path | None) -> ssl.SSLContext:
    """Contexto TLS com verificação de certificado e de nome do servidor sempre ligadas.

    Sem ``ca_file``, usa a cadeia de CAs do sistema; com ele, a CA local indicada.
    """
    return ssl.create_default_context(cafile=str(ca_file) if ca_file else None)


def build_http(base_url: str, ca_file: Path | None) -> httpx.Client:
    return httpx.Client(
        base_url=base_url,
        verify=tls_context(ca_file),
        timeout=httpx.Timeout(20.0, connect=5.0),
        follow_redirects=False,
        trust_env=False,  # sem proxy, sem SSL_CERT_FILE e sem .netrc do ambiente
        headers={"User-Agent": f"ares-agent/{__version__}"},
    )


def safe_code(value: object) -> str | None:
    """Código de erro do servidor só se for um identificador curto; senão ``None``."""
    if isinstance(value, str) and value.isascii() and value.isidentifier() and len(value) <= 64:
        return value
    return None


def load_json(body: bytes) -> Any:
    """``json.loads`` que não deixa nada escapar (JSON muito aninhado levanta RecursionError)."""
    try:
        return json.loads(body)
    except ValueError, RecursionError:
        return None


class ServerClient:
    def __init__(self, http: httpx.Client, credential: str | None = None) -> None:
        self._http = http
        self._credential = credential

    def close(self) -> None:
        self._http.close()

    # --- transporte ------------------------------------------------------------

    def _send(
        self, path: str, *, content: bytes | None = None, headers: dict[str, str] | None = None
    ) -> tuple[int, httpx.Headers, bytes]:
        merged = dict(headers or {})
        if self._credential is not None:
            merged["Authorization"] = f"Agent {self._credential}"
        if content is not None:
            merged["Content-Type"] = "application/json"
        body = bytearray()
        deadline = time.monotonic() + RESPONSE_DEADLINE_SECONDS
        try:
            with self._http.stream("POST", path, content=content, headers=merged) as response:
                for chunk in response.iter_bytes():
                    body.extend(chunk)
                    if len(body) > MAX_RESPONSE_BYTES:
                        raise RetryLater("response_too_large")
                    if time.monotonic() > deadline:
                        raise RetryLater("response_too_slow")
                return response.status_code, response.headers, bytes(body)
        except httpx.HTTPError, httpx.InvalidURL, OSError:
            raise RetryLater("network") from None

    @staticmethod
    def _error_code(body: bytes) -> str:
        data = load_json(body)
        code = data.get("code") if isinstance(data, dict) else None
        return safe_code(code) or "unknown"

    @staticmethod
    def _retry_after(headers: httpx.Headers) -> int | None:
        value = headers.get("retry-after", "").strip()
        if not ids.is_ascii_number(value, max_digits=6):
            return None
        return min(max(int(value), 1), 3600)

    def _raise_for_status(self, status: int, headers: httpx.Headers, body: bytes) -> None:
        if status == 401:
            raise Unauthorized
        if status == 429:
            raise RetryLater("rate_limited", self._retry_after(headers))
        if status in _RETRYABLE:
            raise RetryLater(f"status_{status}", self._retry_after(headers))
        if status in _DROP_BATCH:
            raise BatchRefused(status, self._error_code(body))
        raise RetryLater(f"unexpected_status_{status}")

    # --- operações ---------------------------------------------------------------

    def enroll(self, token: str, host_id: str) -> Enrolled:
        payload = json.dumps({"enrollment_token": token, "host_id": host_id}).encode()
        try:
            status, headers, body = self._send(f"{API}/agents/enroll", content=payload)
        except RetryLater:
            raise EnrollmentError("Não foi possível falar com o servidor.") from None
        if status == 401:
            raise EnrollmentError("Token de enrolamento inválido ou expirado.")
        if status == 409:
            raise EnrollmentError("O termo de autorização do agente não está vigente.")
        if status == 429:
            wait = self._retry_after(headers)
            raise EnrollmentError(f"Muitas tentativas; tente de novo em {wait or 60} s.")
        if status != 201:
            raise EnrollmentError(f"Resposta inesperada do servidor ({status}).")
        return self._parse_enrolled(body)

    @staticmethod
    def _parse_enrolled(body: bytes) -> Enrolled:
        data = load_json(body)
        if not isinstance(data, dict):
            raise EnrollmentError("Resposta de enrolamento inválida.")
        agent_id = data.get("agent_id")
        module = data.get("module")
        credential = data.get("credential")
        if (
            not isinstance(agent_id, str)
            or not isinstance(module, str)
            or not isinstance(credential, str)
            or ids.MODULE.fullmatch(module) is None
            # A credencial embute o agent_id: um servidor não pode dizer outro.
            or ids.agent_id_from_credential(credential) != agent_id.lower()
        ):
            raise EnrollmentError("Resposta de enrolamento inválida.")
        return Enrolled(agent_id.lower(), module, credential)

    def heartbeat(self) -> None:
        status, headers, body = self._send(f"{API}/agents/heartbeat")
        if status != 204:
            self._raise_for_status(status, headers, body)

    def post_events(self, events: list[dict[str, Any]]) -> list[EventResult]:
        event_ids = [str(e["event_id"]) for e in events]
        status, headers, body = self._send(
            f"{API}/events",
            content=encode_batch(events),
            headers={"Idempotency-Key": batch_key(event_ids)},
        )
        if status != 202:
            self._raise_for_status(status, headers, body)
        return self._parse_results(body, event_ids)

    @staticmethod
    def _parse_results(body: bytes, event_ids: list[str]) -> list[EventResult]:
        data = load_json(body)
        raw = data.get("results") if isinstance(data, dict) else None
        if not isinstance(raw, list) or len(raw) != len(event_ids):
            raise RetryLater("invalid_response")
        results: list[EventResult] = []
        # Os resultados vêm na ordem do lote enviado.
        for sent_id, item in zip(event_ids, raw, strict=True):
            if not isinstance(item, dict):
                raise RetryLater("invalid_response")
            outcome, echoed = item.get("outcome"), item.get("event_id")
            if outcome not in _OUTCOMES or echoed not in (None, sent_id):
                raise RetryLater("invalid_response")
            results.append(EventResult(echoed, str(outcome), safe_code(item.get("error_code"))))
        return results
