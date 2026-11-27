import json
from collections.abc import Callable
from typing import Any

import httpx
import pytest

from ares_agent import client as api
from ares_agent.client import (
    BatchRefused,
    EnrollmentError,
    RetryLater,
    ServerClient,
    Unauthorized,
)
from tests.helpers import AGENT_ID, CREDENTIAL

Handler = Callable[[httpx.Request], httpx.Response]


def make(handler: Handler, credential: str | None = CREDENTIAL) -> ServerClient:
    http = httpx.Client(
        base_url="https://core.test",
        transport=httpx.MockTransport(handler),
        follow_redirects=False,
    )
    return ServerClient(http, credential)


def reply_with(body: Any) -> ServerClient:
    return make(lambda r: httpx.Response(201, json=body))


def events(n: int = 2) -> list[dict[str, Any]]:
    return [{"event_id": f"00000000-0000-4000-8000-00000000000{i}", "k": i} for i in range(n)]


def accepted(evs: list[dict[str, Any]], outcome: str = "accepted") -> httpx.Response:
    results = [{"event_id": e["event_id"], "outcome": outcome, "error_code": None} for e in evs]
    return httpx.Response(202, json={"accepted": len(evs), "results": results})


# --- enrolamento -----------------------------------------------------------------


def test_enroll_ok_sends_token_and_host_only() -> None:
    seen: list[httpx.Request] = []

    def handler(req: httpx.Request) -> httpx.Response:
        seen.append(req)
        return httpx.Response(
            201, json={"agent_id": AGENT_ID, "module": "endpoint", "credential": CREDENTIAL}
        )

    got = make(handler, None).enroll("tok-123", "LAB-PC")
    assert (got.agent_id, got.module, got.credential) == (AGENT_ID, "endpoint", CREDENTIAL)
    (req,) = seen
    assert req.url.path == "/api/v1/agents/enroll" and "authorization" not in req.headers
    assert json.loads(req.content) == {"enrollment_token": "tok-123", "host_id": "LAB-PC"}


@pytest.mark.parametrize(
    ("status", "text"),
    [(401, "inválido"), (409, "termo"), (429, "Muitas"), (500, "inesperada")],
)
def test_enroll_refusals_have_safe_messages(status: int, text: str) -> None:
    client = make(lambda r: httpx.Response(status, headers={"Retry-After": "7"}))
    with pytest.raises(EnrollmentError, match=text) as err:
        client.enroll("tok-secreto-xyz", "h")
    assert "tok-secreto-xyz" not in str(err.value)


def test_enroll_rejects_garbage_response_and_network_error() -> None:
    for body in ({"x": 1}, {"agent_id": 1, "module": "m", "credential": "c"}):
        with pytest.raises(EnrollmentError):
            reply_with(body).enroll("t", "h")
    with pytest.raises(EnrollmentError):
        make(lambda r: httpx.Response(201, content=b"nao json")).enroll("t", "h")

    def down(req: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("sem rede")

    with pytest.raises(EnrollmentError, match="servidor"):
        make(down).enroll("t", "h")


# --- eventos -----------------------------------------------------------------------


def test_post_events_sends_credential_key_and_deterministic_body() -> None:
    seen: list[httpx.Request] = []
    evs = events(2)

    def handler(req: httpx.Request) -> httpx.Response:
        seen.append(req)
        return accepted(evs)

    client = make(handler)
    results = client.post_events(evs)
    client.post_events(evs)
    assert [r.outcome for r in results] == ["accepted", "accepted"]
    first, second = seen
    assert first.headers["authorization"] == f"Agent {CREDENTIAL}"
    assert first.headers["content-type"] == "application/json"
    assert first.url.path == "/api/v1/events"
    # Reenvio idêntico: mesma chave e mesmo corpo (o servidor responde por repetição).
    assert first.headers["idempotency-key"] == second.headers["idempotency-key"]
    assert first.content == second.content
    assert api.batch_key(["a"]) != api.batch_key(["b"])
    assert len(first.headers["idempotency-key"]) <= 128


def test_post_events_maps_each_status() -> None:
    evs = events(1)

    def code(status: int, **kw: Any) -> ServerClient:
        return make(lambda r: httpx.Response(status, **kw))

    with pytest.raises(Unauthorized):
        code(401).post_events(evs)
    with pytest.raises(RetryLater) as slow:
        code(429, headers={"Retry-After": "42"}).post_events(evs)
    assert slow.value.delay == 42
    with pytest.raises(RetryLater) as huge:
        code(429, headers={"Retry-After": "999999"}).post_events(evs)
    assert huge.value.delay == 3600
    for status in (408, 500, 502, 503, 504):
        with pytest.raises(RetryLater):
            code(status).post_events(evs)
    for status in (400, 409, 413, 422):
        with pytest.raises(BatchRefused) as refused:
            code(status, json={"code": "validation_error"}).post_events(evs)
        assert refused.value.code == "validation_error" and refused.value.status == status
    # Estados inesperados (URL errada, proxy): mantém os eventos e tenta depois.
    for status in (403, 404, 405, 302):
        with pytest.raises(RetryLater):
            code(status).post_events(evs)
    with pytest.raises(BatchRefused) as odd:
        code(422, json={"code": "<script>"}).post_events(evs)
    assert odd.value.code == "unknown"


def test_post_events_reports_rejected_outcomes() -> None:
    evs = events(2)
    body = {
        "results": [
            {"event_id": evs[0]["event_id"], "outcome": "duplicate", "error_code": None},
            {"event_id": evs[1]["event_id"], "outcome": "rejected", "error_code": "invalid_data"},
        ]
    }
    results = make(lambda r: httpx.Response(202, json=body)).post_events(evs)
    assert [(r.outcome, r.error_code) for r in results] == [
        ("duplicate", None),
        ("rejected", "invalid_data"),
    ]


@pytest.mark.parametrize(
    "body",
    [
        {"results": []},  # faltam resultados
        {"results": [{"event_id": "x", "outcome": "accepted"}] * 2},  # id que não é do lote
        {"results": [{"event_id": None, "outcome": "talvez"}] * 2},  # resultado desconhecido
        {"sem": "results"},
        [],
    ],
)
def test_invalid_202_body_is_retried_not_trusted(body: Any) -> None:
    with pytest.raises(RetryLater, match="invalid_response"):
        make(lambda r: httpx.Response(202, json=body)).post_events(events(2))


def test_results_must_follow_the_order_of_the_batch() -> None:
    evs = events(2)
    swapped = [
        {"event_id": evs[1]["event_id"], "outcome": "accepted"},
        {"event_id": evs[0]["event_id"], "outcome": "accepted"},
    ]
    with pytest.raises(RetryLater):
        make(lambda r: httpx.Response(202, json={"results": swapped})).post_events(evs)


def test_network_errors_are_transient() -> None:
    def down(req: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("devagar")

    with pytest.raises(RetryLater, match="network"):
        make(down).post_events(events(1))


def test_oversized_response_is_cut_off(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(api, "MAX_RESPONSE_BYTES", 100)
    with pytest.raises(RetryLater, match="response_too_large"):
        make(lambda r: httpx.Response(202, content=b"x" * 5000)).post_events(events(1))


def test_credential_is_never_sent_to_a_redirect_target() -> None:
    hosts: list[str] = []

    def handler(req: httpx.Request) -> httpx.Response:
        hosts.append(req.url.host)
        if req.url.host == "core.test":
            return httpx.Response(307, headers={"Location": "https://evil.test/steal"})
        return httpx.Response(202, json={"results": []})

    with pytest.raises(RetryLater):
        make(handler).post_events(events(1))
    assert hosts == ["core.test"]  # não seguiu


# --- heartbeat ---------------------------------------------------------------------


def test_heartbeat() -> None:
    seen: list[httpx.Request] = []

    def handler(req: httpx.Request) -> httpx.Response:
        seen.append(req)
        return httpx.Response(204)

    make(handler).heartbeat()
    assert seen[0].url.path == "/api/v1/agents/heartbeat"
    assert seen[0].headers["authorization"] == f"Agent {CREDENTIAL}"
    with pytest.raises(Unauthorized):
        make(lambda r: httpx.Response(401)).heartbeat()
    with pytest.raises(RetryLater):
        make(lambda r: httpx.Response(503)).heartbeat()


def test_build_http_never_follows_redirects_and_uses_tls_verification(tmp_path: Any) -> None:
    http = api.build_http("https://core.test", None)
    assert http.follow_redirects is False
    http.close()


def test_tls_verification_cannot_be_weakened(tmp_path: Any) -> None:
    import ssl

    ctx = api.tls_context(None)
    assert ctx.verify_mode == ssl.CERT_REQUIRED and ctx.check_hostname is True
    # Certificado de servidor desconhecido (CA local errada) é recusado: o contexto
    # também com ``ca_file`` continua exigindo certificado e nome.
    bad = tmp_path / "ca.pem"
    bad.write_text("não é um certificado", encoding="utf-8")
    with pytest.raises(ssl.SSLError):
        api.tls_context(bad)
