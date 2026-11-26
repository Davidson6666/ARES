from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import BaseModel, ConfigDict

from app.core.config import Settings
from app.main import create_app


class _Payload(BaseModel):
    model_config = ConfigDict(extra="forbid")
    n: int


def _app() -> FastAPI:
    app = create_app(Settings(_env_file=None, env="test"))

    # Rotas só de teste, para exercitar os handlers.
    @app.get("/_boom")
    def boom() -> None:
        raise RuntimeError("detalhe-interno-secreto")

    @app.post("/_echo")
    def echo(payload: _Payload) -> dict[str, int]:
        return {"n": payload.n}

    return app


client = TestClient(_app(), raise_server_exceptions=False)


def _assert_standard(response_json: dict[str, object], header_id: str, code: str) -> None:
    assert response_json["code"] == code
    assert isinstance(response_json["message"], str)
    assert response_json["request_id"] == header_id
    assert "detail" not in response_json


def test_unknown_route_is_404_standard() -> None:
    r = client.get("/nao-existe")
    assert r.status_code == 404
    _assert_standard(r.json(), r.headers["X-Request-ID"], "not_found")


def test_wrong_method_is_405_standard() -> None:
    r = client.post("/health")
    assert r.status_code == 405
    _assert_standard(r.json(), r.headers["X-Request-ID"], "method_not_allowed")


def test_unhandled_exception_is_500_generic() -> None:
    r = client.get("/_boom")
    assert r.status_code == 500
    _assert_standard(r.json(), r.headers["X-Request-ID"], "internal_error")
    assert "detalhe-interno-secreto" not in r.text
    assert "RuntimeError" not in r.text


def test_malformed_json_is_400() -> None:
    r = client.post("/_echo", content=b"{nao e json", headers={"Content-Type": "application/json"})
    assert r.status_code == 400
    _assert_standard(r.json(), r.headers["X-Request-ID"], "malformed_request")


def test_schema_failure_is_422_without_echoing_input() -> None:
    r = client.post("/_echo", json={"n": "valor-enviado-xyz"})
    assert r.status_code == 422
    body = r.json()
    _assert_standard(body, r.headers["X-Request-ID"], "validation_error")
    assert body["details"] == [{"field": "body.n", "type": "int_parsing"}]
    assert "valor-enviado-xyz" not in r.text


def test_extra_field_is_422() -> None:
    r = client.post("/_echo", json={"n": 1, "roles": ["admin"]})
    assert r.status_code == 422
    assert {"field": "body.roles", "type": "extra_forbidden"} in r.json()["details"]
