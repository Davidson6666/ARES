from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr, ValidationError

from app.core.config import Settings
from app.main import create_app


def _settings(**overrides: object) -> Settings:
    # _env_file=None: os testes não leem o .env local do desenvolvedor.
    return Settings(_env_file=None, env="test", **overrides)  # type: ignore[arg-type]  # **overrides é object


@pytest.fixture
def client() -> TestClient:
    return TestClient(create_app(_settings()))


def test_health_ok(client: TestClient) -> None:
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_health_does_not_expose_settings(client: TestClient) -> None:
    body = client.get("/health").text
    assert "env" not in body
    assert "database" not in body


def test_ready_without_database_is_503_with_standard_error(client: TestClient) -> None:
    response = client.get("/ready")
    assert response.status_code == 503
    body = response.json()
    assert body["code"] == "dependency_unavailable"
    assert body["request_id"] == response.headers["X-Request-ID"]
    assert set(body) == {"code", "message", "request_id"}


def test_ready_with_unreachable_database_is_503_without_leaking_url() -> None:
    url = "postgresql+psycopg://u:senha-secreta@127.0.0.1:1/nada"
    client = TestClient(create_app(_settings(database_url=SecretStr(url))))
    response = client.get("/ready")
    assert response.status_code == 503
    assert "senha-secreta" not in response.text
    assert "127.0.0.1" not in response.text


@pytest.mark.db
def test_ready_with_database_ok(temp_database_url: str) -> None:
    app = create_app(_settings(database_url=SecretStr(temp_database_url)))
    try:
        response = TestClient(app).get("/ready")
        assert response.status_code == 200
        assert response.json() == {"status": "ready"}
    finally:
        app.state.engine.dispose()


def test_client_request_id_is_ignored(client: TestClient) -> None:
    response = client.get("/health", headers={"X-Request-ID": "forjado\nlinha"})
    assert response.headers["X-Request-ID"] != "forjado\nlinha"


def test_docs_disabled(client: TestClient) -> None:
    assert client.get("/docs").status_code == 404
    assert client.get("/openapi.json").status_code == 404


def test_settings_rejects_unknown_env_value(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ARES_ENV", "homolog")
    with pytest.raises(ValidationError):
        Settings(_env_file=None)


def test_settings_ignores_compose_keys(tmp_path: Path) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text(
        "POSTGRES_USER=ares_admin\nPOSTGRES_PASSWORD=x\nAPP_DB_PASSWORD=y\nARES_ENV=test\n",
        encoding="utf-8",
    )
    assert Settings(_env_file=env_file).env == "test"


def test_settings_secret_not_in_repr(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ARES_DATABASE_URL", "postgresql://user:senha-secreta@localhost/ares")
    assert "senha-secreta" not in repr(Settings(_env_file=None))
