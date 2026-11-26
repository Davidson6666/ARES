import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app.core.config import Settings
from app.main import create_app


@pytest.fixture
def client() -> TestClient:
    return TestClient(create_app(Settings(env="test")))


def test_health_ok(client: TestClient) -> None:
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_health_does_not_expose_settings(client: TestClient) -> None:
    body = client.get("/health").text
    assert "env" not in body
    assert "database" not in body


def test_ready_ok(client: TestClient) -> None:
    response = client.get("/ready")
    assert response.status_code == 200
    assert response.json() == {"status": "ready"}


def test_docs_disabled(client: TestClient) -> None:
    assert client.get("/docs").status_code == 404
    assert client.get("/openapi.json").status_code == 404


def test_settings_rejects_unknown_env_value(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ARES_ENV", "homolog")
    with pytest.raises(ValidationError):
        Settings()


def test_settings_secret_not_in_repr(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ARES_DATABASE_URL", "postgresql://user:senha-secreta@localhost/ares")
    assert "senha-secreta" not in repr(Settings())
