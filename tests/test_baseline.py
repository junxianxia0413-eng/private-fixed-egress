from fastapi.testclient import TestClient

from controller.config import Settings
from controller.main import create_app


def test_controller_database_is_available(tmp_path):
    settings = Settings(
        database_path=tmp_path / "test.db", public_url="http://testserver", environment="test"
    )
    with TestClient(create_app(settings)) as client:
        response = client.get("/healthz")
        assert response.status_code == 200
        assert response.json() == {"status": "ok", "component": "controller"}
