from fastapi.testclient import TestClient

from controller.main import app


def test_controller_database_is_available():
    with TestClient(app) as client:
        response = client.get("/healthz")
        assert response.status_code == 200
        assert response.json() == {"status": "ok", "component": "controller"}

