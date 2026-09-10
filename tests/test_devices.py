# ruff: noqa: F811
import pytest

from controller.services import devices
from controller.services.database import connect
from tests.test_controller import csrf, login
from tests.test_gateways import client, settings  # noqa: F401


def test_device_persistence_validation_and_history(settings):
    data = {
        "name": "Phone-01",
        "platform": "iOS",
        "type": "Phone",
        "purpose": "work",
        "notes": "first",
    }
    identifier = devices.save(settings, data, "admin")
    devices.save(settings, {**data, "notes": "updated"}, "admin", identifier)
    assert devices.snapshot(settings)[0]["notes"] == "updated"
    with pytest.raises(ValueError):
        devices.save(settings, data, "admin")
    with pytest.raises(ValueError):
        devices.save(settings, {**data, "name": ""}, "admin")
    with connect(settings.database_path) as db:
        events = db.execute(
            "SELECT detail FROM audit_events WHERE action LIKE 'device.%'"
        ).fetchall()
        assert len(events) == 2 and "first" in events[1][0] and "updated" in events[1][0]


def test_device_form_authentication_csrf_and_escaping(client):
    assert client.get("/devices").status_code == 303
    assert client.get("/api/devices").status_code == 401
    data = {"name": "<script>bad</script>", "platform": "iOS"}
    assert client.post("/devices/add", data=data).status_code == 401
    login(client)
    assert client.post("/devices/add", data=data).status_code == 403
    data["csrf"] = csrf(client.get("/devices"))
    assert client.post("/devices/add", data=data).status_code == 303
    assert "<script>bad</script>" not in client.get("/devices").text
    assert "&lt;script&gt;" in client.get("/devices").text
    assert client.post("/devices/1/edit", data={**data, "name": "Phone-02"}).status_code == 303
    assert client.get("/api/devices").json()["devices"][0]["name"] == "Phone-02"
