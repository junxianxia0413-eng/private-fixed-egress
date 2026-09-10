# ruff: noqa: F811
import time

import pytest

from controller.services import devices, exits, groups, isps
from controller.services.database import connect
from tests.test_controller import csrf, login
from tests.test_exits import group_data  # noqa: F401
from tests.test_gateways import client, data, settings  # noqa: F401
from tests.test_isps import isp_data  # noqa: F401


@pytest.fixture
def subscription_data(settings, group_data):
    identifier = exits.register(settings, group_data, "admin")
    with connect(settings.database_path) as db:
        db.execute("UPDATE exit_groups SET applied=1")
    one = devices.save(settings, {"name": "Phone-01", "platform": "iOS"}, "admin")
    two = devices.save(settings, {"name": "Phone-02", "platform": "iOS"}, "admin")
    return {
        "name": "GROUP-01",
        "exit_id": str(identifier),
        "device_one": str(one),
        "device_two": str(two),
    }


def test_exactly_two_devices_and_no_duplicate_membership(settings, subscription_data):
    with pytest.raises(ValueError):
        groups.register(
            settings, {**subscription_data, "device_two": subscription_data["device_one"]}, "admin"
        )
    groups.register(settings, subscription_data, "admin")
    with pytest.raises(ValueError):
        groups.register(settings, {**subscription_data, "name": "GROUP-02"}, "admin")
    rows = groups.snapshot(settings)
    assert len(rows) == 1 and len(rows[0]["devices"]) == 2


def test_change_requires_one_time_confirmation_and_records_old_new_isp(
    settings, subscription_data, isp_data
):
    identifier = groups.register(settings, subscription_data, "admin")
    isp_id = isps.register(
        settings, {**isp_data, "name": "ISP-02", "expected_exit_ip": "8.8.4.4"}, "admin"
    )
    with connect(settings.database_path) as db:
        db.execute(
            "UPDATE isp_exits SET status='HEALTHY',tested_at=?,"
            "current_exit_ip='8.8.4.4' WHERE id=?",
            (int(time.time()), isp_id),
        )
    exit_id = exits.register(
        settings,
        {"name": "EXIT-02", "gateway_id": isp_data["gateway_id"], "isp_id": str(isp_id)},
        "admin",
    )
    with connect(settings.database_path) as db:
        db.execute("UPDATE exit_groups SET applied=1")
    prepared = groups.prepare_change(settings, identifier, str(exit_id), "admin")
    assert groups.snapshot(settings)[0]["exit_id"] == int(subscription_data["exit_id"])
    with pytest.raises(ValueError):
        groups.confirm_change(settings, identifier, "bad-token", "admin")
    groups.confirm_change(settings, identifier, prepared["token"], "admin")
    assert groups.snapshot(settings)[0]["exit_id"] == exit_id
    with pytest.raises(ValueError):
        groups.confirm_change(settings, identifier, prepared["token"], "admin")
    with connect(settings.database_path) as db:
        detail = db.execute(
            "SELECT detail FROM audit_events WHERE action='group.binding.confirmed'"
        ).fetchone()[0]
        assert "1.1.1.1" in detail and "8.8.4.4" in detail


def test_group_pages_authentication_and_csrf(client, subscription_data):
    assert client.get("/groups").status_code == 303
    assert client.get("/api/groups").status_code == 401
    login(client)
    assert client.post("/groups/add", data=subscription_data).status_code == 403
    token = csrf(client.get("/groups"))
    assert client.post("/groups/add", data={**subscription_data, "csrf": token}).status_code == 303
    assert "Phone-02" in client.get("/groups").text
    assert (
        client.post(
            "/groups/1/confirm", data={"csrf": token, "confirmation": "invalid"}
        ).status_code
        == 400
    )
