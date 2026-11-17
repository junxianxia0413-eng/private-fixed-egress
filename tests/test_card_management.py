# ruff: noqa: F811
import json
import time

import pytest

from controller.services import exits, groups, isps, subscriptions
from controller.services.database import connect
from gateways.ssh import GatewayError
from tests.test_controller import csrf, login
from tests.test_exits import group_data  # noqa: F401
from tests.test_gateways import client, data, settings  # noqa: F401
from tests.test_groups import subscription_data  # noqa: F401
from tests.test_isps import isp_data  # noqa: F401


def test_card_order_persists_on_all_pages_and_rejects_stale_lists(
    client, settings, subscription_data, group_data
):
    exits.register(settings, {**group_data, "name": "Second exit"}, "admin")
    groups.register(settings, subscription_data, "admin")
    groups.register(
        settings, {**subscription_data, "device_name": ["Third"], "device_id": [""]}, "admin"
    )
    login(client)
    for page, key, order in (
        ("exits", "groups", [2, 1]),
        ("devices", "devices", [3, 2, 1]),
        ("groups", "groups", [2, 1]),
    ):
        token = csrf(client.get("/" + page))
        endpoint = f"/api/cards/{page}/order"
        assert client.post(endpoint, data={"order": json.dumps(order)}).status_code == 403
        assert (
            client.post(
                endpoint,
                data={"csrf": token, "order": json.dumps(order[:-1])},
            ).status_code
            == 409
        )
        assert (
            client.post(
                endpoint,
                data={"csrf": token, "order": json.dumps(order)},
            ).status_code
            == 200
        )
        assert [v["id"] for v in client.get(f"/api/{page}").json()[key]] == order
        html = client.get("/" + page).text
        assert html.index(f'data-card-id="{order[0]}"') < html.index(f'data-card-id="{order[1]}"')


def test_device_delete_detaches_membership_but_keeps_subscription(
    client, settings, subscription_data
):
    identifier = groups.register(settings, subscription_data, "admin")
    subscriptions.activate(settings, identifier, "admin")
    link = subscriptions.link(settings, identifier)
    login(client)
    token = csrf(client.get("/devices"))
    assert client.post("/devices/1/delete", data={"csrf": token}).status_code == 303
    assert [d["id"] for d in groups.snapshot(settings)[0]["devices"]] == [2]
    assert client.post("/devices/2/delete", data={"csrf": token}).status_code == 303
    groups.update(settings, identifier, {"name": "No device"}, "admin")
    assert groups.snapshot(settings)[0]["devices"] == []
    assert subscriptions.link(settings, identifier) == link


def test_duplicate_group_display_names_render_without_changing_the_link(
    settings, subscription_data
):
    first = groups.register(settings, subscription_data, "admin")
    second = groups.register(
        settings,
        {**subscription_data, "name": "Different", "device_name": ["Third"], "device_id": [""]},
        "admin",
    )
    subscriptions.activate(settings, first, "admin")
    link = subscriptions.link(settings, first)
    with connect(settings.database_path) as db:
        db.execute("UPDATE subscription_groups SET state='READY',deployed_exit_id=exit_id")
        db.execute("UPDATE exit_groups SET status='UNKNOWN'")
    groups.update(
        settings, second, {"name": subscription_data["name"], "device_name": ["Third"]}, "admin"
    )
    assert [g["name"] for g in groups.snapshot(settings)] == [subscription_data["name"]] * 2
    assert subscriptions.link(settings, first) == link


def test_exit_edits_are_verified_and_delete_clears_only_unused_route(
    settings, subscription_data, group_data, isp_data, monkeypatch
):
    group = groups.register(settings, subscription_data, "admin")
    identifier = int(subscription_data["exit_id"])
    replacement = isps.register(
        settings,
        {**isp_data, "name": "NEW", "host": "8.8.4.4", "expected_exit_ip": "8.8.4.4"},
        "admin",
    )
    with connect(settings.database_path) as db:
        db.execute(
            """UPDATE isp_exits SET status='HEALTHY',current_exit_ip=expected_exit_ip,
            tested_at=? WHERE id=?""",
            (int(time.time()), replacement),
        )
        db.execute("UPDATE exit_groups SET current_exit_ip='1.1.1.1'")
    form = {**group_data, "isp_id": str(replacement), "exit_type": "ISP_PROXY"}

    def apply(settings, gateway, routes, transaction, stage):
        assert routes[0]["expected_ip"] == "8.8.4.4"
        raise GatewayError("Validation failed")

    monkeypatch.setattr(exits, "apply_remote", apply)
    exits.edit(settings, identifier, form, "admin")
    assert exits.run_next(settings)
    assert exits.snapshot(settings)[0][0]["current_exit_ip"] == "1.1.1.1"
    assert exits.snapshot(settings)[0][0]["expected_exit_ip"] == "1.1.1.1"
    with pytest.raises(ValueError, match="仍被订阅组"):
        exits.delete(settings, identifier, "admin")

    def succeed(settings, gateway, routes, transaction, stage):
        return {
            value["id"]: {"exit_ip": value["expected_ip"], "latency_ms": 12} for value in routes
        }, "a" * 64

    monkeypatch.setattr(exits, "apply_remote", succeed)
    exits.edit(settings, identifier, form, "admin")
    assert exits.run_next(settings)
    assert groups.snapshot(settings)[0]["expected_exit_ip"] == "8.8.4.4"
    groups.delete(settings, group, "admin")
    exits.delete(settings, identifier, "admin")
    with connect(settings.database_path) as db:
        with pytest.raises(ValueError, match="正在删除"):
            groups.available_exit(db, identifier)
    assert exits.run_next(settings)
    assert not exits.snapshot(settings)[0]
    assert len(isps.snapshot(settings)[0]) == 2
    assert exits.register(settings, form, "admin")
