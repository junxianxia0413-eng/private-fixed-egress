# ruff: noqa: F811
import base64
import hashlib
import json
import time
from urllib.parse import urlsplit

import pytest

from controller.services import devices, exits, gateways, groups, isps, subscriptions
from controller.services.database import connect
from controller.services.gateway_migration import configuration_signature, migrate, retire_source
from controller.services.secrets import SecretStore
from tests.test_gateways import data, settings  # noqa: F401


@pytest.fixture
def migration_case(settings, data):  # noqa: F811
    source = gateways.register(settings, data, "admin")
    target = gateways.register(settings, {**data, "name": "HK", "host": "8.8.4.4"}, "admin")
    with connect(settings.database_path) as db:
        db.execute("UPDATE gateways SET bootstrap_ref=NULL,status='HEALTHY'")
    store = SecretStore(settings.secret_directory)
    expected = []
    for index, ip in enumerate(("1.1.1.1", "1.0.0.1", "9.9.9.9", "8.8.8.8", "8.8.4.4")):
        isp = isps.register(
            settings,
            {
                "name": f"ISP-{index}",
                "host": ip,
                "port": "443",
                "gateway_id": str(source),
                "username": "test",
                "password": "TEST-ONLY",
                "expected_exit_ip": ip,
            },
            "admin",
        )
        with connect(settings.database_path) as db:
            db.execute(
                "UPDATE isp_exits SET status='HEALTHY',current_exit_ip=?,tested_at=? WHERE id=?",
                (ip, int(time.time()), isp),
            )
        route = exits.register(
            settings,
            {
                "name": f"ROUTE-{index}",
                "gateway_id": str(source),
                "isp_id": str(isp),
            },
            "admin",
        )
        with connect(settings.database_path) as db:
            db.execute(
                "UPDATE exit_groups SET applied=1,status='HEALTHY',current_exit_ip=?,"
                "checked_at=? WHERE id=?",
                (ip, int(time.time()), route),
            )
        devices.save(settings, {"name": f"PHONE-{index}", "platform": "iOS"}, "admin")
        identifier = groups.register(
            settings,
            {
                "name": f"GROUP-{index}",
                "exit_id": str(route),
                "device_name": [f"PHONE-{index}"],
                "device_id": [""],
            },
            "admin",
        )
        subscriptions.activate(settings, identifier, "admin")
        with connect(settings.database_path) as db:
            db.execute("UPDATE exit_jobs SET state='SUCCEEDED'")
            db.execute("UPDATE subscription_groups SET state='READY',deployed_exit_id=exit_id")
            group = db.execute(
                "SELECT * FROM subscription_groups WHERE id=?", (identifier,)
            ).fetchone()
            members = [
                dict(r)
                for r in db.execute(
                    "SELECT d.id,d.name FROM devices d JOIN group_devices m ON d.id=m.device_id "
                    "WHERE m.group_id=? ORDER BY m.slot",
                    (identifier,),
                )
            ]
        url = subscriptions.link(settings, identifier)
        expected.append(
            {
                "id": identifier,
                "display_name": group["display_name"],
                "expected_exit_ip": ip,
                "gateway_id": source,
                "devices": members,
                "subscription_sha256": hashlib.sha256(url.encode()).hexdigest(),
                "qr_sha256": hashlib.sha256(subscriptions.qr_data(url).encode()).hexdigest(),
                "client_credentials_sha256": hashlib.sha256(
                    json.dumps(store.get(group["client_ref"]), sort_keys=True).encode()
                ).hexdigest(),
            }
        )
    return source, target, expected[:4], expected[4]


def remote_success(settings, gateway, topology, transaction, stage):
    return {g["id"]: {"exit_ip": g["expected_ip"], "latency_ms": 10} for g in topology}, "a" * 64


def test_four_routes_move_atomically_and_keep_existing_subscription_formats(
    settings,
    migration_case,
    monkeypatch,  # noqa: F811
):
    source, target, expected, untouched = migration_case
    with connect(settings.database_path) as db:
        before = [dict(r) for r in db.execute("SELECT * FROM subscription_groups ORDER BY id")]
        devices_before = [
            dict(r) for r in db.execute("SELECT * FROM group_devices ORDER BY device_id")
        ]
        other_route = dict(
            db.execute("SELECT * FROM exit_groups WHERE id=?", (untouched["id"],)).fetchone()
        )
    monkeypatch.setattr(exits, "apply_remote", remote_success)
    monkeypatch.setattr(
        "controller.services.gateway_migration.deployment.inspect", lambda *args: {"healthy": True}
    )
    result = migrate(settings, expected, target, "admin", lambda stage: None)
    assert result["ok"]
    for item in expected:
        url = subscriptions.link(settings, item["id"])
        assert hashlib.sha256(url.encode()).hexdigest() == item["subscription_sha256"]
        assert hashlib.sha256(subscriptions.qr_data(url).encode()).hexdigest() == item["qr_sha256"]
        token = url.rsplit("/", 1)[1]
        nodes = base64.b64decode(subscriptions.payload(settings, token)).decode().splitlines()
        assert {urlsplit(node).hostname for node in nodes} == {"8.8.4.4"}
        assert "8.8.4.4" in subscriptions.payload(settings, token, "clash")
    with connect(settings.database_path) as db:
        assert [
            dict(r) for r in db.execute("SELECT * FROM subscription_groups ORDER BY id")
        ] == before
        assert [
            dict(r) for r in db.execute("SELECT * FROM group_devices ORDER BY device_id")
        ] == devices_before
        assert (
            dict(db.execute("SELECT * FROM exit_groups WHERE id=?", (untouched["id"],)).fetchone())
            == other_route
        )
        assert (
            db.execute("SELECT COUNT(*) FROM exit_groups WHERE gateway_id=?", (target,)).fetchone()[
                0
            ]
            == 4
        )
    monkeypatch.setattr(
        "controller.services.gateway_migration.deployment.inspect",
        lambda *args: pytest.fail("Source HTTPS can be offline during Controller maintenance"),
    )
    retired = retire_source(settings, expected, target, "admin", lambda stage: None)
    assert retired["gateway_id"] == source
    assert len(retired["retired_routes"]) == 4
    monkeypatch.setattr(
        exits, "apply_remote", lambda *args: pytest.fail("Repeated migration reapplied target")
    )
    assert migrate(settings, expected, target, "admin", lambda stage: None)["already_migrated"]


def test_wrong_exit_does_not_move_any_binding(settings, migration_case, monkeypatch):  # noqa: F811
    source, target, expected, _ = migration_case
    with connect(settings.database_path) as db:
        before = configuration_signature(db)

    def wrong(*args):
        values, digest = remote_success(*args)
        values[next(iter(values))]["exit_ip"] = "4.2.2.2"
        return values, digest

    monkeypatch.setattr(exits, "apply_remote", wrong)
    with pytest.raises(ValueError, match="实际出口"):
        migrate(settings, expected, target, "admin", lambda stage: None)
    with connect(settings.database_path) as db:
        assert configuration_signature(db) == before
        assert (
            db.execute("SELECT COUNT(*) FROM exit_groups WHERE gateway_id=?", (source,)).fetchone()[
                0
            ]
            == 5
        )


def test_concurrent_name_edit_is_preserved_and_migration_aborts(
    settings,
    migration_case,
    monkeypatch,  # noqa: F811
):
    source, target, expected, _ = migration_case

    def concurrent(*args):
        with connect(settings.database_path) as db:
            db.execute(
                "UPDATE subscription_groups SET display_name='Edited' WHERE id=?",
                (expected[0]["id"],),
            )
        return remote_success(*args)

    monkeypatch.setattr(exits, "apply_remote", concurrent)
    monkeypatch.setattr(
        "controller.services.gateway_migration.deployment.inspect", lambda *args: {"healthy": True}
    )
    with pytest.raises(ValueError, match="配置发生变化"):
        migrate(settings, expected, target, "admin", lambda stage: None)
    with connect(settings.database_path) as db:
        assert (
            db.execute(
                "SELECT display_name FROM subscription_groups WHERE id=?", (expected[0]["id"],)
            ).fetchone()[0]
            == "Edited"
        )
        assert (
            db.execute("SELECT COUNT(*) FROM exit_groups WHERE gateway_id=?", (source,)).fetchone()[
                0
            ]
            == 5
        )


def test_unselected_group_sharing_route_is_protected(settings, migration_case):  # noqa: F811
    _, target, expected, _ = migration_case
    groups.register(
        settings,
        {
            "name": "SHARED",
            "exit_id": str(expected[0]["id"]),
            "device_name": ["EXTRA"],
            "device_id": [""],
        },
        "admin",
    )
    with pytest.raises(ValueError, match="其他订阅组"):
        migrate(settings, expected, target, "admin", lambda stage: None)
