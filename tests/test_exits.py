# ruff: noqa: F811
import json
import time
from unittest.mock import MagicMock

import pytest

from controller.services import exits, isps
from controller.services.database import connect
from gateways.configuration import render, validate
from gateways.ssh import GatewayError
from tests.test_controller import csrf, login
from tests.test_gateways import client, data, settings  # noqa: F401
from tests.test_isps import isp_data  # noqa: F401


@pytest.fixture
def group_data(settings, isp_data):
    identifier = isps.register(settings, {**isp_data, "expected_exit_ip": "1.1.1.1"}, "admin")
    with connect(settings.database_path) as db:
        db.execute("UPDATE gateways SET bootstrap_ref=NULL")
        db.execute(
            "UPDATE isp_exits SET status='HEALTHY',current_exit_ip='1.1.1.1',tested_at=?",
            (int(time.time()),),
        )
    return {"name": "EXIT-01", "gateway_id": isp_data["gateway_id"], "isp_id": str(identifier)}


def test_exit_forms_authentication_csrf_and_no_secrets(client, settings, group_data, isp_data):
    assert client.get("/exits").status_code == 303
    assert client.get("/api/exits").status_code == 401
    assert client.post("/exits/add", data=group_data).status_code == 401
    login(client)
    assert client.post("/exits/add", data=group_data).status_code == 403
    token = csrf(client.get("/exits"))
    assert client.post("/exits/add", data={**group_data, "csrf": token}).status_code == 303
    assert client.post("/exits/1/apply", data={"csrf": token}).status_code == 400
    for url in ("/exits", "/api/exits"):
        assert isp_data["password"] not in client.get(url).text
    with connect(settings.database_path) as db:
        assert db.execute("SELECT COUNT(*) FROM exit_jobs").fetchone()[0] == 1


def test_old_or_abnormal_isp_cannot_create_exit(settings, group_data):
    with connect(settings.database_path) as db:
        db.execute("UPDATE isp_exits SET tested_at=1")
    before = set(settings.secret_directory.iterdir())
    with pytest.raises(ValueError):
        exits.register(settings, group_data, "admin")
    assert before == set(settings.secret_directory.iterdir())


def test_exit_apply_success_and_ambiguous_failure(settings, group_data, monkeypatch):
    identifier = exits.register(settings, group_data, "admin")

    def success(settings, gateway, groups, transaction, stage):
        assert groups[0]["expected_ip"] == "1.1.1.1"
        return {identifier: {"exit_ip": "1.1.1.1", "latency_ms": 140}}, "a" * 64

    monkeypatch.setattr(exits, "apply_remote", success)
    exits.enqueue(settings, identifier, "admin")
    assert exits.run_next(settings)
    row = exits.snapshot(settings)[0][0]
    assert row["status"] == "HEALTHY" and row["current_exit_ip"] == "1.1.1.1"

    def broken(*args):
        raise RuntimeError("SECRET-UPSTREAM-PASSWORD")

    monkeypatch.setattr(exits, "apply_remote", broken)
    exits.enqueue(settings, identifier, "admin")
    exits.run_next(settings)
    rows, jobs = exits.snapshot(settings)
    assert rows[0]["status"] == "CONFIG_FAILED" and jobs[0]["state"] == "FAILED"
    assert "SECRET-UPSTREAM-PASSWORD" not in json.dumps([rows, jobs])


def test_remote_mismatched_exit_never_commits(settings, group_data, monkeypatch):
    identifier = exits.register(settings, group_data, "admin")
    gateway, groups = exits.desired(
        settings, {"gateway_id": int(group_data["gateway_id"]), "group_id": identifier}
    )
    monkeypatch.setattr(exits, "connect_gateway", lambda *a: MagicMock())
    calls = []

    def execute(*args, **kwargs):
        calls.append(args[1])
        return json.dumps(
            {
                "ok": True,
                "transaction": "a" * 32,
                "results": [{"id": identifier, "exit_ip": "8.8.4.4", "latency_ms": 4}],
            }
        )

    monkeypatch.setattr(exits, "execute", execute)
    with pytest.raises(GatewayError, match="不匹配"):
        exits.apply_remote(settings, gateway, groups, "a" * 32, lambda _: None)
    assert len(calls) == 1 and "apply-config" in calls[0]


def test_interrupted_jobs_never_stay_healthy(settings, group_data):
    identifier = exits.register(settings, group_data, "admin")
    exits.enqueue(settings, identifier, "admin")
    with connect(settings.database_path) as db:
        db.execute("UPDATE exit_jobs SET state='RUNNING'")
        exits.recover(db)
    rows, jobs = exits.snapshot(settings)
    assert rows[0]["status"] == "UNKNOWN" and jobs[0]["state"] == "FAILED"


@pytest.fixture
def topology():
    return [
        {
            "id": 1,
            "enabled": True,
            "server": "8.8.8.8",
            "port": 443,
            "username": "user",
            "password": "test-only",
            "expected_ip": "1.1.1.1",
            "probe_username": "pfem",
            "probe_password": "A" * 40,
        }
    ]


def test_renderer_only_allows_selected_isp_and_rejects_everything_else(topology):
    config, firewall = render(topology, 995)
    assert all(o["type"] == "socks" for o in config["outbounds"])
    assert config["route"]["rules"][-1] == {"action": "reject"}
    assert config["inbounds"][1]["listen"] == "127.0.0.1"
    assert "ip daddr 8.8.8.8 tcp dport 443 accept" in firewall
    assert "ip6 daddr != ::1 reject" in firewall and "flush ruleset" not in firewall
    topology[0]["enabled"] = False
    config, firewall = render(topology, 995)
    assert config["outbounds"] == [] and "tcp dport 443 accept" not in firewall
    assert config["route"]["rules"][1]["action"] == "reject"


@pytest.mark.parametrize(
    "change",
    [
        {"server": "127.0.0.1"},
        {"server": "8.8.8.8; accept"},
        {"id": True},
        {"port": 65536},
        {"expected_ip": "10.1.1.1"},
        {"probe_password": "weak"},
    ],
)
def test_renderer_rejects_unsafe_structured_inputs(topology, change):
    topology[0].update(change)
    with pytest.raises(ValueError):
        validate(topology)
