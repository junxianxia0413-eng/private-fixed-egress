import json
import os
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import MagicMock

import paramiko
import pytest
from fastapi.testclient import TestClient

from controller.config import Settings
from controller.main import create_app
from controller.models.schema import MIGRATIONS
from controller.services.auth import set_administrator
from controller.services.database import connect, migrate
from controller.services.gateways import GatewayWorker, enqueue, register, snapshot
from controller.services.secrets import SecretStore
from gateways import deployment
from gateways.ssh import GatewayError, connect_gateway, generate_key, parse_host_key
from tests.test_controller import PASSWORD, csrf, login


@pytest.fixture
def settings(tmp_path):
    result = Settings(
        database_path=tmp_path / "controller.db", public_url="http://testserver", environment="test"
    )
    migrate(result.database_path)
    set_administrator(result, "admin", PASSWORD)
    return result


@pytest.fixture
def data():
    return {
        "name": "test-gateway",
        "host": "8.8.8.8",
        "ssh_port": "22",
        "location": "Test",
        "password": "TEST-ONLY-SSH-PASSWORD",
        "host_key": generate_key()[1],
    }


@pytest.fixture
def client(settings):
    with TestClient(create_app(settings), follow_redirects=False) as result:
        yield result


def test_migration_upgrades_existing_phase1_database(tmp_path):
    path = tmp_path / "v1.db"
    with sqlite3.connect(path) as db:
        for sql in MIGRATIONS[0]:
            db.execute(sql)
        db.execute("PRAGMA user_version=1")
        db.execute("INSERT INTO administrator VALUES (1,'existing','retained',1)")
    migrate(path)
    migrate(path)
    with connect(path) as db:
        assert db.execute("SELECT username FROM administrator").fetchone()[0] == "existing"
        assert db.execute("SELECT COUNT(*) FROM gateways").fetchone()[0] == 0


def test_credentials_are_referenced_not_in_database_or_views(client, settings, data):
    login(client)
    response = client.post("/gateways/add", data={**data, "csrf": csrf(client.get("/gateways"))})
    assert response.status_code == 303
    with connect(settings.database_path) as db:
        row = dict(db.execute("SELECT * FROM gateways").fetchone())
        assert data["password"] not in "\n".join(db.iterdump())
    store = SecretStore(settings.secret_directory)
    assert store.get(row["bootstrap_ref"])["password"] == data["password"]
    for response in (client.get("/gateways"), client.get("/api/gateways")):
        assert data["password"] not in response.text
        assert row["managed_ref"] not in response.text
        assert "PRIVATE KEY" not in response.text
    if os.name == "posix":
        assert store.path(row["managed_ref"]).stat().st_mode & 0o777 == 0o600
        assert store.directory.stat().st_mode & 0o777 == 0o700
    assert client.get("/api/gateways").json()["gateways"][0]["status"] == "NEW"


def test_very_low_cpu_is_displayed_as_below_measurement_precision(client, settings, data):
    gateway = register(settings, data, "admin")
    health = {"cpu_percent": 0.0, "ram_percent": 43.2, "disk_percent": 28.5}
    with connect(settings.database_path) as db:
        db.execute(
            "UPDATE gateways SET status='HEALTHY',health_json=?,"
            "checked_at=CAST(strftime('%s','now') AS INTEGER) WHERE id=?",
            (json.dumps(health), gateway),
        )
    login(client)

    for path in ("/gateways", "/network"):
        page = client.get(path).text
        assert "&lt;1%" in page
        assert "&amp;lt;1%" not in page


def test_authentication_csrf_and_recovery_key_download(client, settings, data):
    gateway = register(settings, data, "admin")
    assert client.get("/gateways").status_code == 303
    assert client.get("/api/gateways").status_code == 401
    assert client.post(f"/gateways/{gateway}/deploy").status_code == 401
    login(client)
    assert client.post(f"/gateways/{gateway}/deploy").status_code == 403
    token = csrf(client.get("/gateways"))
    assert (
        client.post(
            "/gateways/add",
            data={**data, "csrf": token},
            headers={"Origin": "https://evil.example"},
        ).status_code
        == 403
    )
    assert client.post(f"/gateways/{gateway}/recovery-key").status_code == 403
    response = client.post(f"/gateways/{gateway}/recovery-key", data={"csrf": token})
    assert response.status_code == 200 and "PRIVATE KEY" in response.text
    assert response.headers["content-disposition"].startswith("attachment;")
    assert response.headers["cache-control"] == "no-store"


@pytest.mark.parametrize(
    "field,value",
    [
        ("host", "127.0.0.1"),
        ("host", "169.254.169.254"),
        ("host", "8.8.8.8;id"),
        ("ssh_port", "0"),
        ("ssh_port", "65536"),
        ("host_key", "invalid"),
        ("bootstrap_user", "unprivileged"),
        ("password", ""),
        ("private_key", "not-a-key"),
    ],
)
def test_invalid_registration_leaves_no_secrets(settings, data, field, value):
    data[field] = value
    with pytest.raises(ValueError):
        register(settings, data, "admin")
    assert not settings.secret_directory.exists()


def test_duplicate_registration_cleans_only_new_secrets(settings, data):
    register(settings, data, "admin")
    original = set(settings.secret_directory.iterdir())
    with pytest.raises(ValueError, match="已存在"):
        register(settings, data, "admin")
    assert set(settings.secret_directory.iterdir()) == original


def test_concurrent_submission_enqueues_only_one_job(settings, data):
    gateway = register(settings, data, "admin")

    def submit(_):
        try:
            return enqueue(settings, gateway, "deploy", "admin")
        except ValueError:
            return None

    with ThreadPoolExecutor(max_workers=4) as pool:
        assert sum(x is not None for x in pool.map(submit, range(8))) == 1
    with pytest.raises(ValueError):
        enqueue(settings, gateway, "delete", "admin")


def test_worker_records_failure_without_leaking_remote_output(settings, data, monkeypatch):
    gateway = register(settings, data, "admin")
    enqueue(settings, gateway, "deploy", "admin")

    def fail(*_):
        raise RuntimeError(data["password"])

    monkeypatch.setattr(deployment, "deploy", fail)
    assert GatewayWorker(settings).once()
    gateways, jobs = snapshot(settings)
    assert gateways[0]["status"] == "DEPLOY_FAILED"
    assert jobs[0]["state"] == "FAILED"
    assert data["password"] not in json.dumps([gateways, jobs])
    assert enqueue(settings, gateway, "deploy", "admin") == 2


def test_worker_success_retains_keys_removes_bootstrap_and_stales(settings, data, monkeypatch):
    gateway = register(settings, data, "admin")
    enqueue(settings, gateway, "deploy", "admin")
    with connect(settings.database_path) as db:
        original = dict(db.execute("SELECT * FROM gateways").fetchone())

    def success(g, store, stage):
        stage("CHECKING")
        assert store.get(g["bootstrap_ref"])["password"] == data["password"]
        return {"healthy": True, "isp_bound": False}

    monkeypatch.setattr(deployment, "deploy", success)
    worker = GatewayWorker(settings)
    assert worker.once() and not worker.once()
    gateways, jobs = snapshot(settings)
    assert gateways[0]["status"] == "HEALTHY" and jobs[0]["state"] == "SUCCEEDED"
    store = SecretStore(settings.secret_directory)
    assert store.get(original["managed_ref"])["private_key"]
    assert not store.path(original["bootstrap_ref"]).exists()
    with connect(settings.database_path) as db:
        assert db.execute("SELECT bootstrap_ref FROM gateways").fetchone()[0] is None
        db.execute("UPDATE gateways SET checked_at=1")
    assert snapshot(settings)[0][0]["status"] == "UNKNOWN"


def test_recovery_marks_interrupted_jobs_and_retains_pending(settings, data):
    first = register(settings, data, "admin")
    second = register(settings, {**data, "host": "1.1.1.1", "name": "second"}, "admin")
    enqueue(settings, first, "deploy", "admin")
    enqueue(settings, second, "deploy", "admin")
    with connect(settings.database_path) as db:
        db.execute("UPDATE gateway_jobs SET state='RUNNING' WHERE gateway_id=?", (first,))
    GatewayWorker(settings).recover()
    gateways, jobs = snapshot(settings)
    assert gateways[0]["status"] == "DEPLOY_FAILED"
    assert jobs[0]["state"] == "QUEUED" and jobs[1]["state"] == "FAILED"
    assert enqueue(settings, first, "deploy", "admin")


def test_host_key_mismatch_fails_closed(data, monkeypatch):
    client = MagicMock()
    expected = parse_host_key(data["host_key"])
    client.connect.side_effect = paramiko.BadHostKeyException(
        "8.8.8.8", parse_host_key(generate_key()[1]), expected
    )
    monkeypatch.setattr("gateways.ssh.paramiko.SSHClient", lambda: client)
    with pytest.raises(GatewayError, match="主机密钥变化"):
        connect_gateway({**data, "ssh_port": 22}, "root", {"password": data["password"]})
    client.close.assert_called_once()
    assert isinstance(client.set_missing_host_key_policy.call_args.args[0], paramiko.RejectPolicy)


def test_secret_path_traversal_is_rejected(settings):
    with pytest.raises(ValueError):
        SecretStore(settings.secret_directory).get("../controller.db")


def test_unknown_remote_actions_never_execute(monkeypatch):
    execute = MagicMock()
    monkeypatch.setattr(deployment, "execute", execute)
    with pytest.raises(ValueError):
        deployment.health(None, "status;id")
    execute.assert_not_called()


def test_unhealthy_core_and_unfinished_ssh_protection_not_healthy(monkeypatch):
    monkeypatch.setattr(deployment, "execute", lambda *a, **k: '{"healthy":false}')
    with pytest.raises(GatewayError, match="未通过"):
        deployment.health(None)
    monkeypatch.setattr(deployment, "health", lambda *a: {"ssh_key_only": False})
    monkeypatch.setattr(deployment, "connect_gateway", lambda *a: MagicMock())
    with pytest.raises(GatewayError, match="登录保护"):
        deployment.inspect({"managed_ref": "ref"}, MagicMock(), "check")
