# ruff: noqa: F811
import json
import sqlite3
from unittest.mock import MagicMock

import pytest

from controller.services import isps
from controller.services.database import connect
from controller.services.gateways import register as register_gateway
from gateways import remote_probe
from gateways.ssh import GatewayError
from tests.test_controller import csrf, login
from tests.test_gateways import client, data, settings  # noqa: F401


@pytest.fixture
def isp_data(settings, data):  # noqa: F811
    gateway = register_gateway(settings, data, "admin")
    return {
        "name": "ISP-01",
        "host": "8.8.8.8",
        "port": "443",
        "username": "test-user",
        "password": "TEST-ONLY-ISP-PASSWORD",
        "gateway_id": str(gateway),
    }


def test_first_success_freezes_identity_and_drift_is_critical(settings, isp_data, monkeypatch):  # noqa: F811
    identifier = isps.register(settings, isp_data, "admin")
    monkeypatch.setattr(isps, "probe", lambda *a: {"exit_ip": "1.1.1.1", "latency_ms": 123})
    isps.enqueue(settings, identifier, "admin")
    assert isps.run_next(settings)
    first = isps.snapshot(settings)[0][0]
    assert first["expected_exit_ip"] == first["current_exit_ip"] == "1.1.1.1"
    assert first["status"] == "HEALTHY"
    monkeypatch.setattr(isps, "probe", lambda *a: {"exit_ip": "8.8.4.4", "latency_ms": 124})
    isps.enqueue(settings, identifier, "admin")
    isps.run_next(settings)
    second = isps.snapshot(settings)[0][0]
    assert second["expected_exit_ip"] == "1.1.1.1"
    assert second["current_exit_ip"] == "8.8.4.4"
    assert second["status"] == "CRITICAL" and "EXIT IP CHANGED" in second["last_error"]
    with connect(settings.database_path) as db:
        with pytest.raises(sqlite3.IntegrityError, match="immutable"):
            db.execute("UPDATE isp_exits SET expected_exit_ip='8.8.4.4'")
        with pytest.raises(sqlite3.IntegrityError, match="immutable"):
            db.execute("UPDATE isp_exits SET expected_exit_ip=NULL")
        assert db.execute("SELECT COUNT(*) FROM isp_checks").fetchone()[0] == 2


def test_auth_failure_preserves_identity_and_never_leaks_secrets(settings, isp_data, monkeypatch):  # noqa: F811
    identifier = isps.register(settings, {**isp_data, "expected_exit_ip": "1.1.1.1"}, "admin")

    def failure(*_):
        raise RuntimeError(isp_data["password"])

    monkeypatch.setattr(isps, "probe", failure)
    isps.enqueue(settings, identifier, "admin")
    isps.run_next(settings)
    values, checks = isps.snapshot(settings)
    assert values[0]["status"] == "CRITICAL" and values[0]["expected_exit_ip"] == "1.1.1.1"
    assert values[0]["current_exit_ip"] is None
    assert isp_data["password"] not in json.dumps([values, checks])
    with connect(settings.database_path) as db:
        assert isp_data["password"] not in "\n".join(db.iterdump())


def test_isp_forms_require_auth_csrf_and_queue_tests(client, settings, isp_data):  # noqa: F811
    assert client.get("/isps").status_code == 303
    assert client.get("/api/isps").status_code == 401
    assert client.post("/isps/add", data=isp_data).status_code == 401
    login(client)
    assert client.post("/isps/add", data=isp_data).status_code == 403
    token = csrf(client.get("/isps"))
    assert client.post("/isps/add", data={**isp_data, "csrf": token}).status_code == 303
    assert isp_data["password"] not in client.get("/isps").text
    assert isp_data["username"] not in client.get("/api/isps").text
    assert client.post("/isps/1/test", data={"csrf": token}).status_code == 400
    assert (
        client.post(
            "/isps/1/test", data={"csrf": token}, headers={"Origin": "https://evil.example"}
        ).status_code
        == 403
    )
    with connect(settings.database_path) as db:
        assert db.execute("SELECT COUNT(*) FROM isp_jobs").fetchone()[0] == 1


def test_minute_scheduler_does_not_duplicate_pending_or_active_jobs(
    settings, isp_data, monkeypatch
):  # noqa: F811
    identifier = isps.register(settings, isp_data, "admin")
    monkeypatch.setattr(isps, "probe", lambda *a: {"exit_ip": "1.1.1.1", "latency_ms": 123})
    isps.enqueue(settings, identifier, "admin")
    isps.run_next(settings)
    isps.schedule_due(settings)
    with connect(settings.database_path) as db:
        assert db.execute("SELECT COUNT(*) FROM isp_jobs").fetchone()[0] == 1
        db.execute("UPDATE isp_exits SET tested_at=1")
    isps.schedule_due(settings)
    isps.schedule_due(settings)
    with connect(settings.database_path) as db:
        assert db.execute("SELECT COUNT(*) FROM isp_jobs").fetchone()[0] == 2
        db.execute("UPDATE isp_jobs SET state='RUNNING' WHERE state='QUEUED'")
    isps.schedule_due(settings)
    with connect(settings.database_path) as db:
        assert db.execute("SELECT COUNT(*) FROM isp_jobs").fetchone()[0] == 2
        isps.recover(db)
    assert isps.snapshot(settings)[0][0]["status"] == "UNKNOWN"


@pytest.mark.parametrize(
    "change",
    [
        {"host": "127.0.0.1"},
        {"host": "host;id"},
        {"port": "65536"},
        {"username": ""},
        {"expires_on": "yesterday"},
        {"gateway_id": "99"},
        {"expected_exit_ip": "10.0.0.1"},
    ],
)
def test_invalid_isp_input_creates_no_secret_files(settings, isp_data, change):  # noqa: F811
    before = set(settings.secret_directory.iterdir())
    with pytest.raises(ValueError):
        isps.register(settings, {**isp_data, **change}, "admin")
    assert set(settings.secret_directory.iterdir()) == before


def test_expired_isp_cannot_be_marked_healthy(settings, isp_data, monkeypatch):  # noqa: F811
    identifier = isps.register(settings, {**isp_data, "expires_on": "2020-01-01"}, "admin")
    monkeypatch.setattr(isps, "probe", lambda *a: {"exit_ip": "1.1.1.1", "latency_ms": 123})
    isps.enqueue(settings, identifier, "admin")
    isps.run_next(settings)
    assert isps.snapshot(settings)[0][0]["status"] == "CRITICAL"


def test_probe_pins_resolved_public_address_and_rejects_private_dns(monkeypatch):
    monkeypatch.setattr(
        remote_probe.socket, "getaddrinfo", lambda *a: [(None, None, None, None, ("127.0.0.1", 0))]
    )
    with pytest.raises(remote_probe.ProbeError, match="INVALID_ENDPOINT"):
        remote_probe.endpoint("public-looking.example")


def test_proxy_must_require_and_validate_authentication(monkeypatch):
    sock = MagicMock()
    sock.recv.side_effect = [b"\x05\x00"]
    monkeypatch.setattr(remote_probe.socket, "create_connection", lambda *a, **k: sock)
    with pytest.raises(remote_probe.ProbeError, match="AUTH_METHOD_REJECTED"):
        remote_probe.open_tunnel("8.8.8.8", 443, b"user", b"password", "api.ipify.org")
    sock.sendall.assert_called_once_with(b"\x05\x01\x02")
    sock.close.assert_called_once()
    sock.reset_mock()
    sock.recv.side_effect = [b"\x05\x02", b"\x01\x01"]
    with pytest.raises(remote_probe.ProbeError, match="AUTH_FAILED"):
        remote_probe.open_tunnel("8.8.8.8", 443, b"user", b"password", "api.ipify.org")
    sock.close.assert_called_once()


def test_fragmented_socks_response_and_domain_tunnel(monkeypatch):
    sock = MagicMock()
    sock.recv.side_effect = [b"\x05", b"\x02", b"\x01\x00", b"\x05\x00\x00\x01", b"\x00" * 6]
    monkeypatch.setattr(remote_probe.socket, "create_connection", lambda *a, **k: sock)
    assert remote_probe.open_tunnel("8.8.8.8", 443, b"user", b"password", "api.ipify.org") is sock
    assert b"api.ipify.org" in sock.sendall.call_args.args[0]


def test_two_different_exit_ips_are_not_reported_stable(monkeypatch):
    monkeypatch.setattr(remote_probe, "endpoint", lambda *a: "8.8.8.8")
    values = iter([("1.1.1.1", 50), ("8.8.4.4", 60)])
    monkeypatch.setattr(remote_probe, "request_ip", lambda *a: next(values))
    result = remote_probe.probe(
        {"host": "8.8.8.8", "port": 443, "username": "user", "password": "secret"}
    )
    assert not result["ok"] and result["error"] == "UNSTABLE_EXIT"


def test_independent_identity_sources_run_concurrently(monkeypatch):
    import threading
    import time

    barrier = threading.Barrier(2)

    def request(*args):
        barrier.wait(timeout=1)
        time.sleep(0.02)
        return "1.1.1.1", 50

    monkeypatch.setattr(remote_probe, "request_ip", request)
    assert len(remote_probe.request_all({}, "8.8.8.8")) == 2


def test_remote_error_is_translated_without_diagnostic_leaks(settings, isp_data, monkeypatch):  # noqa: F811
    identifier = isps.register(settings, isp_data, "admin")
    with connect(settings.database_path) as db:
        isp = dict(db.execute("SELECT * FROM isp_exits WHERE id=?", (identifier,)).fetchone())
        gateway = dict(db.execute("SELECT * FROM gateways").fetchone())
    monkeypatch.setattr(isps, "connect_gateway", lambda *a: MagicMock())
    monkeypatch.setattr(
        isps, "execute", lambda *a, **k: json.dumps({"ok": False, "error": isp_data["password"]})
    )
    with pytest.raises(GatewayError) as exc:
        isps.probe(settings, isp, gateway)
    assert isp_data["password"] not in str(exc.value)
