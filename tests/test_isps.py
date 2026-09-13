# ruff: noqa: F811
import json
import sqlite3
from unittest.mock import MagicMock

import pytest

from controller.services import isps
from controller.services.database import connect
from controller.services.gateways import register as register_gateway
from controller.services.secrets import SecretStore
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
    pending_page = client.get("/isps")
    assert 'http-equiv="refresh" content="1"' in pending_page.text
    assert "页面会自动更新" in pending_page.text
    assert isp_data["password"] not in pending_page.text
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


def test_isp_name_can_be_edited_without_changing_identity(client, settings, isp_data):  # noqa: F811
    identifier = isps.register(settings, {**isp_data, "expected_exit_ip": "1.1.1.1"}, "admin")
    login(client)
    token = csrf(client.get("/isps"))
    assert client.post(f"/isps/{identifier}/edit", data={"csrf": token}).status_code == 400
    assert (
        client.post(
            f"/isps/{identifier}/edit",
            data={"csrf": token, "name": "东京固定出口"},
        ).status_code
        == 303
    )
    values, _ = isps.snapshot(settings)
    assert values[0]["name"] == "东京固定出口"
    assert values[0]["expected_exit_ip"] == "1.1.1.1"
    with connect(settings.database_path) as db:
        action, detail = db.execute(
            "SELECT action,detail FROM audit_events ORDER BY id DESC LIMIT 1"
        ).fetchone()
        assert action == "isp.renamed"
        assert json.loads(detail)["before"] == "ISP-01"


def test_isp_name_edit_rejects_duplicates(settings, isp_data):  # noqa: F811
    first = isps.register(settings, isp_data, "admin")
    isps.register(settings, {**isp_data, "name": "ISP-02", "host": "8.8.4.4"}, "admin")
    with pytest.raises(ValueError, match="已存在"):
        isps.rename(settings, first, "ISP-02", "admin")


def test_complete_socks5_link_is_parsed_and_credentials_stay_secret(settings, isp_data):  # noqa: F811
    identifier = isps.register(
        settings,
        {
            "name": "粘贴导入",
            "gateway_id": isp_data["gateway_id"],
            "proxy_uri": "socks5://user%2B01:p%40ssword@8.8.4.4:8443",
        },
        "admin",
    )
    with connect(settings.database_path) as db:
        row = db.execute(
            "SELECT host,port,secret_ref FROM isp_exits WHERE id=?", (identifier,)
        ).fetchone()
    assert (row["host"], row["port"]) == ("8.8.4.4", 8443)
    assert SecretStore(settings.secret_directory).get(row["secret_ref"]) == {
        "username": "user+01",
        "password": "p@ssword",
    }


def test_connection_edit_validates_then_atomically_replaces_secret(settings, isp_data, monkeypatch):  # noqa: F811
    identifier = isps.register(settings, {**isp_data, "expected_exit_ip": "1.1.1.1"}, "admin")
    with connect(settings.database_path) as db:
        before = dict(db.execute("SELECT * FROM isp_exits WHERE id=?", (identifier,)).fetchone())
    monkeypatch.setattr(
        isps,
        "probe_connection",
        lambda *_: {"exit_ip": "1.1.1.1", "latency_ms": 87.5},
    )
    isps.update_connection(
        settings,
        identifier,
        {"proxy_uri": "socks5://new-user:new-password@8.8.4.4:1080"},
        "admin",
    )
    with connect(settings.database_path) as db:
        after = dict(db.execute("SELECT * FROM isp_exits WHERE id=?", (identifier,)).fetchone())
        detail = db.execute(
            "SELECT detail FROM audit_events WHERE action='isp.connection.updated'"
        ).fetchone()[0]
    assert (after["host"], after["port"], after["current_exit_ip"]) == (
        "8.8.4.4",
        1080,
        "1.1.1.1",
    )
    assert after["secret_ref"] != before["secret_ref"]
    assert not SecretStore(settings.secret_directory).path(before["secret_ref"]).exists()
    assert "new-password" not in detail


def test_failed_connection_edit_keeps_original_connection(settings, isp_data, monkeypatch):  # noqa: F811
    identifier = isps.register(settings, {**isp_data, "expected_exit_ip": "1.1.1.1"}, "admin")
    with connect(settings.database_path) as db:
        before = dict(db.execute("SELECT * FROM isp_exits WHERE id=?", (identifier,)).fetchone())
    monkeypatch.setattr(
        isps,
        "probe_connection",
        lambda *_: {"exit_ip": "8.8.4.4", "latency_ms": 90},
    )
    with pytest.raises(ValueError, match="已保留"):
        isps.update_connection(
            settings,
            identifier,
            {"proxy_uri": "socks5://wrong:wrong@8.8.4.4:1080"},
            "admin",
        )
    with connect(settings.database_path) as db:
        after = dict(db.execute("SELECT * FROM isp_exits WHERE id=?", (identifier,)).fetchone())
    assert after["host"] == before["host"]
    assert after["secret_ref"] == before["secret_ref"]
    assert SecretStore(settings.secret_directory).path(before["secret_ref"]).exists()


def test_isp_page_offers_safe_connection_edit_and_link_import(client, settings, isp_data):  # noqa: F811
    isps.register(settings, isp_data, "admin")
    login(client)
    page = client.get("/isps")
    assert "编辑连接信息" in page.text
    assert "粘贴完整 SOCKS5 链接" in page.text
    assert 'src="/static/isps.js"' in page.text
    assert isp_data["username"] not in page.text
    assert isp_data["password"] not in page.text


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
