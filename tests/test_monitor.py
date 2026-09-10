# ruff: noqa: F811
import time
from unittest.mock import MagicMock

from controller.services import exits, monitor
from controller.services.database import connect
from gateways import quality
from tests.test_controller import csrf, login
from tests.test_exits import group_data  # noqa: F401
from tests.test_gateways import client, data, settings  # noqa: F401
from tests.test_isps import isp_data  # noqa: F401


def test_schedule_intervals_dedup_and_restart(settings, group_data):
    monitor.schedule_due(settings)
    monitor.schedule_due(settings)
    with connect(settings.database_path) as db:
        assert db.execute("SELECT COUNT(*) FROM monitor_jobs").fetchone()[0] == 2
        db.execute("UPDATE monitor_jobs SET state='RUNNING'")
        monitor.recover(db)
        assert (
            db.execute("SELECT COUNT(*) FROM monitor_jobs WHERE state='FAILED'").fetchone()[0] == 2
        )
        db.execute("UPDATE monitor_jobs SET created_at=created_at-61")
    monitor.schedule_due(settings)
    with connect(settings.database_path) as db:
        assert db.execute("SELECT COUNT(*) FROM monitor_jobs").fetchone()[0] == 3


def test_monitor_failure_stale_guard_and_recovery(settings, group_data, monkeypatch):
    identifier = exits.register(settings, group_data, "admin")
    with connect(settings.database_path) as db:
        db.execute("UPDATE exit_groups SET applied=1")
        gateway = dict(db.execute("SELECT * FROM gateways").fetchone())
        now = int(time.time())
        report = {
            "healthy": True,
            "guard": {
                "healthy": True,
                "checked_at": now,
                "results": [{"id": identifier, "exit_ip": "1.1.1.1", "latency_ms": 42}],
            },
        }
        monitor.record_health(db, gateway, report, now)
        assert db.execute("SELECT status FROM exit_groups").fetchone()[0] == "HEALTHY"
        monitor.record_health(db, gateway, report, now + 71)
        assert db.execute("SELECT status FROM exit_groups").fetchone()[0] == "CRITICAL"
        report["guard"]["checked_at"] = now + 1000
        monitor.record_health(db, gateway, report, now)
        assert db.execute("SELECT status FROM exit_groups").fetchone()[0] == "CRITICAL"
    monitor.schedule_due(settings)

    def offline(*args):
        raise OSError("sensitive diagnostic")

    monkeypatch.setattr(monitor, "probe", offline)
    assert monitor.run_next(settings)
    with connect(settings.database_path) as db:
        assert db.execute("SELECT status FROM gateways").fetchone()[0] == "CRITICAL"
        assert "sensitive" not in "\n".join(db.iterdump())
    assert monitor.snapshot(settings)[0]["availability"] == 0


def test_icmp_filtered_is_unknown_not_fake_packet_loss(monkeypatch):
    monkeypatch.setattr(quality.socket, "create_connection", lambda *a, **k: MagicMock())
    monkeypatch.setattr(quality.time, "sleep", lambda *_: None)
    monkeypatch.setattr(quality.shutil, "which", lambda _: "/bin/ping")
    monkeypatch.setattr(
        quality.subprocess,
        "run",
        lambda *a, **k: MagicMock(stdout="10 packets transmitted, 0 received, 100% packet loss"),
    )
    row = quality.measure({"id": 1, "server": "1.1.1.1", "port": 443})
    assert row["tcp_failed"] == 0
    assert row["icmp_loss_percent"] is None
    assert monitor.score(row, 100) is None
    assert not monitor.numeric(float("nan")) and not monitor.numeric(True)


def test_monitor_auth_csrf_and_empty_quality(client, group_data):
    assert client.get("/network").status_code == 303
    assert client.get("/api/network").status_code == 401
    login(client)
    assert client.post("/network/check").status_code == 403
    assert (
        client.post("/network/check", data={"csrf": csrf(client.get("/network"))}).status_code
        == 303
    )
    assert "等待首次线路测量" in client.get("/network").text
