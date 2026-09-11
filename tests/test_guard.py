import importlib
import json
import os

import pytest

pytestmark = pytest.mark.skipif(os.name != "posix", reason="Gateway requires Linux")


def test_guard_isolates_groups_and_keeps_verified_ingress_on_soft_failures(tmp_path, monkeypatch):
    guard = importlib.import_module("gateways.guard")
    apply_error = importlib.import_module("gateways.transactions").ApplyError
    manifest = tmp_path / "manifest.json"
    groups = [
        {"id": 1, "enabled": True, "clients": [{"id": 1}]},
        {"id": 2, "enabled": True, "clients": [{"id": 2}]},
    ]
    manifest.write_text(json.dumps({"transaction": "a" * 32, "groups": groups}))
    for key, value in {
        "BASE": tmp_path,
        "MANIFEST": manifest,
        "PENDING": tmp_path / "pending",
        "LOCK": tmp_path / "lock",
        "EVENTS": tmp_path / "guard-events.jsonl",
    }.items():
        monkeypatch.setattr(guard, key, value)
    leases = []
    monkeypatch.setattr(guard, "lease", lambda ports, tls_ports: leases.append((ports, tls_ports)))

    def healthy(rows, **_):
        group = rows[0]
        return [{"id": group["id"], "exit_ip": f"1.1.1.{group['id']}", "latency_ms": 10}]

    monkeypatch.setattr(guard, "verify", healthy)
    guard.run()
    assert leases[-1] == ([20001, 20002], [13001, 13002])

    def first_unavailable(rows, **_):
        if rows[0]["id"] == 1:
            raise apply_error("EXIT_CHECK_FAILED:1")
        return healthy(rows)

    monkeypatch.setattr(guard, "verify", first_unavailable)
    guard.run()
    state = json.loads((tmp_path / "guard.json").read_text())
    assert leases[-1] == ([20001, 20002], [13001, 13002])
    assert state["healthy"] is True and state["degraded"] is True
    assert state["groups"][0]["ingress_open"] is True

    for _ in range(5):
        guard.run()
    state = json.loads((tmp_path / "guard.json").read_text())
    assert leases[-1] == ([20001, 20002], [13001, 13002])
    assert state["healthy"] is True and state["degraded"] is True
    assert state["groups"][0]["failure_streak"] == 6
    assert state["groups"][0]["ingress_open"] is True
    assert state["groups"][1]["ingress_open"] is True

    monkeypatch.setattr(guard, "verify", healthy)
    guard.run()
    assert leases[-1] == ([20001, 20002], [13001, 13002])

    def identity_changed(rows, **_):
        if rows[0]["id"] == 1:
            raise apply_error("EXIT_IP_MISMATCH:1")
        return healthy(rows)

    monkeypatch.setattr(guard, "verify", identity_changed)
    guard.run()
    state = json.loads((tmp_path / "guard.json").read_text())
    assert leases[-1] == ([20002], [13002])
    assert state["groups"][0]["error"] == "EXIT_IP_MISMATCH"
    assert "secret" not in (tmp_path / "guard-events.jsonl").read_text()


def test_guard_failure_without_previous_success_opens_nothing(tmp_path, monkeypatch):
    guard = importlib.import_module("gateways.guard")
    manifest = tmp_path / "manifest.json"
    manifest.write_text(
        json.dumps(
            {
                "transaction": "b" * 32,
                "groups": [{"id": 1, "enabled": True, "clients": [{"id": 1}]}],
            }
        )
    )
    for key, value in {
        "BASE": tmp_path,
        "MANIFEST": manifest,
        "PENDING": tmp_path / "pending",
        "LOCK": tmp_path / "lock",
        "EVENTS": tmp_path / "guard-events.jsonl",
    }.items():
        monkeypatch.setattr(guard, key, value)
    leases = []
    monkeypatch.setattr(guard, "lease", lambda ports, tls_ports: leases.append((ports, tls_ports)))
    monkeypatch.setattr(
        guard, "verify", lambda *_args, **_kwargs: (_ for _ in ()).throw(RuntimeError("secret"))
    )
    guard.run()
    assert leases == [([], [])]
    state = json.loads((tmp_path / "guard.json").read_text())
    assert state["healthy"] is False and "secret" not in json.dumps(state)


def test_expired_exit_is_hard_failure_without_network_probe(monkeypatch):
    guard = importlib.import_module("gateways.guard")
    monkeypatch.setattr(
        guard,
        "verify",
        lambda *_args, **_kwargs: pytest.fail("expired exits must not be probed"),
    )
    assert guard.check({"expires_on": "2000-01-01"}) == {
        "error": "EXIT_EXPIRED",
        "hard": True,
    }
