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

    monkeypatch.setattr(guard, "bounded_check", lambda group, _: {"result": healthy([group])[0]})
    guard.run()
    assert leases[-1] == ([20001, 20002], [13001, 13002])

    def first_unavailable(rows, **_):
        if rows[0]["id"] == 1:
            raise apply_error("EXIT_CHECK_FAILED:1")
        return healthy(rows)

    def outcome(group, _):
        try:
            return {"result": first_unavailable([group])[0]}
        except apply_error:
            return {"error": "EXIT_UNAVAILABLE", "hard": False}

    monkeypatch.setattr(guard, "bounded_check", outcome)
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

    monkeypatch.setattr(guard, "bounded_check", lambda group, _: {"result": healthy([group])[0]})
    guard.run()
    assert leases[-1] == ([20001, 20002], [13001, 13002])

    def identity_changed(rows, **_):
        if rows[0]["id"] == 1:
            raise apply_error("EXIT_IP_MISMATCH:1")
        return healthy(rows)

    def changed(group, _):
        try:
            return {"result": identity_changed([group])[0]}
        except apply_error:
            return {"error": "EXIT_IP_MISMATCH", "hard": True}

    monkeypatch.setattr(guard, "bounded_check", changed)
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
        guard, "bounded_check", lambda *_: {"error": "EXIT_UNAVAILABLE", "hard": False}
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


def test_slow_worker_is_killed_before_service_timeout(monkeypatch):
    import subprocess
    import time

    guard = importlib.import_module("gateways.guard")
    calls = []

    def stalled(args, **kwargs):
        calls.append((args, kwargs))
        raise subprocess.TimeoutExpired(args, kwargs["timeout"])

    monkeypatch.setattr(guard.subprocess, "run", stalled)
    secret = "TEST-SECRET-NOT-IN-ARGV"
    assert guard.bounded_check({"probe_password": secret}, time.monotonic() + 0.05) == {
        "error": "EXIT_CHECK_TIMEOUT", "hard": False,
    }
    args, options = calls[0]
    assert 0 < options["timeout"] <= 0.05
    assert secret not in " ".join(args)


def test_deadline_terminates_a_real_stalled_process(monkeypatch):
    import sys
    import time

    guard = importlib.import_module("gateways.guard")
    original = guard.subprocess.run

    def stalled_process(args, **kwargs):
        return original([sys.executable, "-c", "import time; time.sleep(60)"], **kwargs)

    monkeypatch.setattr(guard.subprocess, "run", stalled_process)
    start = time.monotonic()
    result = guard.bounded_check({}, start + 0.2)
    assert result["error"] == "EXIT_CHECK_TIMEOUT"
    assert time.monotonic() - start < 3


@pytest.mark.parametrize("changed", [False, True])
def test_network_checks_release_lock_and_discard_old_config(tmp_path, monkeypatch, changed):
    import fcntl

    guard = importlib.import_module("gateways.guard")
    manifest = tmp_path / "manifest.json"
    manifest.write_text(json.dumps({
        "transaction": "c" * 32,
        "groups": [{"id": 1, "enabled": True, "clients": [{"id": 1}]}],
    }))
    for key, value in {
        "BASE": tmp_path, "MANIFEST": manifest, "PENDING": tmp_path / "pending",
        "LOCK": tmp_path / "lock", "EVENTS": tmp_path / "events",
    }.items():
        monkeypatch.setattr(guard, key, value)
    leases = []
    monkeypatch.setattr(guard, "lease", lambda ports, tls: leases.append((ports, tls)))

    def check_without_lock(group, deadline):
        with open(guard.LOCK, "w") as other:
            # Configuration and rollback can proceed while a network check is in flight.
            fcntl.flock(other, fcntl.LOCK_EX | fcntl.LOCK_NB)
            if changed:
                manifest.write_text(json.dumps({"transaction": "d" * 32, "groups": []}))
        return {"result": {"id": 1, "exit_ip": "1.1.1.1", "latency_ms": 10}}

    monkeypatch.setattr(guard, "bounded_check", check_without_lock)
    guard.run()
    assert leases == ([] if changed else [([20001], [13001])])
    assert (tmp_path / "guard.json").exists() is not changed
