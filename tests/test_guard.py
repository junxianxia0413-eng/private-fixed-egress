import importlib
import json
import os

import pytest

pytestmark = pytest.mark.skipif(os.name != "posix", reason="Gateway requires Linux")


def test_guard_failure_closes_lease_and_recovery_only_uses_same_manifest(tmp_path, monkeypatch):
    guard = importlib.import_module("gateways.guard")
    manifest = tmp_path / "manifest.json"
    manifest.write_text(
        json.dumps({"transaction": "a" * 32, "groups": [{"enabled": True, "clients": [{"id": 1}]}]})
    )
    for key, value in {
        "BASE": tmp_path,
        "MANIFEST": manifest,
        "PENDING": tmp_path / "pending",
        "LOCK": tmp_path / "lock",
    }.items():
        monkeypatch.setattr(guard, key, value)
    leases = []
    monkeypatch.setattr(guard, "lease", leases.append)

    def broken(*a, **k):
        raise RuntimeError("secret")

    monkeypatch.setattr(guard, "verify", broken)
    guard.run()
    assert leases == [[]]
    state = json.loads((tmp_path / "guard.json").read_text())
    assert state["healthy"] is False and "secret" not in json.dumps(state)
    monkeypatch.setattr(guard, "verify", lambda *a, **k: [{"id": 1, "exit_ip": "1.1.1.1"}])
    guard.run()
    assert leases[-1] == [20001]
    assert json.loads((tmp_path / "guard.json").read_text())["healthy"] is True
