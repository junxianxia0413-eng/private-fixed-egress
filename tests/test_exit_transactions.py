"""Exercise recovery snapshots and commit ordering without host service changes."""

import importlib
import json
import os
from types import SimpleNamespace

import pytest

pytestmark = pytest.mark.skipif(
    os.name != "posix", reason="Root configuration helper runs on Debian"
)


@pytest.fixture
def remote(tmp_path, monkeypatch):
    module = importlib.import_module("gateways.transactions")
    base = tmp_path / "state"
    base.mkdir(mode=0o700)
    for key, value in {
        "BASE": base,
        "PENDING": base / "pending",
        "MANIFEST": base / "manifest.json",
        "CONFIG": tmp_path / "config.json",
        "FIREWALL": tmp_path / "firewall.nft",
    }.items():
        monkeypatch.setattr(module, key, value)
    module.CONFIG.write_text('{"old":true}')
    module.FIREWALL.write_text("old firewall")
    monkeypatch.setattr(
        module.pwd, "getpwnam", lambda _: SimpleNamespace(pw_uid=995, pw_gid=os.getgid())
    )
    monkeypatch.setattr(module.os, "chown", lambda *a: None)
    monkeypatch.setattr(module, "command", lambda *a, **k: SimpleNamespace(returncode=0))
    monkeypatch.setattr(module, "restart", lambda: None)
    monkeypatch.setattr(module, "verify", lambda groups: [])
    return module


def test_committed_config_is_durable_and_replay_rejects_changed_payload(remote):
    report = remote.apply({"transaction": "a" * 32, "groups": []})
    assert report["ok"] and remote.PENDING.exists()
    assert remote.commit({"transaction": "a" * 32})["committed"]
    assert not remote.PENDING.exists()
    assert remote.apply({"transaction": "a" * 32, "groups": []})["committed"]
    assert remote.rollback()["rolled_back"] is False


def test_failed_actual_exit_probe_restores_all_old_files(remote, monkeypatch):
    def failed(groups):
        raise remote.ApplyError("EXIT_IP_MISMATCH")

    monkeypatch.setattr(remote, "verify", failed)
    report = remote.apply({"transaction": "b" * 32, "groups": []})
    assert report["ok"] is False and report["rolled_back"] is True
    assert report["previous_exit_verified"] is False
    assert remote.CONFIG.read_text() == '{"old":true}'
    assert remote.FIREWALL.read_text() == "old firewall"
    assert not remote.MANIFEST.exists() and not remote.PENDING.exists()


def test_failed_rollback_keeps_recovery_timer_and_snapshot(remote, monkeypatch):
    calls = []
    monkeypatch.setattr(
        remote, "command", lambda args, *a, **k: calls.append(args) or SimpleNamespace(returncode=0)
    )

    def fail():
        raise RuntimeError("Service failed")

    monkeypatch.setattr(remote, "restart", fail)
    report = remote.apply({"transaction": "c" * 32, "groups": []})
    assert report["ok"] is False and report["rolled_back"] is False
    assert remote.PENDING.exists()
    assert not any(args[-1] == "pfem-config-rollback.timer" for args in calls)


def test_reboot_recovers_before_services_start(remote, monkeypatch):
    remote.apply({"transaction": "d" * 32, "groups": []})
    monkeypatch.setattr(
        remote, "restart", lambda: pytest.fail("Must restore before starting services")
    )
    report = remote.rollback(reboot=True)
    assert report["rolled_back"] and report["previous_exit_verified"] is None
    assert remote.CONFIG.read_text() == '{"old":true}'


def test_invalid_candidate_never_replaces_running_config(remote, monkeypatch):
    def fail(args, **kwargs):
        if args[0] == remote.CORE:
            raise remote.ApplyError("CONFIG_COMMAND_FAILED")

    monkeypatch.setattr(remote, "checked", fail)
    with pytest.raises(remote.ApplyError):
        remote.apply({"transaction": "e" * 32, "groups": []})
    assert remote.CONFIG.read_text() == '{"old":true}'
    assert not remote.PENDING.exists()


def test_interrupted_staging_does_not_block_next_apply_and_commit_is_idempotent(remote):
    (remote.BASE / "pending.new").mkdir()
    report = remote.apply({"transaction": "f" * 32, "groups": []})
    assert report["ok"]
    with pytest.raises(remote.ApplyError):
        remote.commit({"transaction": "1" * 32})
    assert remote.PENDING.exists()
    remote.commit({"transaction": "f" * 32})
    remote.commit({"transaction": "f" * 32})
    assert json.loads(remote.MANIFEST.read_text())["transaction"] == "f" * 32
