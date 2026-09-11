"""Linux-only tests of the installed helper's failure and SSH recovery paths."""

import importlib
import json
import os
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

pytestmark = pytest.mark.skipif(os.name != "posix", reason="Gateway runs on Debian")


@pytest.fixture
def remote(tmp_path, monkeypatch):
    module = importlib.import_module("gateways.remote_admin")
    monkeypatch.setattr(module, "SSH_CONFIG", tmp_path / "ssh.conf")
    monkeypatch.setattr(module, "SSH_BACKUP", tmp_path / "before.json")
    config = tmp_path / "config.json"
    config.write_text('{"outbounds":[]}')
    monkeypatch.setattr(module, "CONFIG", str(config))
    monkeypatch.setattr(module, "CPU_CACHE", tmp_path / "cpu.json")
    return module


def test_cpu_uses_interval_since_previous_health_check(remote, monkeypatch):
    remote.CPU_CACHE.write_text(json.dumps({"total": 1000, "idle": 900, "percent": 10.0}))
    monkeypatch.setattr(remote, "cpu_times", lambda: (7000, 6780))
    monkeypatch.setattr(remote.time, "sleep", lambda _: pytest.fail("unexpected short sample"))

    assert remote.cpu_usage() == 2.0
    assert json.loads(remote.CPU_CACHE.read_text())["percent"] == 2.0


def test_cpu_keeps_last_average_when_checks_are_too_close(remote, monkeypatch):
    remote.CPU_CACHE.write_text(json.dumps({"total": 1000, "idle": 990, "percent": 1.0}))
    monkeypatch.setattr(remote, "cpu_times", lambda: (1050, 1040))
    monkeypatch.setattr(remote.time, "sleep", lambda _: pytest.fail("unexpected short sample"))

    assert remote.cpu_usage() == 1.0


def test_first_cpu_check_uses_one_second_sample(remote, monkeypatch):
    samples = iter(((1000, 900), (1100, 998)))
    slept = []
    monkeypatch.setattr(remote, "cpu_times", lambda: next(samples))
    monkeypatch.setattr(remote.time, "sleep", slept.append)

    assert remote.cpu_usage() == 2.0
    assert slept == [1]


def test_invalid_ssh_configuration_restores_previous_settings(remote, monkeypatch):
    remote.SSH_CONFIG.write_text("previous configuration\n")

    def command(args, **kwargs):
        return SimpleNamespace(returncode=1 if args[-1] == "-t" else 0, stdout="")

    monkeypatch.setattr(remote, "command", command)
    assert remote.harden() == 66
    assert remote.SSH_CONFIG.read_text() == "previous configuration\n"
    assert not remote.SSH_BACKUP.exists()


def test_expired_confirmation_restores_missing_original_file(remote, monkeypatch):
    remote.SSH_CONFIG.write_text("PasswordAuthentication no\n")
    remote.SSH_BACKUP.write_text(json.dumps({"previous": None}))
    monkeypatch.setattr(remote, "command", lambda *a, **k: SimpleNamespace(returncode=0))
    remote.rollback_hardening()
    assert not remote.SSH_CONFIG.exists()
    assert not remote.SSH_BACKUP.exists()


def test_missing_firewall_is_not_healthy_even_when_proxy_responds(remote, monkeypatch):
    def command(args, **kwargs):
        if args[0] == "/usr/sbin/nft":
            return SimpleNamespace(returncode=1, stdout="")
        return SimpleNamespace(returncode=0, stdout="sing-box version 1.14.0")

    probe = MagicMock()
    probe.__enter__.return_value.recv.side_effect = [b"\x05\x00", b""]
    monkeypatch.setattr(remote, "command", command)
    monkeypatch.setattr(remote.socket, "create_connection", lambda *a, **k: probe)
    result = remote.status()
    assert result["service"] and result["config_valid"] and result["egress_blocked"]
    assert not result["firewall"] and not result["healthy"]
