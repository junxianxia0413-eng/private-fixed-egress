import hashlib
import json
import sqlite3
import tarfile
from io import BytesIO

import pytest

from controller.services.database import connect
from controller.services.secrets import SecretStore
from scripts.full_backup import create_bundle, verify_bundle
from scripts.service_watch import decisions
from tests.test_controller import settings  # noqa: F401
from tests.test_gateways import data  # noqa: F401


def test_full_backup_restores_database_credentials_and_clears_sessions(settings, data):  # noqa: F811
    from controller.services.gateways import register

    register(settings, data, "admin")
    output = settings.database_path.parent / "complete-backups"
    bundle = create_bundle(settings.database_path, settings.secret_directory, output)
    manifest = verify_bundle(bundle)
    assert any(path.startswith("secrets/") for path in manifest["files"])
    with tarfile.open(bundle) as archive:
        restored = settings.database_path.parent / "restored.db"
        restored.write_bytes(archive.extractfile("controller.db").read())
        with sqlite3.connect(restored) as db:
            assert db.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
            assert not db.execute("SELECT * FROM sessions").fetchall()
            reference = db.execute("SELECT managed_ref FROM gateways").fetchone()[0]
        value = json.load(archive.extractfile("secrets/" + reference))
        assert value == SecretStore(settings.secret_directory).get(reference)


def test_missing_referenced_credentials_do_not_publish_a_backup(settings, data):  # noqa: F811
    from controller.services.gateways import register

    register(settings, data, "admin")
    with connect(settings.database_path) as db:
        reference = db.execute("SELECT managed_ref FROM gateways").fetchone()[0]
    SecretStore(settings.secret_directory).delete(reference)
    output = settings.database_path.parent / "failed-backups"
    with pytest.raises(ValueError, match="Referenced credential missing"):
        create_bundle(settings.database_path, settings.secret_directory, output)
    assert not list(output.glob("pfem-full-*.tar.gz"))


def test_backup_retention_preserves_other_files(settings):  # noqa: F811
    output = settings.database_path.parent / "retention"
    output.mkdir()
    unrelated = output / "user-document.txt"
    unrelated.write_text("keep")
    for _ in range(3):
        create_bundle(settings.database_path, settings.secret_directory, output, keep=2)
    assert len(list(output.glob("pfem-full-*.tar.gz"))) == 2
    assert unrelated.read_text() == "keep"


def test_backup_releases_configuration_lock_before_compression(settings, monkeypatch):  # noqa: F811
    from scripts import full_backup

    released = []
    original = full_backup.tarfile.open

    def archive(*args, **kwargs):
        assert released, "Compression must not retain the live configuration lock"
        return original(*args, **kwargs)

    monkeypatch.setattr(full_backup.tarfile, "open", archive)
    create_bundle(
        settings.database_path,
        settings.secret_directory,
        settings.database_path.parent / "released-backups",
        release_snapshot=lambda: released.append(True),
    )


def test_backup_rejects_tampered_content(tmp_path):
    bundle = tmp_path / "tampered.tar.gz"
    with tarfile.open(bundle, "w:gz") as archive:
        content = b"tampered"
        manifest = json.dumps(
            {
                "files": {
                    "controller.db": hashlib.sha256(b"original").hexdigest(),
                }
            }
        ).encode()
        for name, value in (("controller.db", content), ("manifest.json", manifest)):
            entry = tarfile.TarInfo(name)
            entry.size = len(value)
            archive.addfile(entry, BytesIO(value))
    with pytest.raises(ValueError, match="checksum mismatch"):
        verify_bundle(bundle)


def test_service_watch_requires_repeated_failure_and_respects_cooldown():
    state = {}
    for _ in range(2):
        state, actions = decisions(state, {"caddy": False}, 1000)
        assert not actions
    state, actions = decisions(state, {"caddy": False}, 1000)
    assert actions == ["caddy"]
    state["caddy"]["last_restart"] = 1000
    state, actions = decisions(state, {"caddy": False}, 1299)
    assert not actions
    state, actions = decisions(state, {"caddy": True}, 1300)
    assert not actions and state["caddy"]["failures"] == 0


def test_service_watch_does_not_restart_healthy_services_for_isp_failure():
    state, actions = decisions({}, {"pfem-gateway": True, "caddy": True}, 1000)
    assert not actions
    assert all(item["healthy"] for item in state.values())
