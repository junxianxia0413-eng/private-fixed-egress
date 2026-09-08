import os
import subprocess
import sys

from controller.config import ROOT
from controller.services.auth import HASHER
from controller.services.database import connect


def test_unattended_setup_does_not_print_password_and_is_idempotent(tmp_path):
    password = "only-for-this-test-setup-password"
    secret = tmp_path / "bootstrap"
    secret.write_text(password, encoding="utf-8")
    secret.chmod(0o600)
    database = tmp_path / "production.db"
    environment = {
        **os.environ,
        "APP_ENV": "production",
        "PUBLIC_URL": "https://8.8.8.8",
        "DATABASE_PATH": str(database),
    }
    command = [
        sys.executable,
        "-m",
        "scripts.setup",
        "--no-env",
        "--username",
        "admin",
        "--password-file",
        str(secret),
    ]
    for _ in range(2):
        result = subprocess.run(
            command,
            cwd=ROOT,
            env=environment,
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        assert result.returncode == 0, result.stderr
        assert password not in result.stdout + result.stderr
    with connect(database) as db:
        rows = db.execute("SELECT * FROM administrator").fetchall()
        assert len(rows) == 1
        assert HASHER.verify(rows[0]["password_hash"], password)
        assert db.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0] == 1
