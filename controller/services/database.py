import os
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path

from controller.models.schema import MIGRATIONS


@contextmanager
def connect(path: Path):
    db = sqlite3.connect(path, timeout=10)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA foreign_keys=ON")
    db.execute("PRAGMA busy_timeout=10000")
    try:
        with db:
            yield db
    finally:
        db.close()


def migrate(path: Path):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with connect(path) as db:
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("BEGIN IMMEDIATE")
        version = db.execute("PRAGMA user_version").fetchone()[0]
        if version > len(MIGRATIONS):
            raise RuntimeError("Database newer than application; restore matching release")
        for number, statements in enumerate(MIGRATIONS[version:], start=version + 1):
            for statement in statements:
                db.execute(statement)
            db.execute(f"PRAGMA user_version={number}")
    if os.name == "posix":
        path.chmod(0o600)


def audit(db, actor: str, action: str, detail: str = ""):
    db.execute(
        "INSERT INTO audit_events(occurred_at, actor, action, detail) VALUES (?, ?, ?, ?)",
        (int(time.time()), actor, action, detail),
    )


def backup(source: Path, destination: Path):
    if not source.is_file():
        raise ValueError("Source database does not exist")
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(destination, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    os.close(fd)
    try:
        with connect(source) as origin:
            target = sqlite3.connect(destination)
            try:
                origin.backup(target)
                if target.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                    raise RuntimeError("Backup integrity check failed")
                target.execute("DELETE FROM sessions")
                target.commit()
            finally:
                target.close()
    except Exception:
        destination.unlink(missing_ok=True)
        raise
