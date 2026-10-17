"""Private, consistent controller + credentials + gateway recovery bundles."""

import argparse
import hashlib
import json
import os
import re
import shutil
import sqlite3
import tarfile
import tempfile
from contextlib import ExitStack
from datetime import UTC, datetime
from pathlib import Path

from controller.config import ROOT, Settings


def verify_bundle(path):
    with tarfile.open(path, "r:gz") as archive:
        members = archive.getmembers()
        names = [member.name for member in members]
        if len(names) != len(set(names)) or any(not member.isfile() for member in members):
            raise ValueError("Invalid backup members")
        manifest = json.load(archive.extractfile("manifest.json"))
        if set(names) != {"manifest.json", *manifest["files"]}:
            raise ValueError("Incomplete backup")
        for name, digest in manifest["files"].items():
            if name.startswith("/") or ".." in Path(name).parts:
                raise ValueError("Invalid backup path")
            with archive.extractfile(name) as stream:
                if hashlib.file_digest(stream, "sha256").hexdigest() != digest:
                    raise ValueError("Backup checksum mismatch")
    return manifest


def create_bundle(database, secrets, output, sources=None, keep=14, release_snapshot=None):
    if not database.is_file() or type(keep) is not int or keep < 1:
        raise ValueError("A database and positive backup retention are required")
    output.mkdir(mode=0o700, parents=True, exist_ok=True)
    if os.name == "posix":
        output.chmod(0o700)
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S%fZ")
    destination = output / f"pfem-full-{stamp}.tar.gz"
    with tempfile.TemporaryDirectory(prefix=".preparing-", dir=output) as temporary:
        stage = Path(temporary)
        db_copy = stage / "controller.db"
        # Hold writers on a separate connection; SQLite backup uses a reader so
        # backup() cannot loop on its own uncommitted write transaction.
        with sqlite3.connect(database, timeout=10) as writer:
            writer.execute("BEGIN IMMEDIATE")
            with sqlite3.connect(database) as reader, sqlite3.connect(db_copy) as target:
                reader.backup(target)
                if target.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                    raise ValueError("Database backup failed integrity check")
                if target.execute("PRAGMA foreign_key_check").fetchall():
                    raise ValueError("Database references are invalid")
                tables = {r[0] for r in target.execute("SELECT name FROM sqlite_master")}
                if "sessions" in tables:
                    target.execute("DELETE FROM sessions")
                references = set()
                for table in ("gateways", "isp_exits", "exit_groups", "subscription_groups"):
                    if table not in tables:
                        continue
                    for column in target.execute(f"PRAGMA table_info({table})"):
                        name = column[1]
                        if re.fullmatch(r"[a-z_]+_ref", name):
                            references.update(
                                r[0]
                                for r in target.execute(f'SELECT "{name}" FROM {table}')
                                if r[0]
                            )
                for reference in references:
                    if not re.fullmatch(r"[a-f0-9]{32}", reference):
                        raise ValueError("Invalid credential reference")
                    if not (secrets / reference).is_file() or (secrets / reference).is_symlink():
                        raise ValueError("Referenced credential missing")
                if references:
                    (stage / "secrets").mkdir(mode=0o700)
                    for reference in references:
                        shutil.copy2(secrets / reference, stage / "secrets" / reference)
            for label, source in (sources or {}).items():
                if not re.fullmatch(r"[a-zA-Z0-9_.-]+", label):
                    raise ValueError("Invalid backup source label")
                if source.is_dir():
                    shutil.copytree(
                        source, stage / label, ignore=shutil.ignore_patterns("__pycache__", "*.pyc")
                    )
                elif source.is_file():
                    shutil.copy2(source, stage / label)
        if release_snapshot:
            # Compress only private staged copies; a growing archive must not
            # keep configuration apply, rollback or guard publication locked.
            release_snapshot()
        files = sorted(p for p in stage.rglob("*") if p.is_file())
        manifest = {
            "version": 1,
            "created_at": stamp,
            "files": {
                p.relative_to(stage).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
                for p in files
            },
        }
        (stage / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
        candidate = stage / "bundle.tar.gz"
        with tarfile.open(candidate, "w:gz", dereference=False) as archive:
            for path in [*files, stage / "manifest.json"]:
                archive.add(path, arcname=path.relative_to(stage).as_posix(), recursive=False)
        verify_bundle(candidate)
        candidate.chmod(0o600)
        with candidate.open("rb") as stream:
            os.fsync(stream.fileno())
        os.replace(candidate, destination)
    # Retain only this tool's regular archive files, never unrelated files/symlinks.
    previous = sorted(
        p for p in output.glob("pfem-full-*.tar.gz") if p.is_file() and not p.is_symlink()
    )
    for path in previous[:-keep]:
        path.unlink(missing_ok=True)
    return destination


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output-directory", type=Path, default=Path("/var/backups/private-fixed-egress")
    )
    parser.add_argument("--verify", type=Path)
    args = parser.parse_args()
    if args.verify:
        verify_bundle(args.verify)
        print("Backup checksums verified")
        return
    if os.name != "posix" or os.geteuid() != 0:
        raise SystemExit("Complete production backups require root on Debian")
    import fcntl

    settings = Settings.from_env()
    with open("/run/lock/pfem-full-backup.lock", "a+b") as backup_lock, ExitStack() as stack:
        fcntl.flock(backup_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        for name in ("pfem-controller-upgrade", "pfem-gateway"):
            lock = stack.enter_context(open(f"/run/lock/{name}.lock", "a+b"))
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if Path("/var/lib/pfem-gateway-admin/pending").exists():
            raise SystemExit("Configuration is pending; backup deferred")
        paths = {
            "controller.env": Path("/etc/private-fixed-egress/controller.env"),
            "Caddyfile": Path("/etc/caddy/Caddyfile"),
            "gateway-config": Path("/etc/pfem-gateway"),
            "gateway-manifest.json": Path("/var/lib/pfem-gateway-admin/manifest.json"),
            "gateway-guard.json": Path("/var/lib/pfem-gateway-admin/guard.json"),
            "gateway-runtime": Path("/usr/local/lib/pfem_gateway"),
        }
        paths.update(
            {
                f"source-{name}": ROOT / name
                for name in ("controller", "gateways", "scripts", "deploy", "requirements.txt")
            }
        )
        destination = create_bundle(
            settings.database_path,
            settings.secret_directory,
            args.output_directory,
            paths,
            release_snapshot=stack.close,
        )
    print(f"Complete private backup verified: {destination.name}")


if __name__ == "__main__":
    main()
