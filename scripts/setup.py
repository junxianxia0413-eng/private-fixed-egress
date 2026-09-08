import argparse
import getpass
import os

from controller.config import ROOT, Settings
from controller.services.auth import set_administrator
from controller.services.database import connect, migrate


def main():
    parser = argparse.ArgumentParser(description="Initialize the single administrator locally")
    parser.add_argument(
        "--reset-admin", action="store_true", help="Replace admin; revoke all sessions"
    )
    parser.add_argument("--no-env", action="store_true", help="Use externally supplied environment")
    parser.add_argument("--check", action="store_true", help="Check readiness without prompting")
    args = parser.parse_args()
    settings = Settings.from_env()
    if not args.no_env and not args.check and not (ROOT / ".env").exists():
        fd = os.open(ROOT / ".env", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write((ROOT / ".env.example").read_text(encoding="utf-8"))
    migrate(settings.database_path)
    with connect(settings.database_path) as db:
        existing = db.execute("SELECT id FROM administrator").fetchone() is not None
    if args.check:
        print("Administrator ready" if existing else "Administrator missing")
        return 0 if existing else 1
    if existing and not args.reset_admin:
        print("Administrator already initialized. No changes made.")
        return 0
    username = input("Administrator username: ").strip()
    password = getpass.getpass("Password (14–256 characters): ")
    if password != getpass.getpass("Repeat password: "):
        raise ValueError("Passwords do not match")
    set_administrator(settings, username, password, reset=args.reset_admin)
    print("Administrator saved. All old sessions revoked. Password was not printed or logged.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ValueError as exc:
        raise SystemExit(str(exc)) from None
