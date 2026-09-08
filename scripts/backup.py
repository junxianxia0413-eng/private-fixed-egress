import argparse
from datetime import UTC, datetime
from pathlib import Path

from controller.config import ROOT, Settings
from controller.services.database import backup


def main():
    parser = argparse.ArgumentParser(description="Online SQLite backup with integrity verification")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    destination = args.output or ROOT / "backups" / (
        datetime.now(UTC).strftime("controller-%Y%m%dT%H%M%S%fZ.db")
    )
    backup(Settings.from_env().database_path, destination)
    print(f"Verified backup: {destination}")


if __name__ == "__main__":
    main()
