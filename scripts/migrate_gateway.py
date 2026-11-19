"""Apply an explicitly confirmed batch of dedicated ISP routes to a new gateway."""

import argparse
import json
import os
import sys
from pathlib import Path

from controller.config import Settings
from controller.services.gateway_migration import migrate, retire_source
from gateways.ssh import GatewayError


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target-gateway", type=int, required=True)
    parser.add_argument("--confirmed-manifest", type=Path, required=True)
    parser.add_argument("--result", type=Path, required=True)
    args = parser.parse_args()
    if os.name != "posix" or os.geteuid() != 0:
        raise SystemExit("Run this maintenance operation as root")
    import fcntl

    with open("/run/lock/pfem-controller-upgrade.lock", "a+b") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)

        def stage(value):
            print(json.dumps({"stage": value}), flush=True)

        try:
            settings = Settings.from_env()
            expected = json.loads(args.confirmed_manifest.read_text())
            result = migrate(settings, expected, args.target_gateway, "admin", stage)
            result["source_cleanup"] = retire_source(
                settings, expected, args.target_gateway, "admin", stage
            )
        except Exception as exc:
            result = {
                "ok": False,
                "error": str(exc)
                if isinstance(exc, (ValueError, GatewayError))
                else type(exc).__name__,
            }
        temporary = args.result.with_suffix(".new")
        temporary.write_text(json.dumps(result))
        temporary.chmod(0o600)
        os.replace(temporary, args.result)
        print(json.dumps(result), flush=True)
        if not result["ok"]:
            sys.exit(1)


if __name__ == "__main__":
    main()
