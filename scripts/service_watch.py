"""Recover local service failures without restarting for third-party ISP outages."""

import json
import os
import socket
import ssl
import subprocess
import time
import urllib.request
from contextlib import contextmanager
from pathlib import Path

from controller.config import Settings

UNITS = ("private-fixed-egress", "caddy", "pfem-gateway", "pfem-gateway-guard.timer")
STATE = Path("/var/lib/private-fixed-egress/service-watch.json")
PAUSE = Path("/run/pfem-maintenance.pause")


def decisions(previous, checks, now):
    """Require repeated failures; cap restart frequency at once per five minutes."""
    state = {}
    actions = []
    for unit, good in checks.items():
        old = previous.get(unit, {})
        failures = 0 if good else int(old.get("failures", 0)) + 1
        last_restart = int(old.get("last_restart", 0))
        state[unit] = {"healthy": good, "failures": failures, "last_restart": last_restart}
        if failures >= 3 and now - last_restart >= 300:
            actions.append(unit)
    return state, actions


@contextmanager
def configuration_idle():
    import fcntl

    locks = []
    idle = True
    try:
        for name in ("pfem-controller-upgrade", "pfem-gateway"):
            lock = open(f"/run/lock/{name}.lock", "a+b")
            locks.append(lock)
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                idle = False
                break
        yield idle and not Path("/var/lib/pfem-gateway-admin/pending").exists()
    finally:
        for lock in locks:
            lock.close()


def command(*args):
    return subprocess.run(args, capture_output=True, timeout=5, check=False)


def request_ok(url, settings):
    request = urllib.request.Request(
        url,
        headers={
            "Host": settings.hostname,
            "X-Forwarded-Proto": "https",
        },
    )
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        urllib.request.HTTPSHandler(context=ssl.create_default_context()),
    )
    try:
        with opener.open(request, timeout=2) as response:
            return response.status == 200 and json.load(response).get("status") == "ok"
    except Exception:
        return False


def proxy_responsive():
    try:
        with socket.create_connection(("127.0.0.1", 10810), timeout=2) as sock:
            sock.sendall(b"\x05\x01\x00")
            return sock.recv(2) == b"\x05\x00"
    except OSError:
        return False


def run():
    if PAUSE.exists() and time.time() - PAUSE.stat().st_mtime < 900:
        return {"paused": True}
    with configuration_idle() as idle:
        if not idle:
            return {"configuration_busy": True}
    settings = Settings.from_env()
    checks = {
        unit: command("/usr/bin/systemctl", "is-active", unit).returncode == 0
        for unit in UNITS
        if unit not in ("pfem-gateway", "pfem-gateway-guard.timer")
        or Path("/etc/pfem-gateway/managed-v1").exists()
    }
    checks["private-fixed-egress"] = checks["private-fixed-egress"] and request_ok(
        "http://127.0.0.1:8000/healthz", settings
    )
    # Only restart HTTPS when the Controller is responding; an application failure
    # is not evidence that Caddy itself needs a restart.
    if checks["private-fixed-egress"]:
        checks["caddy"] = checks["caddy"] and request_ok(settings.public_url + "/healthz", settings)
    if "pfem-gateway" in checks:
        checks["pfem-gateway"] = checks["pfem-gateway"] and proxy_responsive()
    try:
        previous = json.loads(STATE.read_text())["services"]
    except (OSError, ValueError, KeyError, TypeError):
        previous = {}
    now = int(time.time())
    services, actions = decisions(previous, checks, now)
    with configuration_idle() as idle:
        if idle:
            for unit in actions[:1]:
                # Start the guard timer rather than interrupt its running check.
                verb = "start" if unit.endswith(".timer") else "restart"
                result = command("/usr/bin/systemctl", "--no-block", verb, unit)
                if result.returncode == 0:
                    services[unit]["last_restart"] = now
    state = {"checked_at": now, "services": services}
    temporary = STATE.with_suffix(".new")
    temporary.write_text(json.dumps(state))
    temporary.chmod(0o640)
    import grp

    os.chown(temporary, 0, grp.getgrnam("pfem").gr_gid)
    os.replace(temporary, STATE)
    return state


if __name__ == "__main__":
    print(json.dumps(run()))
