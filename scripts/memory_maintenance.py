"""Inspect memory and release abandoned diagnostics and old journal mappings."""

import json
import os
import signal
import subprocess
import time
from pathlib import Path

STATE = Path("/var/lib/private-fixed-egress/memory-maintenance.json")
JOURNAL_RSS_LIMIT = 64 * 1024 * 1024
ROTATE_COOLDOWN = 6 * 3600


def memory():
    fields = {}
    for line in Path("/proc/meminfo").read_text().splitlines():
        key, value = line.split(":", 1)
        fields[key] = int(value.split()[0]) * 1024
    return {key: fields[key] for key in ("MemTotal", "MemAvailable", "Cached", "MemFree")}


def process(pid):
    directory = Path("/proc") / str(pid)
    stat = (directory / "stat").read_text().rsplit(")", 1)[1].split()
    return {
        "pid": pid,
        "parent": int(stat[1]),
        "start_ticks": int(stat[19]),
        "rss": int(stat[21]) * os.sysconf("SC_PAGE_SIZE"),
        "name": (directory / "comm").read_text().strip(),
        "command": (directory / "cmdline").read_bytes().rstrip(b"\0").decode().split("\0"),
    }


def abandoned_diagnostic(info, uptime, config_exists):
    command = info["command"]
    age = uptime - info["start_ticks"] / os.sysconf("SC_CLK_TCK")
    if info["parent"] != 1 or age < 600 or len(command) != 4:
        return False
    if command[:3] != ["/usr/local/bin/pfem-sing-box", "run", "-c"]:
        return False
    config = Path(command[3])
    return (
        config.parent.parent == Path("/tmp")
        and config.parent.name.startswith("tmp")
        and config.name == "client.json"
        and not config_exists
    )


def rotation_due(rss, last_rotation, now):
    return rss >= JOURNAL_RSS_LIMIT and now - last_rotation >= ROTATE_COOLDOWN


def run():
    import fcntl

    with open("/run/lock/pfem-memory-maintenance.lock", "a+b") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return {"busy": True}
        try:
            previous = json.loads(STATE.read_text())
        except (OSError, ValueError):
            previous = {}
        now = int(time.time())
        uptime = float(Path("/proc/uptime").read_text().split()[0])
        result = {
            "checked_at": now,
            "before": memory(),
            "last_journal_rotation": previous.get("last_journal_rotation", 0),
            "actions": [],
        }
        for entry in Path("/proc").iterdir():
            if not entry.name.isdigit():
                continue
            try:
                info = process(int(entry.name))
                command = info["command"]
                config_exists = len(command) == 4 and Path(command[3]).exists()
                if abandoned_diagnostic(info, uptime, config_exists):
                    # A pidfd pins the process identity while its PID could be reused.
                    descriptor = os.pidfd_open(info["pid"])
                    try:
                        current = process(info["pid"])
                        same_process = all(
                            current[key] == info[key]
                            for key in ("start_ticks", "parent", "command")
                        )
                        if same_process and not Path(command[3]).exists():
                            signal.pidfd_send_signal(descriptor, signal.SIGTERM)
                            result["actions"].append({"action": "stop_abandoned_diagnostic"})
                    finally:
                        os.close(descriptor)
                if info["name"] == "systemd-journal" and rotation_due(
                    info["rss"], result["last_journal_rotation"], now
                ):
                    rotated = subprocess.run(
                        ["/usr/bin/journalctl", "--rotate"],
                        capture_output=True,
                        timeout=10,
                        check=False,
                    )
                    if rotated.returncode == 0:
                        result["last_journal_rotation"] = now
                        result["actions"].append({"action": "rotate_journal_mappings"})
            except (OSError, ValueError, IndexError, subprocess.TimeoutExpired):
                continue
        result["after"] = memory()
        result["low_available_memory"] = (
            result["after"]["MemAvailable"] < result["after"]["MemTotal"] * 0.15
        )
        temporary = STATE.with_suffix(".new")
        temporary.write_text(json.dumps(result))
        temporary.chmod(0o600)
        os.replace(temporary, STATE)
        return result


if __name__ == "__main__":
    print(json.dumps(run()))
