#!/usr/bin/python3
"""Installed root-owned on a Gateway; sudo permits only these fixed actions."""

import fcntl
import json
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path

SERVICE = "pfem-gateway.service"
CONFIG = "/etc/pfem-gateway/config.json"
CORE = "/usr/local/bin/pfem-sing-box"
SSH_CONFIG = Path("/etc/ssh/sshd_config.d/00-pfem-key-only.conf")
SSH_BACKUP = Path("/etc/pfem-gateway/ssh-before-hardening.json")
TIMER = "pfem-ssh-rollback"


def command(args, timeout=15):
    return subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False)


def status():
    active = command(["/usr/bin/systemctl", "is-active", SERVICE]).returncode == 0
    firewall = command(["/usr/bin/systemctl", "is-active", "pfem-gateway-firewall"]).returncode == 0
    effective = command(["/usr/sbin/sshd", "-T"]).stdout.splitlines()
    key_only = (
        "passwordauthentication no" in effective and "kbdinteractiveauthentication no" in effective
    )
    valid = command([CORE, "check", "-c", CONFIG]).returncode == 0
    port = False
    blocked = False
    try:
        with socket.create_connection(("127.0.0.1", 10810), timeout=3) as probe:
            probe.sendall(b"\x05\x01\x00")
            port = probe.recv(2) == b"\x05\x00"
            if port:
                probe.sendall(b"\x05\x01\x00\x01\x08\x08\x08\x08\x01\xbb")
                reply = probe.recv(10)
                blocked = not reply or (len(reply) >= 2 and reply[0] == 5 and reply[1] != 0)
    except OSError:
        pass

    def cpu():
        values = [int(v) for v in Path("/proc/stat").read_text().splitlines()[0].split()[1:9]]
        return sum(values), values[3] + values[4]

    first = cpu()
    time.sleep(0.2)
    last = cpu()
    delta = last[0] - first[0]
    usage = round(100 * (1 - (last[1] - first[1]) / delta), 1) if delta else 0
    memory = {
        line.split(":")[0]: int(line.split()[1])
        for line in Path("/proc/meminfo").read_text().splitlines()
    }
    disk = shutil.disk_usage("/")
    return {
        "healthy": active and firewall and valid and port and blocked,
        "ssh_key_only": key_only,
        "firewall": firewall,
        "egress_blocked": blocked,
        "service": active,
        "config_valid": valid,
        "proxy_port": port,
        "cpu_percent": usage,
        "ram_percent": round(100 * (1 - memory["MemAvailable"] / memory["MemTotal"]), 1),
        "disk_percent": round(100 * disk.used / disk.total, 1),
        "version": command([CORE, "version"]).stdout.splitlines()[0],
        "checked_at": int(time.time()),
        "isp_bound": False,
    }


def rollback_hardening():
    if SSH_BACKUP.exists():
        old = json.loads(SSH_BACKUP.read_text())["previous"]
        if old is None:
            SSH_CONFIG.unlink(missing_ok=True)
        else:
            SSH_CONFIG.write_text(old)
        command(["/usr/sbin/sshd", "-t"])
        command(["/usr/bin/systemctl", "reload", "ssh"])
        SSH_BACKUP.unlink()


def harden():
    if SSH_BACKUP.exists():
        return 75
    SSH_BACKUP.write_text(
        json.dumps({"previous": SSH_CONFIG.read_text() if SSH_CONFIG.exists() else None})
    )
    SSH_BACKUP.chmod(0o600)
    timer = command(
        [
            "/usr/bin/systemd-run",
            "--unit=" + TIMER,
            "--collect",
            "--on-active=90s",
            "/usr/local/sbin/pfem-gateway-admin",
            "rollback-harden",
        ]
    )
    if timer.returncode:
        SSH_BACKUP.unlink()
        return 67
    SSH_CONFIG.write_text(
        "PasswordAuthentication no\nKbdInteractiveAuthentication no\n"
        "PubkeyAuthentication yes\nPermitRootLogin prohibit-password\n"
    )
    effective = command(["/usr/sbin/sshd", "-T"]).stdout.splitlines()
    if (
        command(["/usr/sbin/sshd", "-t"]).returncode
        or "passwordauthentication no" not in effective
        or "kbdinteractiveauthentication no" not in effective
        or "pubkeyauthentication yes" not in effective
        or "permitrootlogin without-password" not in effective
        or command(["/usr/bin/systemctl", "reload", "ssh"]).returncode
    ):
        rollback_hardening()
        command(["/usr/bin/systemctl", "stop", TIMER + ".timer"])
        return 66
    return 0


def main():
    if len(sys.argv) != 2 or sys.argv[1] not in {
        "status",
        "reconcile",
        "restart",
        "harden",
        "commit-harden",
        "rollback-harden",
    }:
        return 64
    if not Path("/etc/pfem-gateway/managed-v1").is_file():
        return 65
    action = sys.argv[1]
    if action != "status":
        with open("/run/lock/pfem-gateway.lock", "w") as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                return 75
            if action == "harden":
                code = harden()
                if code:
                    return code
            elif action == "rollback-harden":
                rollback_hardening()
                return 0
            elif action == "commit-harden":
                if not SSH_BACKUP.exists():
                    return 70
                command(["/usr/bin/systemctl", "stop", TIMER + ".timer"])
                SSH_BACKUP.unlink()
            else:
                if command([CORE, "check", "-c", CONFIG]).returncode:
                    return 68
                verb = "restart" if action == "restart" else "start"
                if command(["/usr/bin/systemctl", verb, SERVICE]).returncode:
                    return 69
    result = status()
    for _ in range(10):
        if result["healthy"]:
            break
        time.sleep(0.5)
        result = status()
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
