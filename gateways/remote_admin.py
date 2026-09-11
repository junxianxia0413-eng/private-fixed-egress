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
CPU_CACHE = Path("/run/pfem-gateway-cpu.json")
CPU_MIN_TICKS = 100


def network_metrics():
    interfaces = [
        line.split()[0]
        for line in Path("/proc/net/route").read_text().splitlines()[1:]
        if line.split()[1] == "00000000"
    ]
    totals = {"rx_bytes": 0, "tx_bytes": 0, "connections": 0}
    for line in Path("/proc/net/dev").read_text().splitlines()[2:]:
        name, fields = line.split(":", 1)
        if name.strip() in interfaces:
            values = fields.split()
            totals["rx_bytes"] += int(values[0])
            totals["tx_bytes"] += int(values[8])
    for name in ("tcp", "tcp6"):
        for line in Path("/proc/net/" + name).read_text().splitlines()[1:]:
            fields = line.split()
            if fields[3] == "01" and 20001 <= int(fields[1].split(":")[1], 16) <= 21000:
                totals["connections"] += 1
    return totals


def command(args, timeout=15):
    return subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False)


def cpu_times():
    values = [int(v) for v in Path("/proc/stat").read_text().splitlines()[0].split()[1:9]]
    return sum(values), values[3] + values[4]


def save_cpu_sample(total, idle, percent):
    try:
        CPU_CACHE.write_text(json.dumps({"total": total, "idle": idle, "percent": percent}))
    except OSError:
        pass


def cpu_usage():
    """Average CPU use since the previous health check, with a one-second first sample."""
    total, idle = cpu_times()
    try:
        previous = json.loads(CPU_CACHE.read_text())
        old_total, old_idle = int(previous["total"]), int(previous["idle"])
        delta_total, delta_idle = total - old_total, idle - old_idle
        if delta_total >= CPU_MIN_TICKS and 0 <= delta_idle <= delta_total:
            percent = round(100 * (1 - delta_idle / delta_total), 1)
            save_cpu_sample(total, idle, percent)
            return percent
        old_percent = previous.get("percent")
        if (
            delta_total >= 0
            and isinstance(old_percent, (int, float))
            and not isinstance(old_percent, bool)
            and 0 <= old_percent <= 100
        ):
            return old_percent
    except (OSError, ValueError, KeyError, TypeError):
        pass

    first_total, first_idle = total, idle
    time.sleep(1)
    total, idle = cpu_times()
    delta_total, delta_idle = total - first_total, idle - first_idle
    percent = (
        round(100 * (1 - delta_idle / delta_total), 1)
        if delta_total and 0 <= delta_idle <= delta_total
        else 0
    )
    save_cpu_sample(total, idle, percent)
    return percent


def status():
    active = command(["/usr/bin/systemctl", "is-active", SERVICE]).returncode == 0
    firewall = command(["/usr/bin/systemctl", "is-active", "pfem-gateway-firewall"]).returncode == 0
    rules = command(["/usr/sbin/nft", "-j", "list", "table", "inet", "pfem_guard"])
    try:
        entries = json.loads(rules.stdout)["nftables"]
        chains = {entry["chain"]["name"] for entry in entries if "chain" in entry}
        firewall = firewall and rules.returncode == 0 and {"input", "output"} <= chains
        firewall = firewall and sum("rule" in entry for entry in entries) >= 3
    except (ValueError, KeyError, TypeError):
        firewall = False
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

    usage = cpu_usage()
    memory = {
        line.split(":")[0]: int(line.split()[1])
        for line in Path("/proc/meminfo").read_text().splitlines()
    }
    disk = shutil.disk_usage("/")
    try:
        guard = json.loads(Path("/var/lib/pfem-gateway-admin/guard.json").read_text())
    except (OSError, ValueError):
        guard = {}
    return {
        **network_metrics(),
        "guard": guard,
        "probe_available": Path("/usr/local/sbin/pfem-isp-probe").is_file(),
        "config_api": Path("/usr/local/lib/pfem_gateway/gateways/transactions.py").is_file(),
        "phone_api": 8 if Path("/usr/local/lib/pfem_gateway/gateways/quality.py").is_file() else 0,
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
        "isp_bound": bool(json.loads(Path(CONFIG).read_text()).get("outbounds")),
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
        "quality",
        "reconcile",
        "restart",
        "harden",
        "commit-harden",
        "rollback-harden",
        "apply-config",
        "commit-config",
        "rollback-config",
        "recover-config",
    }:
        return 64
    if not Path("/etc/pfem-gateway/managed-v1").is_file():
        return 65
    action = sys.argv[1]
    if action == "quality":
        sys.path.insert(0, "/usr/local/lib/pfem_gateway")
        from gateways.quality import run

        try:
            result = run()
        except Exception:
            result = {"ok": False, "error": "Quality measurement unavailable"}
        print(json.dumps(result))
        return 0
    if action in {"apply-config", "commit-config", "rollback-config", "recover-config"}:
        sys.path.insert(0, "/usr/local/lib/pfem_gateway")
        from gateways.transactions import handle

        return handle(action)
    if action != "status":
        with open("/run/lock/pfem-gateway.lock", "w") as lock:
            deadline = time.monotonic() + 10
            while True:
                try:
                    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if time.monotonic() >= deadline:
                        return 75
                    time.sleep(0.1)
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
                if (
                    action == "reconcile"
                    and command(
                        ["/usr/bin/systemctl", "restart", "pfem-gateway-firewall.service"]
                    ).returncode
                ):
                    return 69
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
