"""Root-side two-phase configuration apply with durable snapshots and remote rollback."""

import fcntl
import hashlib
import json
import os
import pwd
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from gateways.configuration import render, validate
from gateways.remote_probe import TARGETS, request_all, request_ip

BASE = Path("/var/lib/pfem-gateway-admin")
PENDING = BASE / "pending"
CONFIG = Path("/etc/pfem-gateway/config.json")
FIREWALL = Path("/etc/pfem-gateway/firewall.nft")
MANIFEST = BASE / "manifest.json"
CORE = "/usr/local/bin/pfem-sing-box"
TIMER = "pfem-config-rollback"
SERVICE = "pfem-gateway.service"


class ApplyError(Exception):
    pass


def command(args, timeout=20):
    return subprocess.run(args, capture_output=True, timeout=timeout, check=False)


def checked(args, timeout=20):
    if command(args, timeout).returncode:
        raise ApplyError("CONFIG_COMMAND_FAILED")


def sync_directory(path):
    directory = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def write(path, content, mode=0o600, group=None):
    temporary = path.with_name(path.name + ".new")
    with open(temporary, "wb") as stream:
        stream.write(content)
        stream.flush()
        os.fsync(stream.fileno())
    temporary.chmod(mode)
    if group is not None:
        os.chown(temporary, 0, group)
    os.replace(temporary, path)
    sync_directory(path.parent)


def service_ready():
    for _ in range(30):
        if command(["/usr/bin/systemctl", "is-active", SERVICE]).returncode == 0:
            try:
                with socket.create_connection(("127.0.0.1", 10810), timeout=1) as sock:
                    sock.sendall(b"\x05\x01\x00")
                    if sock.recv(2) == b"\x05\x00":
                        return
            except OSError:
                pass
        time.sleep(0.2)
    raise ApplyError("SERVICE_NOT_READY")


def stop_timer():
    checked(["/usr/bin/systemctl", "stop", TIMER + ".timer"])


def restart():
    checked(["/usr/bin/systemctl", "restart", "pfem-gateway-firewall.service"])
    checked(["/usr/bin/systemctl", "restart", SERVICE])
    service_ready()


def verify_client(group, client):
    # A real encrypted client confirms that the generated phone entry reaches the pinned ISP.
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
    config = {
        "log": {"disabled": True},
        "inbounds": [
            {
                "type": "socks",
                "listen": "127.0.0.1",
                "listen_port": port,
                "users": [
                    {"username": group["probe_username"], "password": group["probe_password"]}
                ],
            }
        ],
        "outbounds": [
            {
                "type": "shadowsocks",
                "tag": "selected",
                "server": "127.0.0.1",
                "server_port": 20000 + client["id"],
                "method": "aes-128-gcm",
                "password": client["password"],
            }
        ],
        "route": {"final": "selected"},
    }
    with tempfile.TemporaryDirectory(prefix="pfem-entry-", dir=str(BASE)) as directory:
        path = Path(directory) / "client.json"
        write(path, json.dumps(config).encode())
        checked([CORE, "check", "-c", str(path)])
        process = subprocess.Popen(
            [CORE, "run", "-c", str(path)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        try:
            for _ in range(30):
                if process.poll() is not None:
                    raise ApplyError("ENCRYPTED_CLIENT_FAILED")
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                        break
                except OSError:
                    time.sleep(0.1)
            probe = {
                "port": port,
                "username": group["probe_username"],
                "password": group["probe_password"],
            }
            actual, _ = request_ip(probe, "127.0.0.1", TARGETS[0])
            if actual != group["expected_ip"]:
                raise ApplyError("ENCRYPTED_EXIT_MISMATCH")
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)


def verify(groups, clients=True):
    results = []
    for group in groups:
        if not group["enabled"]:
            continue
        config = {
            "port": 12000 + group["id"],
            "username": group["probe_username"],
            "password": group["probe_password"],
        }
        measurements = request_all(config, "127.0.0.1")
        if any(ip != group["expected_ip"] for ip, _ in measurements):
            raise ApplyError("EXIT_IP_MISMATCH")
        if clients:
            for client in group.get("clients", []):
                verify_client(group, client)
        results.append(
            {
                "id": group["id"],
                "exit_ip": group["expected_ip"],
                "latency_ms": round(sum(ms for _, ms in measurements) / len(measurements), 1),
            }
        )
    return results


def restore_files():
    meta = json.loads((PENDING / "meta.json").read_text())
    backup = BASE / "backups" / meta["transaction"]
    group = pwd.getpwnam("pfem-proxy").pw_gid
    write(CONFIG, (backup / "config.json").read_bytes(), 0o640, group)
    write(FIREWALL, (backup / "firewall.nft").read_bytes())
    if (backup / "manifest.json").exists():
        write(MANIFEST, (backup / "manifest.json").read_bytes())
    else:
        MANIFEST.unlink(missing_ok=True)


def rollback(reboot=False):
    if not PENDING.exists():
        return {"ok": True, "rolled_back": False}
    if not reboot:
        checked(["/usr/bin/systemctl", "stop", SERVICE])
    restore_files()
    if not reboot:
        restart()
        previous = json.loads(MANIFEST.read_text()).get("groups", []) if MANIFEST.exists() else []
        # Restore availability separately from old ISP availability; never hide a broken rollback.
        try:
            verify(previous)
            usable = True
        except Exception:
            usable = False
    else:
        usable = None
    shutil.rmtree(PENDING)
    sync_directory(BASE)
    return {"ok": True, "rolled_back": True, "previous_exit_verified": usable}


def apply(payload):
    transaction = payload.get("transaction", "")
    if not re.fullmatch("[a-f0-9]{32}", transaction):
        raise ApplyError("INVALID_TRANSACTION")
    groups = validate(payload["groups"])
    if PENDING.exists():
        raise ApplyError("ANOTHER_TRANSACTION_PENDING")
    if MANIFEST.exists():
        previous = json.loads(MANIFEST.read_text())
        if previous["transaction"] == transaction:
            if previous["groups"] != groups:
                raise ApplyError("TRANSACTION_PAYLOAD_CHANGED")
            return {
                "ok": True,
                "committed": True,
                "transaction": transaction,
                "results": verify(groups),
                "config_hash": hashlib.sha256(CONFIG.read_bytes()).hexdigest(),
            }
    config, firewall = render(groups, pwd.getpwnam("pfem-proxy").pw_uid)
    old_groups = json.loads(MANIFEST.read_text()).get("groups", []) if MANIFEST.exists() else []
    old_ports = {20000 + c["id"] for g in old_groups for c in g.get("clients", [])}
    new_ports = {20000 + c["id"] for g in groups for c in g.get("clients", [])}
    for port in new_ports - old_ports:
        with socket.socket() as reservation:
            try:
                reservation.bind(("0.0.0.0", port))
            except OSError:
                raise ApplyError("PHONE_PORT_IN_USE") from None
    BASE.mkdir(mode=0o700, parents=True, exist_ok=True)
    backups = BASE / "backups"
    backups.mkdir(mode=0o700, exist_ok=True)
    backup = backups / transaction
    backup.mkdir(mode=0o700)
    candidate = backup / "candidate.json"
    candidate.write_text(json.dumps(config))
    candidate.chmod(0o600)
    candidate_fw = backup / "candidate.nft"
    candidate_fw.write_text(firewall)
    checked([CORE, "check", "-c", str(candidate)])
    checked(["/usr/sbin/nft", "-c", "-f", str(candidate_fw)])
    shutil.copy2(CONFIG, backup / "config.json")
    shutil.copy2(FIREWALL, backup / "firewall.nft")
    if MANIFEST.exists():
        shutil.copy2(MANIFEST, backup / "manifest.json")
    # Publish pending only after a complete, durable recovery snapshot exists.
    for path in backup.iterdir():
        with open(path, "rb") as stream:
            os.fsync(stream.fileno())
    sync_directory(backup)
    sync_directory(backups)
    pending_stage = BASE / "pending.new"
    if pending_stage.exists():
        # Root-owned staging directory; no live transaction uses it.
        shutil.rmtree(pending_stage)
    pending_stage.mkdir(mode=0o700)
    write(pending_stage / "meta.json", json.dumps({"transaction": transaction}).encode())
    os.replace(pending_stage, PENDING)
    sync_directory(BASE)
    try:
        checked(
            [
                "/usr/bin/systemd-run",
                "--unit=" + TIMER,
                "--collect",
                "--on-active=120s",
                "--timer-property=AccuracySec=1s",
                "--property=Restart=on-failure",
                "--property=RestartSec=5s",
                "/usr/local/sbin/pfem-gateway-admin",
                "rollback-config",
            ]
        )
        checked(["/usr/bin/systemctl", "stop", SERVICE])
        write(CONFIG, candidate.read_bytes(), 0o640, pwd.getpwnam("pfem-proxy").pw_gid)
        write(FIREWALL, candidate_fw.read_bytes())
        restart()
        results = verify(groups)
        # Keep existing firewall policy. Open only reserved, lease-protected phone ports.
        if shutil.which("ufw") and b"Status: active" in getattr(
            command(["ufw", "status"]), "stdout", b""
        ):
            for port in sorted(new_ports):
                checked(["ufw", "allow", str(port) + "/tcp", "comment", "PFEM-phone-entry"])
        write(MANIFEST, json.dumps({"transaction": transaction, "groups": groups}).encode())
        return {
            "ok": True,
            "transaction": transaction,
            "results": results,
            "pending": True,
            "config_hash": hashlib.sha256(CONFIG.read_bytes()).hexdigest(),
        }
    except Exception as exc:
        try:
            restored = rollback()
        except Exception:
            restored = {"rolled_back": False, "previous_exit_verified": False}
        if restored.get("rolled_back"):
            command(["/usr/bin/systemctl", "stop", TIMER + ".timer"])
        return {
            **restored,
            "ok": False,
            "error": str(exc) if isinstance(exc, ApplyError) else "EXIT_CHECK_FAILED",
        }


def commit(payload):
    transaction = payload.get("transaction", "")
    if not re.fullmatch("[a-f0-9]{32}", transaction):
        raise ApplyError("INVALID_TRANSACTION")
    if not MANIFEST.exists() or json.loads(MANIFEST.read_text())["transaction"] != transaction:
        raise ApplyError("TRANSACTION_NOT_APPLIED")
    if PENDING.exists():
        if json.loads((PENDING / "meta.json").read_text())["transaction"] != transaction:
            raise ApplyError("TRANSACTION_CHANGED")
        shutil.rmtree(PENDING)
        sync_directory(BASE)
        # Removal is the durable commit point. A delayed timer now safely does nothing.
        command(["/usr/bin/systemctl", "stop", TIMER + ".timer"])
    return {"ok": True, "committed": True, "transaction": transaction}


def handle(action):
    if action == "recover-config" and not PENDING.exists():
        return 0
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
        try:
            if action in {"apply-config", "commit-config"}:
                raw = sys.stdin.buffer.read(131073)
                if len(raw) > 131072:
                    raise ApplyError("PAYLOAD_TOO_LARGE")
                payload = json.loads(raw)
                result = apply(payload) if action == "apply-config" else commit(payload)
            else:
                result = rollback(reboot=action == "recover-config")
            print(json.dumps(result))
            return 0
        except Exception as exc:
            print(
                json.dumps(
                    {
                        "ok": False,
                        "error": str(exc)
                        if isinstance(exc, ApplyError)
                        else "CONFIG_OPERATION_FAILED",
                    }
                )
            )
            # Let the remote recovery unit retry until the previous configuration is restored.
            return 1 if action in {"rollback-config", "recover-config"} else 0
