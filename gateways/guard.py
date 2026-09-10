"""An independent Gateway lease; stale or failed probes close public ingress."""

import fcntl
import json
import subprocess
import time
from pathlib import Path

from gateways.transactions import BASE, MANIFEST, PENDING, verify, write

LOCK = Path("/run/lock/pfem-gateway.lock")


def lease(ports):
    rules = "flush set inet pfem_guard pfem_live\n"
    if ports:
        rules += (
            "add element inet pfem_guard pfem_live { "
            + ", ".join(f"{port} timeout 70s" for port in ports)
            + " }\n"
        )
    result = subprocess.run(
        ["/usr/sbin/nft", "-f", "-"], input=rules.encode(), capture_output=True, timeout=5
    )
    if result.returncode:
        raise RuntimeError("Lease update failed")


def run():
    with open(LOCK, "w") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return
        if PENDING.exists() or not MANIFEST.exists():
            return
        manifest = json.loads(MANIFEST.read_text())
        groups = manifest["groups"]
        ports = [20000 + c["id"] for g in groups if g["enabled"] for c in g.get("clients", [])]
        state = {
            "checked_at": int(time.time()),
            "transaction": manifest["transaction"],
            "healthy": False,
            "results": [],
            "public_ports": ports,
        }
        try:
            state["results"] = verify(groups, clients=False)
            lease(ports)
            state["healthy"] = True
        except Exception:
            try:
                lease([])
            except Exception:
                # If nft is unavailable, expiration still closes entry within 70 seconds.
                pass
            state["error"] = "固定出口检查失败，手机入口已关闭或等待租约到期。"
        write(BASE / "guard.json", json.dumps(state).encode())


if __name__ == "__main__":
    run()
