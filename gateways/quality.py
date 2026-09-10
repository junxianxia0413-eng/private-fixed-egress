"""Gateway-to-ISP measurements; never describe HTTP failures as packet loss."""

import json
import os
import re
import shutil
import socket
import statistics
import subprocess
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

MANIFEST = Path("/var/lib/pfem-gateway-admin/manifest.json")


def measure(group):
    samples = []
    failed = 0
    for _ in range(10):
        began = time.monotonic()
        try:
            with socket.create_connection((group["server"], group["port"]), timeout=1):
                samples.append((time.monotonic() - began) * 1000)
        except OSError:
            failed += 1
        time.sleep(0.1)
    result = {
        "id": group["id"],
        "server": group["server"],
        "samples": 10,
        "tcp_failed": failed,
        "tcp_latency_ms": round(statistics.median(samples), 2) if samples else None,
        "tcp_jitter_ms": round(
            statistics.mean(abs(b - a) for a, b in zip(samples, samples[1:], strict=False)), 2
        )
        if len(samples) > 1
        else None,
        "icmp_loss_percent": None,
        "icmp_received": None,
        "icmp_sent": None,
    }
    if shutil.which("ping"):
        response = subprocess.run(
            ["ping", "-n", "-c", "10", "-i", "0.2", "-W", "1", "-w", "5", group["server"]],
            capture_output=True,
            text=True,
            timeout=7,
            env={**os.environ, "LC_ALL": "C"},
        )
        match = re.search(
            r"(\d+) packets transmitted, (\d+) (?:packets )?received", response.stdout
        )
        if match:
            sent, received = map(int, match.groups())
            result.update(icmp_sent=sent, icmp_received=received)
            # Zero replies cannot distinguish filtering from actual loss on a usable TCP path.
            if sent and received:
                result["icmp_loss_percent"] = round(100 * (sent - received) / sent, 1)
    return result


def run():
    if not MANIFEST.exists():
        return {"ok": True, "measurements": [], "checked_at": int(time.time())}
    manifest = json.loads(MANIFEST.read_text())
    groups = manifest["groups"]
    with ThreadPoolExecutor(max_workers=4) as pool:
        values = list(pool.map(measure, groups))
    return {
        "ok": True,
        "measurements": values,
        "checked_at": int(time.time()),
        "transaction": manifest["transaction"],
    }
