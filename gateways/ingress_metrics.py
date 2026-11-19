"""Summarize active ingress TCP connections without retaining client addresses."""

import hashlib
import ipaddress
import json
import math
import re
import statistics
import subprocess
import time
from pathlib import Path

STATE = Path("/run/pfem-ingress-metrics.json")


def parse(text):
    rows = {}
    lines = text.splitlines()
    for index, line in enumerate(lines):
        fields = line.split()
        if len(fields) < 4 or not fields[0].isdigit():
            continue
        local, peer = fields[2:4]
        if local.rsplit(":", 1)[-1] not in {"443", "8443"}:
            continue
        try:
            address = ipaddress.ip_address(peer.rsplit(":", 1)[0].strip("[]"))
            if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
                address = address.ipv4_mapped
            if not address.is_global:
                continue
        except ValueError:
            continue
        info = lines[index + 1] if index + 1 < len(lines) else ""

        def number(pattern, info=info):
            match = re.search(pattern, info)
            return float(match[1]) if match else 0

        key = hashlib.sha256((local + "|" + peer).encode()).hexdigest()
        rows[key] = {
            "rtt": number(r"\brtt:([\d.]+)"),
            "retrans": int(number(r"\bretrans:\d+/(\d+)")),
            "segments": int(number(r"\bdata_segs_out:(\d+)")),
        }
    return rows


def summarize(rows, previous, now):
    samples = sorted(row["rtt"] for row in rows.values() if row["rtt"] > 0)
    result = {
        "ingress_tcp_connections": len(rows),
        "ingress_rtt_median_ms": round(statistics.median(samples), 1) if samples else None,
        "ingress_rtt_p95_ms": round(samples[math.ceil(0.95 * len(samples)) - 1], 1)
        if samples
        else None,
        "ingress_retrans_delta": None,
        "ingress_data_segments_delta": None,
        "ingress_sample_seconds": None,
    }
    elapsed = now - previous.get("checked_at", 0)
    if 0 < elapsed <= 180:
        comparable = [
            (row, previous["rows"][key])
            for key, row in rows.items()
            if key in previous.get("rows", {})
            and row["retrans"] >= previous["rows"][key]["retrans"]
            and row["segments"] >= previous["rows"][key]["segments"]
        ]
        if comparable:
            result.update(
                ingress_retrans_delta=sum(
                    row["retrans"] - prior["retrans"] for row, prior in comparable
                ),
                ingress_data_segments_delta=sum(
                    row["segments"] - prior["segments"] for row, prior in comparable
                ),
                ingress_sample_seconds=round(elapsed, 1),
            )
    return result


def sample():
    try:
        output = subprocess.run(
            ["ss", "-Htni", "state", "established"],
            capture_output=True,
            text=True,
            timeout=4,
            check=True,
        ).stdout
        rows, now = parse(output), time.time()
        try:
            previous = json.loads(STATE.read_text())
        except (OSError, ValueError):
            previous = {}
        result = summarize(rows, previous, now)
        stage = STATE.with_suffix(".new")
        stage.write_text(json.dumps({"checked_at": now, "rows": rows}))
        stage.chmod(0o600)
        stage.replace(STATE)
        return result
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        return {}
