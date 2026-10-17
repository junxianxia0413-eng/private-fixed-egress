"""Independently verify each fixed exit and lease only its public client ports."""

import fcntl
import json
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, date, datetime
from pathlib import Path

from gateways.transactions import BASE, MANIFEST, PENDING, ApplyError, verify, write

LOCK = Path("/run/lock/pfem-gateway.lock")
EVENTS = BASE / "guard-events.jsonl"
PROBE_BUDGET = 25


def bounded_check(group, deadline):
    """A stalled DNS/SOCKS/TLS request must not stall the gateway heartbeat."""
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        return {"error": "EXIT_CHECK_TIMEOUT", "hard": False, "attempted": False}
    try:
        result = subprocess.run(
            [sys.executable, "-m", "gateways.guard", "check"],
            input=json.dumps(group).encode(),
            capture_output=True,
            timeout=remaining,
        )
        if result.returncode:
            raise ValueError("Probe worker failed")
        outcome = json.loads(result.stdout)
        if not isinstance(outcome, dict) or not ("result" in outcome or "error" in outcome):
            raise ValueError("Invalid probe report")
        return outcome
    except subprocess.TimeoutExpired:
        return {"error": "EXIT_CHECK_TIMEOUT", "hard": False}
    except Exception:
        return {"error": "EXIT_UNAVAILABLE", "hard": False}


def lease(ports, tls_ports):
    rules = "flush set inet pfem_guard pfem_live\n"
    if ports:
        rules += (
            "add element inet pfem_guard pfem_live { "
            + ", ".join(f"{port} timeout 70s" for port in ports)
            + " }\n"
        )
    tls_set = (
        subprocess.run(
            ["/usr/sbin/nft", "list", "set", "inet", "pfem_guard", "pfem_tls_live"],
            capture_output=True,
            timeout=5,
        ).returncode
        == 0
    )
    if tls_set:
        rules += "flush set inet pfem_guard pfem_tls_live\n"
        if tls_ports:
            rules += (
                "add element inet pfem_guard pfem_tls_live { "
                + ", ".join(map(str, tls_ports))
                + " }\n"
            )
    result = subprocess.run(
        ["/usr/sbin/nft", "-f", "-"], input=rules.encode(), capture_output=True, timeout=5
    )
    if result.returncode:
        raise RuntimeError("Lease update failed")


def load_state():
    try:
        value = json.loads((BASE / "guard.json").read_text())
        return value if isinstance(value, dict) else {}
    except (OSError, ValueError):
        return {}


def previous_groups(previous, manifest):
    if previous.get("transaction") != manifest["transaction"]:
        return {}
    rows = previous.get("groups")
    if isinstance(rows, list):
        return {row.get("id"): row for row in rows if isinstance(row, dict)}
    # Upgrade a previously healthy state so transient upstream checks cannot close its ingress.
    results = {
        row.get("id"): row
        for row in previous.get("results") or []
        if isinstance(row, dict) and type(row.get("id")) is int
    }
    if previous.get("healthy") is not True:
        return {}
    return {
        identifier: {
            "id": identifier,
            "healthy": True,
            "ingress_open": True,
            "failure_streak": 0,
            "last_success_at": previous.get("checked_at"),
            "result": result,
        }
        for identifier, result in results.items()
    }


def check(group):
    expires_on = group.get("expires_on")
    if expires_on and date.fromisoformat(expires_on) < datetime.now(UTC).date():
        return {"error": "EXIT_EXPIRED", "hard": True}
    try:
        return {"result": verify([group], clients=False, attempts=2)[0]}
    except ApplyError as exc:
        error = str(exc)
        return {
            "error": "EXIT_IP_MISMATCH"
            if error.startswith("EXIT_IP_MISMATCH:")
            else "EXIT_UNAVAILABLE",
            "hard": error.startswith("EXIT_IP_MISMATCH:"),
        }
    except Exception:
        return {"error": "EXIT_UNAVAILABLE", "hard": False}


def record_event(previous, state):
    old = [
        (row.get("id"), row.get("healthy"), row.get("ingress_open"), row.get("error"))
        for row in previous.get("groups") or []
        if isinstance(row, dict)
    ]
    new = [
        (row.get("id"), row.get("healthy"), row.get("ingress_open"), row.get("error"))
        for row in state["groups"]
    ]
    if old == new and not state["degraded"]:
        return
    try:
        lines = EVENTS.read_text().splitlines()[-199:]
    except OSError:
        lines = []
    event = {
        "checked_at": state["checked_at"],
        "transaction": state["transaction"],
        "healthy": state["healthy"],
        "degraded": state["degraded"],
        "groups": [
            {
                key: row.get(key)
                for key in ("id", "healthy", "ingress_open", "failure_streak", "error")
            }
            for row in state["groups"]
        ],
    }
    write(EVENTS, ("\n".join([*lines, json.dumps(event)]) + "\n").encode())


def run():
    # Snapshot only under the configuration lock. Network checks run outside it so
    # an unavailable detection site cannot block apply/rollback/restart operations.
    with open(LOCK, "w") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return
        if PENDING.exists() or not MANIFEST.exists():
            return
        manifest = json.loads(MANIFEST.read_text())
        groups = [group for group in manifest["groups"] if group["enabled"]]
        previous = load_state()
        old_groups = previous_groups(previous, manifest)
    # Older/never-attempted routes go first if there are more routes than workers.
    groups.sort(key=lambda group: old_groups.get(group["id"], {}).get("attempted_at", 0))
    deadline = time.monotonic() + PROBE_BUDGET
    with ThreadPoolExecutor(max_workers=min(4, max(1, len(groups)))) as pool:
        outcomes = list(pool.map(lambda group: bounded_check(group, deadline), groups))
    with open(LOCK, "w") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return
        if PENDING.exists() or not MANIFEST.exists():
            return
        if json.loads(MANIFEST.read_text()) != manifest:
            # Never authorize ports or overwrite guard state using an old config.
            return
        previous = load_state()
        old_groups = previous_groups(previous, manifest)
        now = int(time.time())
        states = []
        open_ports = []
        open_tls_ports = []
        for group, outcome in zip(groups, outcomes, strict=True):
            prior = old_groups.get(group["id"], {})
            if "result" in outcome:
                row = {
                    "id": group["id"],
                    "healthy": True,
                    "ingress_open": True,
                    "failure_streak": 0,
                    "last_success_at": now,
                    "result": outcome["result"],
                }
            else:
                streak = int(prior.get("failure_streak") or 0) + 1
                last_success = prior.get("last_success_at")
                grace = (
                    not outcome.get("hard")
                    and prior.get("ingress_open") is True
                    and type(last_success) is int
                )
                row = {
                    "id": group["id"],
                    "healthy": False,
                    "ingress_open": grace,
                    "failure_streak": streak,
                    "last_success_at": last_success,
                    "error": outcome["error"],
                }
                if grace and isinstance(prior.get("result"), dict):
                    row["result"] = prior["result"]
            row["attempted_at"] = (
                now if outcome.get("attempted", True) else prior.get("attempted_at", 0)
            )
            if row["ingress_open"]:
                open_ports.extend(20000 + client["id"] for client in group.get("clients", []))
                open_tls_ports.extend(13000 + client["id"] for client in group.get("clients", []))
            states.append(row)
        state = {
            "checked_at": now,
            "transaction": manifest["transaction"],
            "healthy": all(row["ingress_open"] for row in states),
            "degraded": any(not row["healthy"] for row in states),
            "groups": states,
            "results": [row["result"] for row in states if isinstance(row.get("result"), dict)],
            "public_ports": open_ports,
            "tls_ports": open_tls_ports,
        }
        try:
            lease(open_ports, open_tls_ports)
        except Exception:
            state.update(
                healthy=False,
                degraded=True,
                public_ports=[],
                tls_ports=[],
                error="LEASE_UPDATE_FAILED",
            )
            for row in states:
                row["ingress_open"] = False
            try:
                lease([], [])
            except Exception:
                pass
        record_event(previous, state)
        write(BASE / "guard.json", json.dumps(state).encode())


if __name__ == "__main__":
    if sys.argv[1:] == ["check"]:
        # Credentials enter over stdin, never process arguments or logs.
        raw = sys.stdin.buffer.read(131073)
        if len(raw) > 131072:
            raise SystemExit(64)
        print(json.dumps(check(json.loads(raw))))
    elif not sys.argv[1:]:
        run()
    else:
        raise SystemExit(64)
