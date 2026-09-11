import json
import math
import time
from datetime import UTC, datetime

from controller.services.database import audit, connect
from controller.services.secrets import SecretStore
from gateways.ssh import connect_gateway, execute


def schedule_due(settings):
    now = int(time.time())
    with connect(settings.database_path) as db:
        db.execute("BEGIN IMMEDIATE")
        gateways = db.execute("""SELECT * FROM gateways WHERE bootstrap_ref IS NULL
            AND NOT EXISTS(SELECT 1 FROM gateway_jobs j WHERE j.gateway_id=gateways.id
            AND j.state IN ('QUEUED','RUNNING'))""").fetchall()
        for gateway in gateways:
            for kind, interval in (("health", 60), ("quality", 300)):
                last = db.execute(
                    "SELECT MAX(created_at) FROM monitor_jobs WHERE gateway_id=? AND kind=?",
                    (gateway["id"], kind),
                ).fetchone()[0]
                if last and now - last < interval:
                    continue
                if db.execute(
                    "SELECT 1 FROM monitor_jobs WHERE gateway_id=? AND kind=? "
                    "AND state IN ('QUEUED','RUNNING')",
                    (gateway["id"], kind),
                ).fetchone():
                    continue
                db.execute(
                    "INSERT INTO monitor_jobs(gateway_id,kind,created_at) VALUES (?,?,?)",
                    (gateway["id"], kind, now),
                )


def recover(db):
    db.execute(
        "UPDATE monitor_jobs SET state='FAILED',error='检查被控制台重启中断' WHERE state='RUNNING'"
    )


def numeric(value, maximum=1e16):
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(value)
        and 0 <= value <= maximum
    )


def probe(settings, gateway, kind):
    store = SecretStore(settings.secret_directory)
    with connect_gateway(gateway, "proxyadmin", store.get(gateway["managed_ref"])) as client:
        report = json.loads(
            execute(
                client,
                "sudo -n /usr/local/sbin/pfem-gateway-admin "
                + ("status" if kind == "health" else "quality"),
                timeout=80,
            )
        )
    if kind == "health":
        required = (
            "healthy",
            "service",
            "config_valid",
            "proxy_port",
            "firewall",
            "ssh_key_only",
            "egress_blocked",
        )
        if not all(type(report.get(k)) is bool for k in required):
            raise ValueError("Invalid health report")
        safe = {k: report[k] for k in required}
        safe["isp_bound"] = report.get("isp_bound") is True
        safe["version"] = str(report.get("version", ""))[:120]
        for key in ("cpu_percent", "ram_percent", "disk_percent"):
            if not numeric(report.get(key), 100):
                raise ValueError("Invalid resource measurement")
            safe[key] = report[key]
        for key in ("rx_bytes", "tx_bytes", "connections", "checked_at"):
            if numeric(report.get(key)):
                safe[key] = report[key]
        guard = report.get("guard", {})
        if not isinstance(guard, dict):
            raise ValueError("Invalid guard report")
        safe["guard"] = {
            k: guard.get(k)
            for k in (
                "healthy",
                "degraded",
                "checked_at",
                "groups",
                "results",
                "public_ports",
                "tls_ports",
            )
        }
        return safe
    if report.get("ok") is not True or not isinstance(report.get("measurements"), list):
        raise ValueError("Invalid quality report")
    values = []
    for row in report["measurements"][:20]:
        value = {
            k: row.get(k)
            for k in (
                "id",
                "samples",
                "tcp_failed",
                "tcp_latency_ms",
                "tcp_jitter_ms",
                "icmp_loss_percent",
                "icmp_received",
                "icmp_sent",
            )
        }
        if not all(v is None or numeric(v) for v in value.values()):
            raise ValueError("Invalid quality measurement")
        values.append(value)
    return {"measurements": values}


def record_health(db, gateway, report, now):
    good = report.get("healthy") is True
    db.execute(
        "UPDATE gateways SET status=?,last_error=?,health_json=?,checked_at=? WHERE id=?",
        (
            "HEALTHY" if good else "CRITICAL",
            "" if good else "定时检查未通过，请检查网关连接或服务。",
            json.dumps(report),
            now,
            gateway["id"],
        ),
    )
    guard = report.get("guard") or {}
    fresh = numeric(guard.get("checked_at")) and -5 <= now - guard["checked_at"] <= 70
    results = {
        r["id"]: r
        for r in guard.get("results") or []
        if isinstance(r, dict) and type(r.get("id")) is int
    }
    rows = db.execute(
        """SELECT e.id,i.expected_exit_ip,i.status AS isp_status FROM exit_groups e
        JOIN isp_exits i ON e.isp_id=i.id WHERE e.gateway_id=? AND e.applied=1""",
        (gateway["id"],),
    ).fetchall()
    for row in rows:
        result = results.get(row["id"], {})
        healthy = (
            good
            and fresh
            and guard.get("healthy") is True
            and result.get("exit_ip") == row["expected_exit_ip"]
            and row["isp_status"] in ("HEALTHY", "CHECKING")
        )
        latency = result.get("latency_ms")
        db.execute(
            "UPDATE exit_groups SET status=?,last_error=?,current_exit_ip=?,"
            "latency_ms=?,checked_at=? WHERE id=?",
            (
                "HEALTHY" if healthy else "CRITICAL",
                "" if healthy else "线路检查失败或入口保护结果已过期。",
                result.get("exit_ip") if healthy else None,
                latency if numeric(latency) else None,
                guard["checked_at"] if fresh else now,
                row["id"],
            ),
        )


def run_next(settings):
    with connect(settings.database_path) as db:
        db.execute("BEGIN IMMEDIATE")
        row = db.execute(
            "SELECT * FROM monitor_jobs WHERE state='QUEUED' ORDER BY kind,id LIMIT 1"
        ).fetchone()
        if not row:
            return False
        job = dict(row)
        gateway = dict(
            db.execute("SELECT * FROM gateways WHERE id=?", (job["gateway_id"],)).fetchone()
        )
        db.execute("UPDATE monitor_jobs SET state='RUNNING' WHERE id=?", (job["id"],))
    error = ""
    try:
        report = probe(settings, gateway, job["kind"])
    except Exception:
        report = {}
        error = "无法取得网关实时检测结果。"
    now = int(time.time())
    with connect(settings.database_path) as db:
        db.execute("BEGIN IMMEDIATE")
        if job["kind"] == "health":
            record_health(db, gateway, report, now)
        healthy = not error and (report.get("healthy") is True if job["kind"] == "health" else True)
        db.execute(
            "INSERT INTO monitor_samples(gateway_id,kind,occurred_at,healthy,data_json) "
            "VALUES (?,?,?,?,?)",
            (gateway["id"], job["kind"], now, int(healthy), json.dumps(report)),
        )
        db.execute(
            "UPDATE monitor_jobs SET state=?,error=?,finished_at=? WHERE id=?",
            ("SUCCEEDED" if healthy else "FAILED", error, now, job["id"]),
        )
        # Keep a bounded month of observations. Audit history is retained separately.
        db.execute("DELETE FROM monitor_samples WHERE occurred_at<?", (now - 30 * 86400,))
        db.execute("DELETE FROM monitor_jobs WHERE finished_at<?", (now - 30 * 86400,))
        if job["kind"] == "health" and gateway["status"] != ("HEALTHY" if healthy else "CRITICAL"):
            audit(
                db,
                "system",
                "gateway.recovered" if healthy else "gateway.down",
                f"gateway_id={gateway['id']}",
            )
    return True


def refresh(settings, actor):
    with connect(settings.database_path) as db:
        db.execute("BEGIN IMMEDIATE")
        for row in db.execute("SELECT id FROM gateways WHERE bootstrap_ref IS NULL"):
            for kind in ("health", "quality"):
                last = db.execute(
                    "SELECT MAX(created_at) FROM monitor_jobs WHERE gateway_id=? AND kind=?",
                    (row["id"], kind),
                ).fetchone()[0]
                if last and time.time() - last < 30:
                    continue
                db.execute(
                    "INSERT OR IGNORE INTO monitor_jobs(gateway_id,kind,created_at) VALUES (?,?,?)",
                    (row["id"], kind, int(time.time())),
                )
        audit(db, actor, "network.check.queued")


def score(measurement, availability):
    latency, jitter, loss = (
        measurement.get(k) for k in ("tcp_latency_ms", "tcp_jitter_ms", "icmp_loss_percent")
    )
    if any(v is None for v in (latency, jitter, loss, availability)):
        return None
    return round(
        0.35 * max(0, 100 - latency * 0.5)
        + 0.25 * max(0, 100 - loss * 10)
        + 0.2 * max(0, 100 - jitter * 5)
        + 0.2 * availability
    )


def snapshot(settings):
    now = int(time.time())
    result = []
    with connect(settings.database_path) as db:
        for gateway in db.execute(
            "SELECT id,name,status,health_json,checked_at FROM gateways ORDER BY id"
        ):
            value = dict(gateway)
            value["health"] = json.loads(value.pop("health_json"))
            last = db.execute(
                "SELECT * FROM monitor_samples WHERE gateway_id=? AND kind='quality' "
                "ORDER BY id DESC LIMIT 1",
                (gateway["id"],),
            ).fetchone()
            value["quality"] = json.loads(last["data_json"]).get("measurements", []) if last else []
            value["quality_stale"] = not last or now - last["occurred_at"] > 600
            availability = db.execute(
                "SELECT AVG(healthy)*100,COUNT(*) FROM monitor_samples WHERE gateway_id=? "
                "AND kind='health' AND occurred_at>=?",
                (gateway["id"], now - 3600),
            ).fetchone()
            value["availability"] = round(availability[0], 1) if availability[1] else None
            value["availability_samples"] = availability[1]
            recent = db.execute(
                "SELECT occurred_at,data_json FROM monitor_samples WHERE gateway_id=? "
                "AND kind='health' AND healthy=1 ORDER BY id DESC LIMIT 2",
                (gateway["id"],),
            ).fetchall()
            value["rx_mbps"] = value["tx_mbps"] = None
            if len(recent) == 2:
                elapsed = recent[0]["occurred_at"] - recent[1]["occurred_at"]
                current, previous = (json.loads(r["data_json"]) for r in recent)
                for direction in ("rx", "tx"):
                    key = direction + "_bytes"
                    if (
                        0 < elapsed <= 180
                        and key in current
                        and key in previous
                        and current[key] >= previous[key]
                    ):
                        value[direction + "_mbps"] = round(
                            (current[key] - previous[key]) * 8 / elapsed / 1e6, 3
                        )
            for row in value["quality"]:
                row["score"] = (
                    score(row, value["availability"]) if not value["quality_stale"] else None
                )
                name = db.execute(
                    "SELECT name FROM exit_groups WHERE id=?", (row["id"],)
                ).fetchone()
                row["name"] = name[0] if name else "未知线路"
            value["last_check"] = (
                datetime.fromtimestamp(value["checked_at"], UTC).strftime("%m-%d %H:%M:%S UTC")
                if value["checked_at"]
                else "尚未检测"
            )
            if not value["checked_at"] or now - value["checked_at"] > 120:
                value["status"] = "UNKNOWN"
                value["health"] = {}
                value["rx_mbps"] = value["tx_mbps"] = None
            result.append(value)
    return result
