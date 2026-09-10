import time
from datetime import UTC, date, datetime

from controller.services.database import connect


def _conditions(db, now):
    conditions = []
    for row in db.execute("SELECT id,name,status,last_error,checked_at FROM gateways"):
        if row["status"] in {"CRITICAL", "UNKNOWN"}:
            conditions.append(
                (
                    "gateway",
                    f"gateway:{row['id']}",
                    "CRITICAL",
                    f"网关 {row['name']} 异常",
                    row["last_error"] or "网关检查未通过。",
                )
            )
    for row in db.execute("SELECT id,name,status,last_error,expires_on FROM isp_exits"):
        if row["status"] in {"CRITICAL", "UNKNOWN"}:
            conditions.append(
                (
                    "isp",
                    f"isp:{row['id']}",
                    "CRITICAL",
                    f"ISP {row['name']} 异常",
                    row["last_error"] or "ISP 检查未通过。",
                )
            )
        if row["expires_on"]:
            days = (date.fromisoformat(row["expires_on"]) - datetime.now(UTC).date()).days
            if days in (1, 3, 7):
                conditions.append(
                    (
                        "expiry",
                        f"expiry:{row['id']}:{days}",
                        "WARNING",
                        f"ISP {row['name']} 将在 {days} 天后到期",
                        "请确认服务商续期状态。",
                    )
                )
            elif days < 0:
                conditions.append(
                    (
                        "expiry",
                        f"expiry:{row['id']}:expired",
                        "CRITICAL",
                        f"ISP {row['name']} 已到期",
                        "入口保护会阻止不再有效的线路。",
                    )
                )
    for row in db.execute("SELECT id,name,status,last_error FROM exit_groups"):
        if row["status"] in {"CRITICAL", "UNKNOWN"}:
            conditions.append(
                (
                    "exit",
                    f"exit:{row['id']}",
                    "CRITICAL",
                    f"出口线路 {row['name']} 异常",
                    row["last_error"] or "线路检查未通过。",
                )
            )
    return conditions


def sync(settings):
    now = int(time.time())
    with connect(settings.database_path) as db:
        db.execute("BEGIN IMMEDIATE")
        conditions = _conditions(db, now)
        active = {
            row["fingerprint"]: row
            for row in db.execute("SELECT * FROM alerts WHERE resolved_at IS NULL")
        }
        seen = set()
        for kind, fingerprint, severity, title, detail in conditions:
            seen.add(fingerprint)
            if fingerprint in active:
                db.execute(
                    "UPDATE alerts SET severity=?,title=?,detail=?,last_seen=? WHERE id=?",
                    (severity, title, detail, now, active[fingerprint]["id"]),
                )
            else:
                db.execute(
                    """INSERT INTO alerts
                    (kind,fingerprint,severity,title,detail,first_seen,last_seen)
                    VALUES (?,?,?,?,?,?,?)""",
                    (kind, fingerprint, severity, title, detail, now, now),
                )
        for fingerprint, row in active.items():
            if fingerprint not in seen:
                db.execute(
                    "UPDATE alerts SET resolved_at=?,last_seen=? WHERE id=?", (now, now, row["id"])
                )


def snapshot(settings, include_resolved=False, page=1):
    sync(settings)
    page = max(1, min(page, 1000))
    limit, offset = 50, (page - 1) * 50
    with connect(settings.database_path) as db:
        where = "" if include_resolved else "WHERE resolved_at IS NULL"
        rows = [
            dict(row)
            for row in db.execute(
                f"SELECT * FROM alerts {where} ORDER BY resolved_at IS NULL DESC,"
                "last_seen DESC LIMIT ? OFFSET ?",
                (limit, offset),
            )
        ]
    for row in rows:
        row["first_time"] = datetime.fromtimestamp(row["first_seen"], UTC).strftime(
            "%Y-%m-%d %H:%M UTC"
        )
        row["last_time"] = datetime.fromtimestamp(row["last_seen"], UTC).strftime(
            "%Y-%m-%d %H:%M UTC"
        )
        row["resolved_time"] = (
            datetime.fromtimestamp(row["resolved_at"], UTC).strftime("%Y-%m-%d %H:%M UTC")
            if row["resolved_at"]
            else None
        )
    return rows
