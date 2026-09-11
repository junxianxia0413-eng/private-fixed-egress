import hashlib
import json
import secrets
import sqlite3
import time
from datetime import UTC, date, datetime

from controller.services.database import audit, connect

MAX_DEVICES = 20


def available_exit(db, identifier):
    row = db.execute(
        """SELECT e.*,i.name AS isp_name,i.expected_exit_ip,i.status AS isp_status,
        i.current_exit_ip AS verified_ip,i.expires_on,
        i.tested_at FROM exit_groups e JOIN isp_exits i ON e.isp_id=i.id WHERE e.id=?""",
        (identifier,),
    ).fetchone()
    if (
        not row
        or not row["applied"]
        or row["isp_status"] not in ("HEALTHY", "CHECKING")
        or row["verified_ip"] != row["expected_exit_ip"]
        or (row["expires_on"] and date.fromisoformat(row["expires_on"]) < datetime.now(UTC).date())
        or not row["tested_at"]
        or time.time() - row["tested_at"] > 120
    ):
        raise ValueError("请选择已经应用且 ISP 最近检测正常的出口线路。")
    return row


def form_values(data, key):
    raw = data.getlist(key) if hasattr(data, "getlist") else data.get(key, [])
    if isinstance(raw, str):
        return [raw]
    return list(raw) if isinstance(raw, (list, tuple)) else []


def member_fields(data):
    names = [value.strip() for value in form_values(data, "device_name")]
    raw_ids = form_values(data, "device_id")
    if not 1 <= len(names) <= MAX_DEVICES or any(not name or len(name) > 64 for name in names):
        raise ValueError("订阅组需要 1–20 台设备，每个名称为 1–64 个字符。")
    if len({name.casefold() for name in names}) != len(names):
        raise ValueError("同一订阅组内的设备名称不能重复。")
    if raw_ids and len(raw_ids) != len(names):
        raise ValueError("设备信息不完整，请刷新页面后重试。")
    raw_ids.extend([""] * (len(names) - len(raw_ids)))
    identifiers = []
    for value in raw_ids[: len(names)]:
        try:
            identifiers.append(int(value) if value else None)
        except (TypeError, ValueError):
            raise ValueError("设备标识无效，请刷新页面后重试。") from None
    return list(zip(identifiers, names, strict=True))


def resolve_members(db, fields, actor, group_id=None):
    current = {
        row[0]
        for row in db.execute(
            "SELECT device_id FROM group_devices WHERE group_id=?", (group_id,)
        ).fetchall()
    }
    members = []
    for supplied_id, name in fields:
        if supplied_id is not None and supplied_id not in current:
            raise ValueError("设备归属已变化，请刷新页面后重试。")
        existing = db.execute("SELECT id FROM devices WHERE name=?", (name,)).fetchone()
        if existing:
            device_id = existing["id"]
        elif supplied_id is not None:
            before = db.execute("SELECT name FROM devices WHERE id=?", (supplied_id,)).fetchone()
            db.execute("UPDATE devices SET name=? WHERE id=?", (name, supplied_id))
            device_id = supplied_id
            audit(
                db,
                actor,
                "device.renamed.inline",
                json.dumps(
                    {"device_id": device_id, "before": before["name"], "after": name},
                    ensure_ascii=False,
                ),
            )
        else:
            device_id = db.execute(
                """INSERT INTO devices(name,type,platform,purpose,notes,created_at)
                VALUES (?,'Phone','iOS','','',?)""",
                (name, int(time.time())),
            ).lastrowid
            audit(
                db,
                actor,
                "device.created.inline",
                json.dumps({"device_id": device_id, "name": name}, ensure_ascii=False),
            )
        if device_id in members:
            raise ValueError("同一台设备不能在订阅组中重复出现。")
        members.append(device_id)
    return members


def register(settings, data, actor):
    name = data.get("name", "").strip()
    if not 1 <= len(name) <= 64:
        raise ValueError("组名称需为 1–64 个字符。")
    try:
        exit_id = int(data.get("exit_id", ""))
    except ValueError:
        raise ValueError("请选择固定出口。") from None
    fields = member_fields(data)
    try:
        with connect(settings.database_path) as db:
            db.execute("BEGIN IMMEDIATE")
            available_exit(db, exit_id)
            members = resolve_members(db, fields, actor)
            identifier = db.execute(
                "INSERT INTO subscription_groups(name,exit_id,created_at) VALUES (?,?,?)",
                (name, exit_id, int(time.time())),
            ).lastrowid
            for slot, device in enumerate(members, 1):
                db.execute(
                    "INSERT INTO group_devices(device_id,group_id,slot) VALUES (?,?,?)",
                    (device, identifier, slot),
                )
            audit(
                db,
                actor,
                "group.created",
                json.dumps({"group_id": identifier, "exit_id": exit_id, "devices": members}),
            )
            return identifier
    except sqlite3.IntegrityError:
        raise ValueError("组名称已存在，或所选设备已经属于其他订阅组。") from None


def update(settings, identifier, data, actor):
    name = data.get("name", "").strip()
    if not 1 <= len(name) <= 64:
        raise ValueError("组名称需为 1–64 个字符。")
    fields = member_fields(data)
    try:
        with connect(settings.database_path) as db:
            db.execute("BEGIN IMMEDIATE")
            group = db.execute(
                "SELECT id,name FROM subscription_groups WHERE id=?", (identifier,)
            ).fetchone()
            if not group:
                raise ValueError("未找到订阅组。")
            before = [
                dict(row)
                for row in db.execute(
                    """SELECT d.id,d.name FROM group_devices m JOIN devices d ON d.id=m.device_id
                    WHERE m.group_id=? ORDER BY m.slot""",
                    (identifier,),
                )
            ]
            members = resolve_members(db, fields, actor, identifier)
            db.execute("UPDATE subscription_groups SET name=? WHERE id=?", (name, identifier))
            db.execute("DELETE FROM group_devices WHERE group_id=?", (identifier,))
            for slot, device in enumerate(members, 1):
                db.execute(
                    "INSERT INTO group_devices(device_id,group_id,slot) VALUES (?,?,?)",
                    (device, identifier, slot),
                )
            audit(
                db,
                actor,
                "group.updated",
                json.dumps(
                    {
                        "group_id": identifier,
                        "before": {"name": group["name"], "devices": before},
                        "after": {"name": name, "devices": members},
                    },
                    ensure_ascii=False,
                ),
            )
    except sqlite3.IntegrityError:
        raise ValueError("组名称已存在，或所选设备已经属于其他订阅组。") from None


def snapshot(settings):
    with connect(settings.database_path) as db:
        rows = [
            dict(r)
            for r in db.execute("""SELECT s.id,s.name,s.exit_id,s.state,s.created_at,
            e.name AS exit_name,e.gateway_id,
            i.name AS isp_name,i.expected_exit_ip FROM subscription_groups s
            JOIN exit_groups e ON s.exit_id=e.id JOIN isp_exits i ON e.isp_id=i.id ORDER BY s.id""")
        ]
        for row in rows:
            row["devices"] = [
                dict(r)
                for r in db.execute(
                    """SELECT d.id,d.name FROM group_devices m
                JOIN devices d ON m.device_id=d.id WHERE m.group_id=? ORDER BY m.slot""",
                    (row["id"],),
                )
            ]
    return rows


def prepare_change(settings, identifier, new_exit_id, actor):
    try:
        new_exit_id = int(new_exit_id)
    except ValueError:
        raise ValueError("请选择新出口。") from None
    token = secrets.token_urlsafe(32)
    with connect(settings.database_path) as db:
        db.execute("BEGIN IMMEDIATE")
        group = db.execute("SELECT * FROM subscription_groups WHERE id=?", (identifier,)).fetchone()
        if not group:
            raise ValueError("未找到订阅组。")
        old = db.execute(
            """SELECT e.*,i.name AS isp_name,i.expected_exit_ip FROM exit_groups e
            JOIN isp_exits i ON e.isp_id=i.id WHERE e.id=?""",
            (group["exit_id"],),
        ).fetchone()
        new = available_exit(db, new_exit_id)
        if old["id"] == new["id"]:
            raise ValueError("新旧出口相同。")
        if old["gateway_id"] != new["gateway_id"]:
            raise ValueError("当前版本支持同一网关内切换 ISP；跨网关迁移尚未开放。")
        db.execute(
            "DELETE FROM group_confirmations WHERE expires_at<? OR group_id=?",
            (int(time.time()), identifier),
        )
        db.execute(
            """INSERT INTO group_confirmations
            (token_hash,group_id,old_exit_id,new_exit_id,actor,expires_at)
            VALUES (?,?,?,?,?,?)""",
            (
                hashlib.sha256(token.encode()).hexdigest(),
                identifier,
                old["id"],
                new["id"],
                actor,
                int(time.time()) + 300,
            ),
        )
        return {
            "token": token,
            "group_id": identifier,
            "name": group["name"],
            "old": dict(old),
            "new": dict(new),
        }


def confirm_change(settings, identifier, token, actor):
    with connect(settings.database_path) as db:
        db.execute("BEGIN IMMEDIATE")
        row = db.execute(
            "SELECT * FROM group_confirmations WHERE token_hash=?",
            (hashlib.sha256(token.encode()).hexdigest(),),
        ).fetchone()
        group = db.execute("SELECT * FROM subscription_groups WHERE id=?", (identifier,)).fetchone()
        if (
            not row
            or not group
            or row["group_id"] != identifier
            or row["actor"] != actor
            or row["expires_at"] < time.time()
            or row["old_exit_id"] != group["exit_id"]
        ):
            raise ValueError("确认已过期或绑定已变化，请重新选择。")
        new = available_exit(db, row["new_exit_id"])
        if db.execute(
            "SELECT 1 FROM exit_jobs WHERE gateway_id=? AND state IN ('QUEUED','RUNNING')",
            (new["gateway_id"],),
        ).fetchone():
            raise ValueError("网关配置处理中，请稍后重新确认。")
        old = db.execute(
            """SELECT e.isp_id,i.name,i.expected_exit_ip FROM exit_groups e
            JOIN isp_exits i ON e.isp_id=i.id WHERE e.id=?""",
            (row["old_exit_id"],),
        ).fetchone()
        db.execute(
            "UPDATE subscription_groups SET exit_id=?,state='PENDING' WHERE id=?",
            (row["new_exit_id"], identifier),
        )
        db.execute("DELETE FROM group_confirmations WHERE group_id=?", (identifier,))
        if group["client_ref"]:
            from controller.services.subscriptions import queue

            queue(db, identifier, actor)
        audit(
            db,
            actor,
            "group.binding.confirmed",
            json.dumps(
                {
                    "group_id": identifier,
                    "old_exit_id": row["old_exit_id"],
                    "new_exit_id": row["new_exit_id"],
                    "old_isp": old["name"],
                    "old_ip": old["expected_exit_ip"],
                    "new_isp": new["isp_name"],
                    "new_ip": new["expected_exit_ip"],
                },
                ensure_ascii=False,
            ),
        )
        return new["id"]
