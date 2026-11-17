import json
import sqlite3
import time

from controller.services.database import audit, connect

FIELDS = {"name": 64, "type": 40, "platform": 40, "purpose": 120, "notes": 1000}


def save(settings, data, actor, identifier=None):
    values = {key: data.get(key, "").strip() for key in FIELDS}
    if any(len(values[key]) > limit for key, limit in FIELDS.items()) or not values["name"]:
        raise ValueError("请填写设备名称，并检查各字段长度。")
    if not values["platform"]:
        raise ValueError("请填写设备系统，例如 iOS。")
    try:
        with connect(settings.database_path) as db:
            db.execute("BEGIN IMMEDIATE")
            old = None
            if identifier is not None:
                old = db.execute("SELECT * FROM devices WHERE id=?", (identifier,)).fetchone()
                if not old:
                    raise ValueError("未找到设备。")
                db.execute(
                    "UPDATE devices SET name=?,type=?,platform=?,purpose=?,notes=? WHERE id=?",
                    (*values.values(), identifier),
                )
            else:
                identifier = db.execute(
                    """INSERT INTO devices(name,type,platform,purpose,notes,created_at)
                    VALUES (?,?,?,?,?,?)""",
                    (*values.values(), int(time.time())),
                ).lastrowid
            audit(
                db,
                actor,
                "device.updated" if old else "device.created",
                json.dumps(
                    {
                        "device_id": identifier,
                        "before": dict(old) if old else None,
                        "after": values,
                    },
                    ensure_ascii=False,
                ),
            )
            return identifier
    except sqlite3.IntegrityError:
        raise ValueError("该设备名称已存在。") from None


def snapshot(settings):
    with connect(settings.database_path) as db:
        return [
            dict(row)
            for row in db.execute(
                """SELECT d.*, COALESCE(s.display_name,s.name) AS group_name
                FROM devices d LEFT JOIN group_devices m ON d.id=m.device_id
                LEFT JOIN subscription_groups s ON s.id=m.group_id
                ORDER BY d.display_order=0,d.display_order,d.id"""
            )
        ]


def delete(settings, identifier, actor):
    with connect(settings.database_path) as db:
        db.execute("BEGIN IMMEDIATE")
        row = db.execute("SELECT name FROM devices WHERE id=?", (identifier,)).fetchone()
        if not row:
            raise ValueError("未找到设备。")
        db.execute("DELETE FROM group_devices WHERE device_id=?", (identifier,))
        db.execute("DELETE FROM devices WHERE id=?", (identifier,))
        audit(db, actor, "device.deleted", json.dumps({"id": identifier, "name": row["name"]}))
