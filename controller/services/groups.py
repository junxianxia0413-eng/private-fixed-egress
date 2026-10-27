import hashlib
import json
import secrets
import sqlite3
import time
from datetime import UTC, date, datetime

from controller.services.database import audit, connect
from controller.services.secrets import SecretStore

MAX_DEVICES = 20
AI_PROVIDERS = {"ANTHROPIC", "OPENAI", "GEMINI"}


def available_exit(db, identifier):
    row = db.execute(
        """SELECT e.*,COALESCE(i.name,'VPS 自带公网 IP') AS isp_name,
        COALESCE(i.expected_exit_ip,e.direct_expected_ip) AS expected_exit_ip,
        i.status AS isp_status,i.current_exit_ip AS verified_ip,i.expires_on,
        i.tested_at FROM exit_groups e LEFT JOIN isp_exits i ON e.isp_id=i.id WHERE e.id=?""",
        (identifier,),
    ).fetchone()
    direct_ready = bool(
        row
        and row["exit_type"] == "GATEWAY_DIRECT"
        and row["applied"]
        and row["status"] == "HEALTHY"
        and row["current_exit_ip"] == row["direct_expected_ip"]
    )
    isp_ready = bool(
        row
        and row["exit_type"] == "ISP_PROXY"
        and row["applied"]
        and row["isp_status"] in ("HEALTHY", "CHECKING")
        and row["verified_ip"] == row["expected_exit_ip"]
        and not (
            row["expires_on"] and date.fromisoformat(row["expires_on"]) < datetime.now(UTC).date()
        )
        and row["tested_at"]
        and time.time() - row["tested_at"] <= 120
    )
    if not (direct_ready or isp_ready):
        raise ValueError("请选择已经应用且最近检测正常的出口线路。")
    return row


def form_values(data, key):
    raw = data.getlist(key) if hasattr(data, "getlist") else data.get(key, [])
    if isinstance(raw, str):
        return [raw]
    return list(raw) if isinstance(raw, (list, tuple)) else []


def ai_selection(db, data, primary, current=None):
    if "ai_exit_id" not in data and current is not None:
        return current["ai_exit_id"], json.loads(current["ai_providers"])
    raw_exit = str(data.get("ai_exit_id", "")).strip()
    providers = [value.strip().upper() for value in form_values(data, "ai_provider")]
    if not raw_exit:
        if providers:
            raise ValueError("启用 AI 提供商前请先选择 AI 专用出口。")
        return None, []
    try:
        ai_exit_id = int(raw_exit)
    except ValueError:
        raise ValueError("请选择有效的 AI 专用出口。") from None
    if (
        not providers
        or len(providers) != len(set(providers))
        or any(provider not in AI_PROVIDERS for provider in providers)
    ):
        raise ValueError("请选择至少一个有效的 AI 提供商。")
    ai_exit = available_exit(db, ai_exit_id)
    if ai_exit["gateway_id"] != primary["gateway_id"]:
        raise ValueError("AI 专用出口必须与主出口位于同一网关。")
    return ai_exit_id, providers


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
            primary = available_exit(db, exit_id)
            ai_exit_id, ai_providers = ai_selection(db, data, primary)
            members = resolve_members(db, fields, actor)
            identifier = db.execute(
                """INSERT INTO subscription_groups
                (name,exit_id,ai_exit_id,ai_providers,created_at) VALUES (?,?,?,?,?)""",
                (name, exit_id, ai_exit_id, json.dumps(ai_providers), int(time.time())),
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
                json.dumps(
                    {
                        "group_id": identifier,
                        "exit_id": exit_id,
                        "ai_exit_id": ai_exit_id,
                        "ai_providers": ai_providers,
                        "devices": members,
                    }
                ),
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
                "SELECT * FROM subscription_groups WHERE id=?", (identifier,)
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
            primary = available_exit(db, group["exit_id"])
            ai_exit_id, ai_providers = ai_selection(db, data, primary, group)
            ai_changed = (
                group["ai_exit_id"] != ai_exit_id
                or json.loads(group["ai_providers"]) != ai_providers
            )
            db.execute(
                """UPDATE subscription_groups SET name=?,ai_exit_id=?,ai_providers=?,
                state=CASE WHEN ai_exit_id IS ? AND ai_providers=? THEN state ELSE 'PENDING' END
                WHERE id=?""",
                (
                    name,
                    ai_exit_id,
                    json.dumps(ai_providers),
                    ai_exit_id,
                    json.dumps(ai_providers),
                    identifier,
                ),
            )
            db.execute("DELETE FROM group_devices WHERE group_id=?", (identifier,))
            for slot, device in enumerate(members, 1):
                db.execute(
                    "INSERT INTO group_devices(device_id,group_id,slot) VALUES (?,?,?)",
                    (device, identifier, slot),
                )
            if ai_changed and group["client_ref"]:
                from controller.services.subscriptions import queue

                queue(db, identifier, actor)
            audit(
                db,
                actor,
                "group.updated",
                json.dumps(
                    {
                        "group_id": identifier,
                        "before": {"name": group["name"], "devices": before},
                        "after": {
                            "name": name,
                            "devices": members,
                            "ai_exit_id": ai_exit_id,
                            "ai_providers": ai_providers,
                        },
                    },
                    ensure_ascii=False,
                ),
            )
    except sqlite3.IntegrityError:
        raise ValueError("组名称已存在，或所选设备已经属于其他订阅组。") from None


def delete(settings, identifier, actor):
    from controller.services import exits
    from gateways.ssh import GatewayError

    store = SecretStore(settings.secret_directory)
    with connect(settings.database_path) as db:
        db.execute("BEGIN IMMEDIATE")
        group = db.execute(
            """SELECT s.*,e.gateway_id FROM subscription_groups s
            JOIN exit_groups e ON e.id=s.exit_id WHERE s.id=?""",
            (identifier,),
        ).fetchone()
        if not group:
            raise ValueError("未找到订阅组。")
        if db.execute(
            "SELECT 1 FROM exit_jobs WHERE gateway_id=? AND state IN ('QUEUED','RUNNING')",
            (group["gateway_id"],),
        ).fetchone():
            raise ValueError("网关正在应用配置，请稍后再删除。")
        references = [group[key] for key in ("client_ref", "token_ref") if group[key]]
        needs_remote_removal = bool(group["client_ref"] and group["deployed_exit_id"])
        if not needs_remote_removal:
            db.execute("DELETE FROM group_confirmations WHERE group_id=?", (identifier,))
            db.execute("DELETE FROM group_devices WHERE group_id=?", (identifier,))
            db.execute("DELETE FROM subscription_groups WHERE id=?", (identifier,))
            audit(
                db,
                actor,
                "group.deleted",
                json.dumps({"group_id": identifier, "name": group["name"]}, ensure_ascii=False),
            )
            transaction = None
        else:
            transaction = secrets.token_hex(16)
            job_id = db.execute(
                """INSERT INTO exit_jobs(group_id,gateway_id,actor,transaction_id,state,stage,
                created_at) VALUES (?,?,?,?,'RUNNING','PREPARING',?)""",
                (
                    group["exit_id"],
                    group["gateway_id"],
                    actor,
                    transaction,
                    int(time.time()),
                ),
            ).lastrowid
            audit(db, actor, "group.delete.started", f"group_id={identifier}")
    if not transaction:
        for reference in references:
            store.delete(reference)
        return

    job = {
        "id": job_id,
        "gateway_id": group["gateway_id"],
        "group_id": group["exit_id"],
        "transaction_id": transaction,
    }

    def stage(value):
        with connect(settings.database_path) as db:
            db.execute("UPDATE exit_jobs SET stage=? WHERE id=?", (value, job_id))

    try:
        gateway, desired_groups = exits.desired(settings, job, {identifier})
        results, digest = exits.apply_remote(settings, gateway, desired_groups, transaction, stage)
        with connect(settings.database_path) as db:
            db.execute("BEGIN IMMEDIATE")
            latest = db.execute(
                "SELECT exit_id,client_ref,token_ref FROM subscription_groups WHERE id=?",
                (identifier,),
            ).fetchone()
            if (
                not latest
                or latest["exit_id"] != group["exit_id"]
                or latest["client_ref"] != group["client_ref"]
                or latest["token_ref"] != group["token_ref"]
            ):
                raise ValueError("订阅组已被其他操作修改，请刷新后重试。")
            for configured in desired_groups:
                result = results.get(configured["id"], {})
                db.execute(
                    """UPDATE exit_groups SET status=?,last_error=?,current_exit_ip=?,
                    latency_ms=?,checked_at=?,config_hash=? WHERE id=?""",
                    (
                        "HEALTHY" if configured["enabled"] else "CRITICAL",
                        "" if configured["enabled"] else "ISP 异常，路由已关闭。",
                        result.get("exit_ip"),
                        result.get("latency_ms"),
                        int(time.time()),
                        digest,
                        configured["id"],
                    ),
                )
            db.execute("DELETE FROM group_confirmations WHERE group_id=?", (identifier,))
            db.execute("DELETE FROM group_devices WHERE group_id=?", (identifier,))
            db.execute("DELETE FROM subscription_groups WHERE id=?", (identifier,))
            db.execute(
                """UPDATE exit_jobs SET state='SUCCEEDED',stage='COMPLETE',finished_at=?
                WHERE id=?""",
                (int(time.time()), job_id),
            )
            audit(
                db,
                actor,
                "group.deleted",
                json.dumps({"group_id": identifier, "name": group["name"]}, ensure_ascii=False),
            )
    except Exception as exc:
        error = str(exc) if isinstance(exc, (GatewayError, ValueError)) else "删除配置异常。"
        with connect(settings.database_path) as db:
            db.execute(
                "UPDATE exit_jobs SET state='FAILED',error=?,finished_at=? WHERE id=?",
                (error, int(time.time()), job_id),
            )
            audit(db, actor, "group.delete.failed", f"group_id={identifier}")
        raise ValueError(f"删除失败，原订阅继续保留：{error}") from None
    for reference in references:
        store.delete(reference)


def snapshot(settings):
    with connect(settings.database_path) as db:
        rows = [
            dict(r)
            for r in db.execute("""SELECT s.id,s.name,s.exit_id,s.state,s.created_at,
            s.deployed_exit_id,g.host AS gateway_host,
            e.name AS exit_name,e.gateway_id,e.exit_type,s.ai_exit_id,s.ai_providers,
            e.current_exit_ip AS route_current_ip,e.checked_at AS route_checked_at,
            e.status AS route_status,e.last_error AS route_error,
            previous.name AS deployed_exit_name,previous.current_exit_ip AS deployed_exit_ip,
            (SELECT j.state FROM exit_jobs j WHERE j.gateway_id=e.gateway_id
             AND j.group_id=e.id ORDER BY j.id DESC LIMIT 1) AS apply_state,
            (SELECT j.error FROM exit_jobs j WHERE j.gateway_id=e.gateway_id
             AND j.group_id=e.id ORDER BY j.id DESC LIMIT 1) AS apply_error,
            COALESCE(i.name,'VPS 自带公网 IP') AS isp_name,
            COALESCE(i.expected_exit_ip,e.direct_expected_ip) AS expected_exit_ip,
            ae.name AS ai_exit_name
            FROM subscription_groups s JOIN exit_groups e ON s.exit_id=e.id
            JOIN gateways g ON e.gateway_id=g.id
            LEFT JOIN isp_exits i ON e.isp_id=i.id
            LEFT JOIN exit_groups previous ON s.deployed_exit_id=previous.id
            LEFT JOIN exit_groups ae ON s.ai_exit_id=ae.id ORDER BY s.id""")
        ]
        for row in rows:
            row["applying"] = row["apply_state"] in ("QUEUED", "RUNNING")
            row["binding_applied"] = (
                row["state"] == "READY" and row["exit_id"] == row["deployed_exit_id"]
            )
            row["exit_verified"] = bool(
                row["binding_applied"]
                and row["expected_exit_ip"]
                and row["route_current_ip"] == row["expected_exit_ip"]
                and row["route_status"] == "HEALTHY"
                and row["route_checked_at"]
                and -5 <= time.time() - row["route_checked_at"] <= 120
            )
            row["last_verified"] = (
                datetime.fromtimestamp(row["route_checked_at"], UTC).strftime("%m-%d %H:%M:%S UTC")
                if row["route_checked_at"]
                else "尚未验证"
            )
            row["ai_providers"] = json.loads(row["ai_providers"])
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
            """SELECT e.*,COALESCE(i.name,'VPS 自带公网 IP') AS isp_name,
            COALESCE(i.expected_exit_ip,e.direct_expected_ip) AS expected_exit_ip
            FROM exit_groups e LEFT JOIN isp_exits i ON e.isp_id=i.id WHERE e.id=?""",
            (group["exit_id"],),
        ).fetchone()
        new = available_exit(db, new_exit_id)
        if old["id"] == new["id"]:
            raise ValueError("新旧出口相同。")
        if old["gateway_id"] != new["gateway_id"]:
            raise ValueError("当前版本支持同一网关内切换出口；跨网关迁移尚未开放。")
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
            """SELECT e.isp_id,COALESCE(i.name,'VPS 自带公网 IP') AS name,
            COALESCE(i.expected_exit_ip,e.direct_expected_ip) AS expected_exit_ip
            FROM exit_groups e LEFT JOIN isp_exits i ON e.isp_id=i.id WHERE e.id=?""",
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
