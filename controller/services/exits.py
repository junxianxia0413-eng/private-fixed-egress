import json
import re
import secrets
import sqlite3
import time
from datetime import UTC, date, datetime

from controller.services.database import audit, connect
from controller.services.secrets import SecretStore
from gateways.configuration import validate
from gateways.remote_probe import endpoint
from gateways.ssh import GatewayError, connect_gateway, execute


def register(settings, data, actor):
    name = data.get("name", "").strip()
    if not 1 <= len(name) <= 64:
        raise ValueError("名称需为 1–64 个字符。")
    try:
        gateway_id, isp_id = int(data.get("gateway_id", "")), int(data.get("isp_id", ""))
    except ValueError:
        raise ValueError("请选择网关与 ISP。") from None
    store = SecretStore(settings.secret_directory)
    reference = store.put({"username": "pfem", "password": secrets.token_urlsafe(32)})
    try:
        with connect(settings.database_path) as db:
            db.execute("BEGIN IMMEDIATE")
            gateway = db.execute("SELECT * FROM gateways WHERE id=?", (gateway_id,)).fetchone()
            isp = db.execute("SELECT * FROM isp_exits WHERE id=?", (isp_id,)).fetchone()
            if not gateway or gateway["bootstrap_ref"]:
                raise ValueError("请先完成网关部署。")
            if (
                not isp
                or isp["status"] != "HEALTHY"
                or not isp["tested_at"]
                or time.time() - isp["tested_at"] > 120
                or not isp["expected_exit_ip"]
                or isp["expected_exit_ip"] != isp["current_exit_ip"]
            ):
                raise ValueError("ISP 必须有最近两分钟内通过的固定出口检测。")
            count = db.execute(
                "SELECT COUNT(*) FROM exit_groups WHERE gateway_id=?", (gateway_id,)
            ).fetchone()[0]
            if count >= 20:
                raise ValueError("当前每台网关最多 20 个出口组。")
            row = db.execute(
                """INSERT INTO exit_groups(name,gateway_id,isp_id,secret_ref,created_at)
                VALUES (?,?,?,?,?)""",
                (name, gateway_id, isp_id, reference, int(time.time())),
            )
            audit(db, actor, "exit.created", f"group_id={row.lastrowid}")
            return row.lastrowid
    except Exception as exc:
        store.delete(reference)
        if isinstance(exc, sqlite3.IntegrityError):
            raise ValueError("该名称已存在或出口组数量超过限制。") from None
        raise


def enqueue(settings, group_id, actor):
    try:
        with connect(settings.database_path) as db:
            db.execute("BEGIN IMMEDIATE")
            group = db.execute("SELECT * FROM exit_groups WHERE id=?", (group_id,)).fetchone()
            if not group:
                raise ValueError("未找到出口组。")
            row = db.execute(
                """INSERT INTO exit_jobs(group_id,gateway_id,actor,transaction_id,created_at)
                VALUES (?,?,?,?,?)""",
                (group_id, group["gateway_id"], actor, secrets.token_hex(16), int(time.time())),
            )
            audit(db, actor, "exit.apply.queued", f"group_id={group_id}")
            return row.lastrowid
    except sqlite3.IntegrityError:
        raise ValueError("该网关已有配置任务，请稍后重试。") from None


def snapshot(settings):
    with connect(settings.database_path) as db:
        rows = db.execute("""SELECT e.id,e.name,e.status,e.last_error,e.current_exit_ip,
            e.checked_at,e.latency_ms,e.applied,g.name AS gateway_name,i.name AS isp_name,
            i.expected_exit_ip,i.status AS isp_status FROM exit_groups e
            JOIN gateways g ON e.gateway_id=g.id JOIN isp_exits i ON e.isp_id=i.id
            ORDER BY e.id""").fetchall()
        active = {
            r[0]
            for r in db.execute(
                "SELECT group_id FROM exit_jobs WHERE state IN ('QUEUED','RUNNING')"
            )
        }
        jobs = [
            dict(r)
            for r in db.execute("""SELECT j.id,e.name,j.state,j.stage,j.error
            FROM exit_jobs j JOIN exit_groups e ON e.id=j.group_id ORDER BY j.id DESC LIMIT 30""")
        ]
    values = []
    for row in rows:
        value = dict(row)
        value["busy"] = row["id"] in active
        value["last_check"] = (
            datetime.fromtimestamp(row["checked_at"], UTC).strftime("%m-%d %H:%M:%S UTC")
            if row["checked_at"]
            else "尚未验证"
        )
        if value["status"] == "HEALTHY" and (
            not row["checked_at"] or time.time() - row["checked_at"] > 300
        ):
            value["status"] = "UNKNOWN"
        if value["applied"] and value["isp_status"] == "CRITICAL":
            value["status"] = "CRITICAL"
        values.append(value)
    return values, jobs


def desired(settings, job):
    store = SecretStore(settings.secret_directory)
    with connect(settings.database_path) as db:
        gateway = dict(
            db.execute("SELECT * FROM gateways WHERE id=?", (job["gateway_id"],)).fetchone()
        )
        rows = db.execute(
            """SELECT e.*,i.host,i.port,i.secret_ref AS isp_secret,
            i.expected_exit_ip,i.status AS isp_status,i.current_exit_ip AS isp_current,i.tested_at,
            i.expires_on
            FROM exit_groups e JOIN isp_exits i ON e.isp_id=i.id
            WHERE e.gateway_id=? AND (e.applied=1 OR e.id=?) ORDER BY e.id""",
            (job["gateway_id"], job["group_id"]),
        ).fetchall()
        clients = db.execute(
            """SELECT s.id,s.exit_id,s.client_ref FROM subscription_groups s
            JOIN exit_groups e ON s.exit_id=e.id
            WHERE e.gateway_id=? AND s.client_ref IS NOT NULL""",
            (job["gateway_id"],),
        ).fetchall()
    groups = []
    today = datetime.now(UTC).date()
    for row in rows:
        if not row["expected_exit_ip"]:
            raise GatewayError("ISP 尚未取得固定出口身份。")
        expired = bool(row["expires_on"] and date.fromisoformat(row["expires_on"]) < today)
        identity_changed = bool(
            row["isp_current"] and row["isp_current"] != row["expected_exit_ip"]
        )
        target_ready = bool(
            row["isp_status"] == "HEALTHY"
            and row["isp_current"] == row["expected_exit_ip"]
            and row["tested_at"]
            and time.time() - row["tested_at"] <= 300
            and not expired
        )
        if row["id"] == job["group_id"] and not target_ready:
            raise GatewayError("目标 ISP 检测不正常，请先检测 ISP。")
        # An existing route keeps running through a temporary probe failure or stale
        # dashboard sample. Only a confirmed identity change or expiry disables it.
        enabled = (
            target_ready
            if row["id"] == job["group_id"]
            else bool(row["applied"] and not identity_changed and not expired)
        )
        credentials = store.get(row["isp_secret"])
        probe = store.get(row["secret_ref"])
        # Pin a public upstream IP before rendering both core and firewall rules.
        server = endpoint(row["host"])
        groups.append(
            {
                "id": row["id"],
                "enabled": bool(enabled),
                "server": server,
                "port": row["port"],
                **credentials,
                "expected_ip": row["expected_exit_ip"],
                "expires_on": row["expires_on"],
                "probe_username": probe["username"],
                "probe_password": probe["password"],
                "clients": [
                    {"id": c["id"], "password": store.get(c["client_ref"])["password"]}
                    for c in clients
                    if c["exit_id"] == row["id"]
                ],
            }
        )
    validate(groups)
    return gateway, groups


def apply_remote(settings, gateway, groups, transaction, stage):
    store = SecretStore(settings.secret_directory)
    with connect_gateway(gateway, "proxyadmin", store.get(gateway["managed_ref"])) as client:
        stage("APPLYING")
        report = json.loads(
            execute(
                client,
                "sudo -n /usr/local/sbin/pfem-gateway-admin apply-config",
                stdin=json.dumps({"transaction": transaction, "groups": groups}).encode(),
                timeout=110,
            )
        )
        if report.get("ok") is not True:
            if report.get("rolled_back") is True:
                reason = str(report.get("error", ""))
                match = re.fullmatch(r"EXIT_(CHECK_FAILED|IP_MISMATCH):(\d{1,4})", reason)
                if match:
                    detail = (
                        "连接超时或请求失败" if match[1] == "CHECK_FAILED" else "出口 IP 不匹配"
                    )
                    raise GatewayError(
                        f"出口线路 #{match[2]} {detail}；已恢复旧配置，请先检测对应 ISP。"
                    )
                raise GatewayError("新配置未通过出口验证，已恢复旧配置。")
            raise GatewayError("配置操作失败或回滚待确认；请检查网关，禁止当作正常出口使用。")
        expected = {g["id"]: g["expected_ip"] for g in groups if g["enabled"]}
        results = {r["id"]: r for r in report["results"]}
        if report.get("transaction") != transaction or set(results) != set(expected):
            raise GatewayError("配置验证结果不完整，等待服务器自动回滚。")
        if any(results[k]["exit_ip"] != v for k, v in expected.items()):
            raise GatewayError("最终出口不匹配，等待服务器自动回滚。")
        stage("CONFIRMING")
        confirmed = json.loads(
            execute(
                client,
                "sudo -n /usr/local/sbin/pfem-gateway-admin commit-config",
                stdin=json.dumps({"transaction": transaction}).encode(),
            )
        )
        if confirmed.get("ok") is not True or confirmed.get("transaction") != transaction:
            raise GatewayError("配置确认失败，请检测后重试。")
        return results, report.get("config_hash")


def recover(db):
    for row in db.execute("SELECT * FROM exit_jobs WHERE state='RUNNING'").fetchall():
        db.execute(
            "UPDATE exit_jobs SET state='FAILED',error=?,finished_at=? WHERE id=?",
            ("控制台重启中断配置，请等待远程回滚并重新验证。", int(time.time()), row["id"]),
        )
        db.execute(
            "UPDATE exit_groups SET status='UNKNOWN',last_error=? WHERE id=?",
            ("配置任务中断，旧配置由服务器自动恢复，请重新验证当前线路。", row["group_id"]),
        )
        audit(db, "system", "exit.apply.interrupted", f"group_id={row['group_id']}")


def run_next(settings):
    with connect(settings.database_path) as db:
        db.execute("BEGIN IMMEDIATE")
        found = db.execute(
            "SELECT * FROM exit_jobs WHERE state='QUEUED' ORDER BY id LIMIT 1"
        ).fetchone()
        if not found:
            return False
        job = dict(found)
        db.execute(
            "UPDATE exit_jobs SET state='RUNNING',stage='PREPARING' WHERE id=?", (job["id"],)
        )
        db.execute(
            "UPDATE exit_groups SET status='APPLYING',last_error='' WHERE id=?", (job["group_id"],)
        )

    def stage(value):
        with connect(settings.database_path) as db:
            db.execute("UPDATE exit_jobs SET stage=? WHERE id=?", (value, job["id"]))

    try:
        gateway, groups = desired(settings, job)
        results, digest = apply_remote(settings, gateway, groups, job["transaction_id"], stage)
        with connect(settings.database_path) as db:
            for group in groups:
                result = results.get(group["id"], {})
                db.execute(
                    """UPDATE exit_groups SET applied=1,status=?,last_error=?,current_exit_ip=?,
                    latency_ms=?,checked_at=?,config_hash=? WHERE id=?""",
                    (
                        "HEALTHY" if group["enabled"] else "CRITICAL",
                        "" if group["enabled"] else "ISP 异常，路由已关闭。",
                        result.get("exit_ip"),
                        result.get("latency_ms"),
                        int(time.time()),
                        digest,
                        group["id"],
                    ),
                )
                for client in group.get("clients", []):
                    db.execute(
                        """UPDATE subscription_groups SET state=?,deployed_exit_id=?
                        WHERE id=? AND exit_id=?""",
                        (
                            "READY" if group["enabled"] else "PENDING",
                            group["id"],
                            client["id"],
                            group["id"],
                        ),
                    )
                    audit(
                        db,
                        job["actor"],
                        "subscription.applied",
                        f"group_id={client['id']};exit_id={group['id']}",
                    )
            db.execute(
                "UPDATE exit_jobs SET state='SUCCEEDED',stage='COMPLETE',finished_at=? WHERE id=?",
                (int(time.time()), job["id"]),
            )
            audit(db, job["actor"], "exit.apply.succeeded", f"group_id={job['group_id']}")
    except Exception as exc:
        error = str(exc) if isinstance(exc, GatewayError) else "出口组配置异常，请检测后重试。"
        with connect(settings.database_path) as db:
            previous = db.execute(
                "SELECT applied,current_exit_ip FROM exit_groups WHERE id=?", (job["group_id"],)
            ).fetchone()
            old_route_working = bool(
                previous and previous["applied"] and previous["current_exit_ip"]
            )
            if old_route_working:
                db.execute(
                    "UPDATE exit_groups SET status='HEALTHY',last_error=? WHERE id=?",
                    (f"新配置失败，旧配置继续运行：{error}", job["group_id"]),
                )
            else:
                db.execute(
                    "UPDATE subscription_groups SET state='PENDING' WHERE exit_id=?",
                    (job["group_id"],),
                )
                db.execute(
                    "UPDATE exit_groups SET status='CONFIG_FAILED',last_error=? WHERE id=?",
                    (error, job["group_id"]),
                )
            db.execute(
                "UPDATE exit_jobs SET state='FAILED',error=?,finished_at=? WHERE id=?",
                (error, int(time.time()), job["id"]),
            )
            audit(db, job["actor"], "exit.apply.failed", f"group_id={job['group_id']}")
    return True
