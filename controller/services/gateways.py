import io
import ipaddress
import json
import sqlite3
import threading
import time
from datetime import UTC, datetime

import paramiko

from controller.services import exits, isps
from controller.services.database import audit, connect
from controller.services.secrets import SecretStore
from gateways import deployment
from gateways.ssh import GatewayError, fingerprint, generate_key, parse_host_key


def register(settings, data, actor):
    name, location = data.get("name", "").strip(), data.get("location", "").strip()
    if not 1 <= len(name) <= 64 or len(location) > 80:
        raise ValueError("名称需为 1–64 个字符，位置最多 80 个字符。")
    try:
        address = ipaddress.ip_address(data.get("host", ""))
        if address.version != 4 or not address.is_global:
            raise ValueError
        port = int(data.get("ssh_port", "22"))
        if not 1 <= port <= 65535:
            raise ValueError
    except ValueError:
        raise ValueError("请填写公网 IPv4 地址及 1–65535 范围内的 SSH 端口。") from None
    host_key = data.get("host_key", "").strip()
    parse_host_key(host_key)
    if data.get("bootstrap_user", "root") != "root":
        raise ValueError("首次安装需要 root；安装后系统自动使用受限管理账户。")
    credentials = {k: data.get(k, "") for k in ("password", "private_key") if data.get(k)}
    if len(credentials) != 1:
        raise ValueError("请提供一种 SSH 登录凭据：密码或未加密的 Ed25519 私钥。")
    if len(credentials.get("password", "")) > 256:
        raise ValueError("SSH 密码过长。")
    if "private_key" in credentials:
        try:
            paramiko.Ed25519Key.from_private_key(io.StringIO(credentials["private_key"]))
        except Exception:
            raise ValueError("私钥格式不正确；目前支持未加密的 Ed25519 私钥。") from None
    private, public = generate_key()
    recovery_private, recovery_public = generate_key()
    store = SecretStore(settings.secret_directory)
    refs = []
    try:
        refs.append(store.put(credentials))
        refs.append(
            store.put(
                {
                    "private_key": private,
                    "public_key": public,
                    "recovery_private_key": recovery_private,
                    "recovery_public_key": recovery_public,
                }
            )
        )
        with connect(settings.database_path) as db:
            row = db.execute(
                """INSERT INTO gateways(name,host,ssh_port,location,bootstrap_user,host_key,
                   bootstrap_ref,managed_ref,created_at) VALUES (?,?,?,?,?,?,?,?,?)""",
                (name, str(address), port, location, "root", host_key, *refs, int(time.time())),
            )
            audit(db, actor, "gateway.created", f"gateway_id={row.lastrowid}")
            return row.lastrowid
    except Exception as exc:
        for reference in refs:
            store.delete(reference)
        if isinstance(exc, sqlite3.IntegrityError):
            raise ValueError("该名称或服务器地址及端口已存在。") from None
        raise


def enqueue(settings, gateway_id, kind, actor):
    if kind not in {"deploy", "check", "restart"}:
        raise ValueError("不支持的操作。")
    try:
        with connect(settings.database_path) as db:
            db.execute("BEGIN IMMEDIATE")
            gateway = db.execute("SELECT * FROM gateways WHERE id=?", (gateway_id,)).fetchone()
            if gateway is None:
                raise ValueError("未找到服务器。")
            if kind != "deploy" and gateway["status"] == "NEW":
                raise ValueError("请先部署服务器。")
            job = db.execute(
                "INSERT INTO gateway_jobs(gateway_id,kind,actor,created_at) VALUES (?,?,?,?)",
                (gateway_id, kind, actor, int(time.time())),
            )
            audit(db, actor, "gateway." + kind + ".queued", f"gateway_id={gateway_id}")
            return job.lastrowid
    except sqlite3.IntegrityError:
        raise ValueError("该服务器已有任务正在处理，请等待完成。") from None


def snapshot(settings):
    with connect(settings.database_path) as db:
        rows = db.execute("""SELECT id,name,host,ssh_port,location,host_key,status,
                          last_error,health_json,checked_at FROM gateways ORDER BY id""").fetchall()
        jobs = [
            dict(r)
            for r in db.execute("""SELECT j.id,j.gateway_id,g.name,j.kind,j.state,
            j.stage,j.error,j.created_at FROM gateway_jobs j JOIN gateways g ON g.id=j.gateway_id
            ORDER BY j.id DESC LIMIT 30""")
        ]
        active_ids = {
            r[0]
            for r in db.execute("""SELECT gateway_id FROM gateway_jobs
                                              WHERE state IN ('QUEUED','RUNNING')""")
        }
    result = []
    for row in rows:
        value = dict(row)
        value["fingerprint"] = fingerprint(parse_host_key(value.pop("host_key")))
        value["health"] = json.loads(value.pop("health_json"))
        value["busy"] = row["id"] in active_ids
        value["stale"] = not row["checked_at"] or time.time() - row["checked_at"] > 300
        value["last_check"] = (
            datetime.fromtimestamp(row["checked_at"], UTC).strftime("%m-%d %H:%M:%S UTC")
            if row["checked_at"]
            else "尚未检测"
        )
        if value["status"] == "HEALTHY" and value["stale"]:
            value["status"] = "UNKNOWN"
        result.append(value)
    return result, jobs


class GatewayWorker:
    """One bounded worker per Controller; SQLite retains jobs across process restarts."""

    def __init__(self, settings):
        self.settings = settings
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self.run, name="gateway-worker", daemon=True)

    def recover(self):
        with connect(self.settings.database_path) as db:
            db.execute("BEGIN IMMEDIATE")
            isps.recover(db)
            exits.recover(db)
            for row in db.execute("SELECT * FROM gateway_jobs WHERE state='RUNNING'").fetchall():
                db.execute(
                    """UPDATE gateways SET status=?,last_error=? WHERE id=?""",
                    (
                        "DEPLOY_FAILED" if row["kind"] == "deploy" else "UNKNOWN",
                        "上次任务因控制台重启中断，请检测后重试。",
                        row["gateway_id"],
                    ),
                )
                db.execute(
                    """UPDATE gateway_jobs SET state='FAILED',error=?,finished_at=?
                            WHERE id=?""",
                    ("控制台重启中断任务", int(time.time()), row["id"]),
                )
                audit(db, "system", "gateway.job.interrupted", f"job_id={row['id']}")

    def start(self):
        # Cross-process lock prevents another Uvicorn worker from recovering live jobs.
        import os

        self.lock = open(self.settings.database_path.parent / "gateway-worker.lock", "a+b")
        try:
            if os.name == "posix":
                import fcntl

                fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            else:
                import msvcrt

                self.lock.seek(0)
                msvcrt.locking(self.lock.fileno(), msvcrt.LK_NBLCK, 1)
        except OSError:
            self.lock.close()
            raise RuntimeError("Run one Controller worker per database") from None
        self.recover()
        self.thread.start()

    def close(self):
        self.stop.set()
        self.thread.join(timeout=20)

    def run(self):
        needs_recovery = False
        try:
            while not self.stop.is_set():
                try:
                    if needs_recovery:
                        self.recover()
                        needs_recovery = False
                    isps.schedule_due(self.settings)
                    worked = (
                        self.once() or isps.run_next(self.settings) or exits.run_next(self.settings)
                    )
                except Exception:
                    # DB outages must not kill the worker or disclose stored data in logs.
                    needs_recovery = True
                    worked = False
                if not worked:
                    self.stop.wait(2)
        finally:
            self.lock.close()

    def once(self):
        with connect(self.settings.database_path) as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT * FROM gateway_jobs WHERE state='QUEUED' ORDER BY id LIMIT 1"
            ).fetchone()
            if row is None:
                return False
            job = dict(row)
            gateway = dict(
                db.execute("SELECT * FROM gateways WHERE id=?", (job["gateway_id"],)).fetchone()
            )
            db.execute(
                "UPDATE gateway_jobs SET state='RUNNING',stage=?,started_at=? WHERE id=?",
                (
                    "CONNECTING" if job["kind"] == "deploy" else "CHECKING",
                    int(time.time()),
                    job["id"],
                ),
            )
            db.execute(
                "UPDATE gateways SET status=?,last_error='' WHERE id=?",
                ("DEPLOYING" if job["kind"] == "deploy" else "CHECKING", gateway["id"]),
            )

        def stage(value):
            with connect(self.settings.database_path) as db:
                db.execute("UPDATE gateway_jobs SET stage=? WHERE id=?", (value, job["id"]))

        store = SecretStore(self.settings.secret_directory)
        try:
            report = (
                deployment.deploy(gateway, store, stage)
                if job["kind"] == "deploy"
                else deployment.inspect(gateway, store, job["kind"])
            )
            with connect(self.settings.database_path) as db:
                db.execute(
                    """UPDATE gateways SET status='HEALTHY',last_error='',health_json=?,
                           checked_at=?,bootstrap_ref=NULL WHERE id=?""",
                    (json.dumps(report), int(time.time()), gateway["id"]),
                )
                db.execute(
                    """UPDATE gateway_jobs SET state='SUCCEEDED',stage='COMPLETE',
                           finished_at=? WHERE id=?""",
                    (int(time.time()), job["id"]),
                )
                audit(
                    db,
                    job["actor"],
                    "gateway." + job["kind"] + ".succeeded",
                    f"gateway_id={gateway['id']};job_id={job['id']}",
                )
            if gateway["bootstrap_ref"]:
                store.delete(gateway["bootstrap_ref"])
        except Exception as exc:
            error = (
                str(exc) if isinstance(exc, GatewayError) else "任务执行异常；请检测状态后重试。"
            )
            with connect(self.settings.database_path) as db:
                db.execute(
                    "UPDATE gateways SET status=?,last_error=? WHERE id=?",
                    (
                        "DEPLOY_FAILED" if job["kind"] == "deploy" else "CRITICAL",
                        error,
                        gateway["id"],
                    ),
                )
                db.execute(
                    """UPDATE gateway_jobs SET state='FAILED',error=?,finished_at=?
                            WHERE id=?""",
                    (error, int(time.time()), job["id"]),
                )
                audit(
                    db,
                    job["actor"],
                    "gateway." + job["kind"] + ".failed",
                    f"gateway_id={gateway['id']};job_id={job['id']}",
                )
        return True
