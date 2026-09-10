import base64
import hashlib
import re
import secrets
import sqlite3
import time
from urllib.parse import quote

from controller.services.database import audit, connect
from controller.services.groups import available_exit
from controller.services.secrets import SecretStore


def queue(db, identifier, actor):
    row = db.execute(
        """SELECT s.exit_id,e.gateway_id FROM subscription_groups s
        JOIN exit_groups e ON s.exit_id=e.id WHERE s.id=?""",
        (identifier,),
    ).fetchone()
    if not row:
        raise ValueError("订阅组不存在。")
    if db.execute(
        "SELECT 1 FROM exit_jobs WHERE gateway_id=? AND state IN ('QUEUED','RUNNING')",
        (row["gateway_id"],),
    ).fetchone():
        raise ValueError("网关正在应用配置，请稍后重试。")
    db.execute(
        """INSERT INTO exit_jobs(group_id,gateway_id,actor,transaction_id,created_at)
        VALUES (?,?,?,?,?)""",
        (row["exit_id"], row["gateway_id"], actor, secrets.token_hex(16), int(time.time())),
    )
    db.execute("UPDATE subscription_groups SET state='PENDING' WHERE id=?", (identifier,))
    audit(db, actor, "subscription.apply.queued", f"group_id={identifier}")


def activate(settings, identifier, actor):
    store = SecretStore(settings.secret_directory)
    created = []
    try:
        with connect(settings.database_path) as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT * FROM subscription_groups WHERE id=?", (identifier,)
            ).fetchone()
            if not row:
                raise ValueError("未找到订阅组。")
            available_exit(db, row["exit_id"])
            if not row["client_ref"]:
                client_ref = store.put({"password": secrets.token_urlsafe(32)})
                created.append(client_ref)
                token = secrets.token_urlsafe(32)
                token_ref = store.put({"token": token})
                created.append(token_ref)
                db.execute(
                    "UPDATE subscription_groups SET client_ref=?,token_ref=?,token_hash=? "
                    "WHERE id=?",
                    (client_ref, token_ref, hashlib.sha256(token.encode()).hexdigest(), identifier),
                )
            queue(db, identifier, actor)
    except Exception as exc:
        for reference in created:
            store.delete(reference)
        if isinstance(exc, sqlite3.IntegrityError):
            raise ValueError("已有配置任务，请稍后重试。") from None
        raise


def link(settings, identifier):
    with connect(settings.database_path) as db:
        row = db.execute(
            "SELECT token_ref FROM subscription_groups WHERE id=?", (identifier,)
        ).fetchone()
    if not row or not row["token_ref"]:
        raise ValueError("请先生成并应用订阅。")
    token = SecretStore(settings.secret_directory).get(row["token_ref"])["token"]
    return settings.public_url + "/sub/" + token


def rotate(settings, identifier, actor):
    token = secrets.token_urlsafe(32)
    store = SecretStore(settings.secret_directory)
    reference = store.put({"token": token})
    try:
        with connect(settings.database_path) as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT token_ref FROM subscription_groups WHERE id=?", (identifier,)
            ).fetchone()
            if not row or not row["token_ref"]:
                raise ValueError("请先生成订阅。")
            db.execute(
                "UPDATE subscription_groups SET token_ref=?,token_hash=? WHERE id=?",
                (reference, hashlib.sha256(token.encode()).hexdigest(), identifier),
            )
            audit(db, actor, "subscription.token.rotated", f"group_id={identifier}")
    except Exception:
        store.delete(reference)
        raise
    store.delete(row["token_ref"])


def payload(settings, token):
    if not re.fullmatch("[a-zA-Z0-9_-]{43}", token):
        return None
    with connect(settings.database_path) as db:
        row = db.execute(
            """SELECT s.id,s.name,s.state,s.client_ref,s.exit_id,s.deployed_exit_id,
            g.host,i.status AS isp_status,i.tested_at,i.expected_exit_ip,i.current_exit_ip
            FROM subscription_groups s JOIN exit_groups e ON s.exit_id=e.id
            JOIN gateways g ON e.gateway_id=g.id JOIN isp_exits i ON e.isp_id=i.id
            WHERE s.token_hash=?""",
            (hashlib.sha256(token.encode()).hexdigest(),),
        ).fetchone()
    if not row:
        return None
    if (
        row["state"] != "READY"
        or row["exit_id"] != row["deployed_exit_id"]
        or row["isp_status"] not in ("HEALTHY", "CHECKING")
        or not row["tested_at"]
        or time.time() - row["tested_at"] > 120
        or row["current_exit_ip"] != row["expected_exit_ip"]
    ):
        raise ValueError("出口配置尚未就绪或检查异常，请稍后重试。")
    password = SecretStore(settings.secret_directory).get(row["client_ref"])["password"]
    user = base64.urlsafe_b64encode(("aes-128-gcm:" + password).encode()).decode().rstrip("=")
    node = f"ss://{user}@{row['host']}:{20000 + row['id']}#{quote(row['name'], safe='')}"
    return base64.b64encode((node + "\n").encode()).decode()
