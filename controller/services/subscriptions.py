import base64
import hashlib
import io
import json
import re
import secrets
import sqlite3
import time
from urllib.parse import quote, urlencode

import segno
import yaml

from controller.services.database import audit, connect
from controller.services.groups import available_exit
from controller.services.secrets import SecretStore
from gateways.configuration import (
    QUIC_OBFS_PORT_BASE,
    QUIC_PORT_BASE,
    client_uuid,
    quic_obfs_password,
    tls_path,
)


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
    db.execute(
        "UPDATE subscription_groups SET state=CASE "
        "WHEN state='READY' AND deployed_exit_id=exit_id THEN 'READY' ELSE 'PENDING' END "
        "WHERE id=?",
        (identifier,),
    )
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
            primary = available_exit(db, row["exit_id"])
            if row["ai_exit_id"] is not None:
                ai_exit = available_exit(db, row["ai_exit_id"])
                if ai_exit["gateway_id"] != primary["gateway_id"]:
                    raise ValueError("AI 专用出口必须与主出口位于同一网关。")
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


def qr_data(link_value):
    if not isinstance(link_value, str) or not link_value.startswith(
        ("https://", "http://testserver/")
    ):
        raise ValueError("Invalid subscription link")
    output = io.BytesIO()
    segno.make_qr(link_value, error="h").save(
        output,
        kind="svg",
        scale=6,
        border=4,
        dark="#111827",
        light="#ffffff",
        xmldecl=False,
        svgns=True,
    )
    return "data:image/svg+xml;base64," + base64.b64encode(output.getvalue()).decode()


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


def _guard_verified(row):
    """A fresh successful check of the actual route is valid identity evidence too."""
    try:
        report = json.loads(row["health_json"] or "{}")
        guard = report["guard"]
        checked_at = guard["checked_at"]
        if (
            report.get("healthy") is not True
            or type(checked_at) not in (int, float)
            or not -5 <= time.time() - checked_at <= 120
        ):
            return False
        state = next(g for g in guard["groups"] if g["id"] == row["route_id"])
        return bool(
            state.get("healthy") is True
            and state.get("ingress_open") is True
            and row["expected_exit_ip"]
            and state.get("result", {}).get("exit_ip") == row["expected_exit_ip"]
        )
    except (ValueError, KeyError, TypeError, AttributeError, StopIteration):
        return False


def _record(settings, token):
    if not re.fullmatch("[a-zA-Z0-9_-]{43}", token):
        return None
    with connect(settings.database_path) as db:
        row = db.execute(
            """SELECT s.id,COALESCE(s.display_name,s.name) AS name,
            s.state,s.client_ref,s.exit_id,s.deployed_exit_id,
            g.host,g.health_json,e.id AS route_id,e.exit_type,
            CASE WHEN e.exit_type='GATEWAY_DIRECT' THEN e.status ELSE i.status END
                AS egress_status,
            CASE WHEN e.exit_type='GATEWAY_DIRECT' THEN e.checked_at ELSE i.tested_at END
                AS tested_at,
            CASE WHEN e.exit_type='GATEWAY_DIRECT'
                THEN e.direct_expected_ip ELSE i.expected_exit_ip END AS expected_exit_ip,
            CASE WHEN e.exit_type='GATEWAY_DIRECT'
                THEN e.current_exit_ip ELSE i.current_exit_ip END AS current_exit_ip
            FROM subscription_groups s JOIN exit_groups e ON s.exit_id=e.id
            JOIN gateways g ON e.gateway_id=g.id LEFT JOIN isp_exits i ON e.isp_id=i.id
            WHERE s.token_hash=?""",
            (hashlib.sha256(token.encode()).hexdigest(),),
        ).fetchone()
    if not row:
        return None
    standalone_verified = (
        row["egress_status"] in ("HEALTHY", "CHECKING")
        and row["tested_at"]
        and -5 <= time.time() - row["tested_at"] <= 120
        and row["current_exit_ip"] == row["expected_exit_ip"]
    )
    mismatch = bool(row["current_exit_ip"] and row["current_exit_ip"] != row["expected_exit_ip"])
    if (
        row["state"] != "READY"
        or row["exit_id"] != row["deployed_exit_id"]
        or mismatch
        or not (standalone_verified or _guard_verified(row))
    ):
        raise ValueError("出口配置尚未就绪或检查异常，请稍后重试。")
    password = SecretStore(settings.secret_directory).get(row["client_ref"])["password"]
    return dict(row), password


def _node_name(row, label):
    return f"{row['name']} · 出口 {row['expected_exit_ip']} · {label}"


def _node(row, password, port, label):
    query = urlencode(
        {
            "encryption": "none",
            "security": "tls",
            "type": "ws",
            "host": row["host"],
            "sni": row["host"],
            "peer": row["host"],
            "path": tls_path(row["id"]),
            # The current phone service is verified for TCP only, like the Clash profile.
            "udp": "0",
        }
    )
    node = (
        f"vless://{client_uuid(password)}@{row['host']}:{port}?{query}#"
        f"{quote(_node_name(row, label), safe='')}"
    )
    return node


def shadowrocket_payload(row, password):
    nodes = (
        _node(row, password, 443, "443 主入口"),
        _node(row, password, 8443, "8443 备用入口"),
    )
    if _quic_enabled(row):
        query = urlencode({"sni": row["host"], "insecure": "0"})
        quic_node = (
            f"hysteria2://{quote(password, safe='')}@{row['host']}:"
            f"{QUIC_PORT_BASE + row['id']}?{query}#"
            f"{quote(_node_name(row, 'QUIC 抗抖动入口'), safe='')}"
        )
        nodes = (quic_node, *nodes)
        if _quic_enabled(row, obfs=True):
            query = urlencode(
                {
                    "sni": row["host"],
                    "insecure": "0",
                    "obfs": "salamander",
                    "obfs-password": quic_obfs_password(password),
                }
            )
            stable = (
                f"hysteria2://{quote(password, safe='')}@{row['host']}:"
                f"{QUIC_OBFS_PORT_BASE + row['id']}?{query}#"
                f"{quote(_node_name(row, 'QUIC 稳定入口'), safe='')}"
            )
            nodes = (stable, *nodes)
    return base64.b64encode(("\n".join(nodes) + "\n").encode()).decode()


def _quic_enabled(row, obfs=False):
    try:
        report = json.loads(row.get("health_json") or "{}")
        return (
            report.get("healthy") is True
            and report.get("quic_ready") is True
            and (not obfs or report.get("quic_obfs_ready") is True)
            and type(report.get("checked_at")) in (int, float)
            and -5 <= time.time() - report["checked_at"] <= 120
        )
    except (ValueError, TypeError, AttributeError):
        return False


def clash_payload(row, password):
    primary = _node_name(row, "443 主入口")
    alternate = _node_name(row, "8443 备用入口")
    # Mihomo rule lines are comma-separated. Keep the original name on the nodes.
    rule_safe_name = " ".join(row["name"].replace(",", "，").splitlines())
    proxy_group = rule_safe_name + " · 固定出口"
    document = {
        "mixed-port": 7890,
        "mode": "rule",
        "allow-lan": False,
        "log-level": "warning",
        "ipv6": False,
        "unified-delay": True,
        "tcp-concurrent": True,
        "keep-alive-interval": 15,
        "keep-alive-idle": 30,
        "proxies": [
            {
                "name": primary,
                "type": "vless",
                "server": row["host"],
                "port": 443,
                "uuid": client_uuid(password),
                "network": "ws",
                "tls": True,
                "servername": row["host"],
                "skip-cert-verify": False,
                "client-fingerprint": "chrome",
                "udp": False,
                "ws-opts": {
                    "path": tls_path(row["id"]),
                    "headers": {"Host": row["host"]},
                },
            },
            {
                "name": alternate,
                "type": "vless",
                "server": row["host"],
                "port": 8443,
                "uuid": client_uuid(password),
                "network": "ws",
                "tls": True,
                "servername": row["host"],
                "skip-cert-verify": False,
                "client-fingerprint": "chrome",
                "udp": False,
                "ws-opts": {
                    "path": tls_path(row["id"]),
                    "headers": {"Host": row["host"]},
                },
            },
        ],
        "proxy-groups": [
            {
                "name": proxy_group,
                "type": "fallback",
                "proxies": [primary, alternate],
                "url": "https://www.gstatic.com/generate_204",
                "interval": 120,
                "lazy": False,
            }
        ],
        "rules": [f"MATCH,{proxy_group}"],
    }
    if _quic_enabled(row):
        quic_name = _node_name(row, "QUIC 抗抖动入口")
        document["proxies"].insert(
            0,
            {
                "name": quic_name,
                "type": "hysteria2",
                "server": row["host"],
                "port": QUIC_PORT_BASE + row["id"],
                "password": password,
                "sni": row["host"],
                "skip-cert-verify": False,
                "udp": False,
            },
        )
        document["proxy-groups"][0]["proxies"].insert(0, quic_name)
        document["proxy-groups"][0]["interval"] = 60
        if _quic_enabled(row, obfs=True):
            stable_name = _node_name(row, "QUIC 稳定入口")
            document["proxies"].insert(
                0,
                {
                    "name": stable_name,
                    "type": "hysteria2",
                    "server": row["host"],
                    "port": QUIC_OBFS_PORT_BASE + row["id"],
                    "password": password,
                    "obfs": "salamander",
                    "obfs-password": quic_obfs_password(password),
                    "sni": row["host"],
                    "skip-cert-verify": False,
                    "udp": False,
                },
            )
            document["proxy-groups"][0]["proxies"].insert(0, stable_name)
    return yaml.safe_dump(document, allow_unicode=True, sort_keys=False)


def payload(settings, token, format_name="shadowrocket"):
    found = _record(settings, token)
    if not found:
        return None
    row, password = found
    if format_name == "shadowrocket":
        return shadowrocket_payload(row, password)
    if format_name == "clash":
        return clash_payload(row, password)
    raise ValueError("不支持的订阅格式。")
