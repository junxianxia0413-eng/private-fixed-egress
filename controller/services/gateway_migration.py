"""Move dedicated ISP routes after validating the destination, retaining subscriptions."""

import hashlib
import json
import secrets
import time

from controller.services import exits
from controller.services.database import audit, connect
from controller.services.secrets import SecretStore
from controller.services.subscriptions import qr_data
from gateways import deployment

CONFIGURATION_FIELDS = {
    "subscription_groups": "id,name,display_name,exit_id,deployed_exit_id,client_ref,token_ref,"
    "token_hash,ai_exit_id,ai_providers,display_order,created_at",
    "group_devices": "device_id,group_id,slot",
    "devices": "*",
    "exit_groups": "id,name,gateway_id,exit_type,isp_id,secret_ref,direct_expected_ip,"
    "verification_sources,applied,display_order,created_at",
    "isp_exits": "id,name,host,port,secret_ref,gateway_id,country,city,provider,expires_on,"
    "expected_exit_ip,created_at",
    "gateways": "id,name,host,ssh_port,location,host_key,bootstrap_ref,managed_ref,created_at",
}


def configuration_signature(db):
    values = {
        table: [dict(row) for row in db.execute(f"SELECT {fields} FROM {table} ORDER BY 1")]
        for table, fields in CONFIGURATION_FIELDS.items()
    }
    return hashlib.sha256(json.dumps(values, sort_keys=True).encode()).hexdigest()


def selection(settings, db, expected):
    identifiers = [item["id"] for item in expected]
    if not identifiers or len(identifiers) != len(set(identifiers)):
        raise ValueError("请选择明确且不重复的订阅组。")
    store = SecretStore(settings.secret_directory)
    rows = []
    for item in expected:
        row = db.execute(
            """SELECT s.*,e.gateway_id,e.isp_id,e.exit_type,i.expected_exit_ip
            FROM subscription_groups s JOIN exit_groups e ON s.exit_id=e.id
            LEFT JOIN isp_exits i ON e.isp_id=i.id WHERE s.id=?""",
            (item["id"],),
        ).fetchone()
        if not row or row["exit_type"] != "ISP_PROXY" or row["ai_exit_id"] is not None:
            raise ValueError("本次迁移仅适用于未启用 AI 分流的固定 ISP 订阅组。")
        if row["state"] != "READY" or row["exit_id"] != row["deployed_exit_id"]:
            raise ValueError("订阅组尚有未完成的绑定，请先完成当前配置。")
        if (row["display_name"] or row["name"]) != item["display_name"] or row[
            "expected_exit_ip"
        ] != item["expected_exit_ip"]:
            raise ValueError("订阅名称或固定出口已变化，请重新核对。")
        url = settings.public_url + "/sub/" + store.get(row["token_ref"])["token"]
        fingerprints = {
            "subscription_sha256": hashlib.sha256(url.encode()).hexdigest(),
            "qr_sha256": hashlib.sha256(qr_data(url).encode()).hexdigest(),
            "client_credentials_sha256": hashlib.sha256(
                json.dumps(store.get(row["client_ref"]), sort_keys=True).encode()
            ).hexdigest(),
        }
        if any(item[key] != value for key, value in fingerprints.items()):
            raise ValueError("订阅链接、二维码或连接凭据已变化，请重新核对。")
        members = [
            dict(r)
            for r in db.execute(
                """SELECT d.id,d.name FROM devices d JOIN group_devices m ON d.id=m.device_id
            WHERE m.group_id=? ORDER BY m.slot""",
                (row["id"],),
            )
        ]
        if members != item["devices"]:
            raise ValueError("设备绑定已变化，请重新核对。")
        rows.append(dict(row))
    route_ids = {row["exit_id"] for row in rows}
    isp_ids = {row["isp_id"] for row in rows}
    for row in db.execute("SELECT id,exit_id,ai_exit_id FROM subscription_groups"):
        if row["id"] not in identifiers and (
            row["exit_id"] in route_ids or row["ai_exit_id"] in route_ids
        ):
            raise ValueError("所选线路还被其他订阅组使用，请先核对迁移范围。")
    for row in db.execute("SELECT id,isp_id FROM exit_groups"):
        if row["isp_id"] in isp_ids and row["id"] not in route_ids:
            raise ValueError("所选 ISP 仍关联其他线路，需先核对独立迁移范围。")
    return rows


def migrate(settings, expected, target_gateway_id, actor, stage):
    with connect(settings.database_path) as db:
        db.execute("BEGIN IMMEDIATE")
        rows = selection(settings, db, expected)
        source_ids = {row["gateway_id"] for row in rows}
        if source_ids == {target_gateway_id}:
            return {"ok": True, "already_migrated": True, "gateway_id": target_gateway_id}
        if len(source_ids) != 1 or target_gateway_id in source_ids:
            raise ValueError("本次批量迁移需来自同一网关。")
        source_id = next(iter(source_ids))
        target = db.execute("SELECT * FROM gateways WHERE id=?", (target_gateway_id,)).fetchone()
        if not target or target["bootstrap_ref"] or target["status"] != "HEALTHY":
            raise ValueError("目标网关尚未完成部署与验证。")
        if db.execute(
            "SELECT 1 FROM exit_groups WHERE gateway_id=?", (target_gateway_id,)
        ).fetchone():
            raise ValueError("本次整组迁移需要空白目标网关，请先核对目标配置。")
        if (
            db.execute(
                """SELECT 1 FROM exit_jobs WHERE gateway_id IN (?,?)
            AND state IN ('QUEUED','RUNNING')""",
                (source_id, target_gateway_id),
            ).fetchone()
            or db.execute(
                """SELECT 1 FROM gateway_jobs WHERE gateway_id IN (?,?)
            AND state IN ('QUEUED','RUNNING')""",
                (source_id, target_gateway_id),
            ).fetchone()
        ):
            raise ValueError("网关仍有配置任务，请等待任务结束。")
        signature = configuration_signature(db)
        target = dict(target)
    stage("PREPARING")
    _, topology = exits.desired(settings, {"gateway_id": source_id, "group_id": None})
    route_ids = {row["exit_id"] for row in rows}
    chosen = [route for route in topology if route["id"] in route_ids]
    if {route["id"] for route in chosen} != route_ids or any(not g["enabled"] for g in chosen):
        raise ValueError("迁移线路缺少有效配置或出口身份异常。")
    transaction = secrets.token_hex(16)
    results, digest = exits.apply_remote(settings, target, chosen, transaction, stage)
    if set(results) != route_ids or any(
        results[g["id"]].get("exit_ip") != g["expected_ip"] for g in chosen
    ):
        raise ValueError("新网关的实际出口未通过完整核对，原订阅绑定继续生效。")
    report = deployment.inspect(target, SecretStore(settings.secret_directory), "check")
    stage("COMMITTING_BINDINGS")
    with connect(settings.database_path) as db:
        db.execute("BEGIN IMMEDIATE")
        if configuration_signature(db) != signature:
            raise ValueError("部署期间配置发生变化，原订阅绑定继续生效，请重新核对。")
        for table in ("exit_jobs", "gateway_jobs"):
            if db.execute(
                f"SELECT 1 FROM {table} WHERE gateway_id IN (?,?) "
                "AND state IN ('QUEUED','RUNNING')",
                (source_id, target_gateway_id),
            ).fetchone():
                raise ValueError("有新的网关配置任务，原订阅绑定继续生效。")
        selection(settings, db, expected)
        for row in rows:
            result = results[row["exit_id"]]
            db.execute(
                """UPDATE exit_groups SET gateway_id=?,config_hash=?,current_exit_ip=?,
                latency_ms=?,checked_at=?,status='HEALTHY',last_error='' WHERE id=?""",
                (
                    target_gateway_id,
                    digest,
                    result["exit_ip"],
                    result["latency_ms"],
                    int(time.time()),
                    row["exit_id"],
                ),
            )
            db.execute(
                """UPDATE isp_exits SET gateway_id=?,status='HEALTHY',last_error='',
                current_exit_ip=?,latency_ms=?,tested_at=? WHERE id=?""",
                (
                    target_gateway_id,
                    result["exit_ip"],
                    result["latency_ms"],
                    int(time.time()),
                    row["isp_id"],
                ),
            )
            db.execute(
                """INSERT INTO isp_checks(isp_id,gateway_id,occurred_at,status,expected_ip,
                observed_ip,latency_ms,error) VALUES (?,?,?,'HEALTHY',?,?,?,'')""",
                (
                    row["isp_id"],
                    target_gateway_id,
                    int(time.time()),
                    row["expected_exit_ip"],
                    result["exit_ip"],
                    result["latency_ms"],
                ),
            )
        db.execute(
            "UPDATE gateways SET health_json=?,checked_at=? WHERE id=?",
            (json.dumps(report), int(time.time()), target_gateway_id),
        )
        audit(
            db,
            actor,
            "gateway.routes.migrated",
            json.dumps(
                {
                    "source_gateway_id": source_id,
                    "target_gateway_id": target_gateway_id,
                    "groups": [r["id"] for r in rows],
                    "transaction": transaction,
                }
            ),
        )
    stage("COMPLETE")
    return {
        "ok": True,
        "gateway_id": target_gateway_id,
        "host": target["host"],
        "groups": [{"id": row["id"], "exit_ip": row["expected_exit_ip"]} for row in rows],
    }


def retire_source(settings, expected, target_gateway_id, actor, stage):
    """Remove migrated listeners from the old gateway after new bindings are committed."""
    source_ids = {item["gateway_id"] for item in expected}
    if len(source_ids) != 1 or target_gateway_id in source_ids:
        raise ValueError("原网关确认信息不完整。")
    source_id = next(iter(source_ids))
    with connect(settings.database_path) as db:
        rows = selection(settings, db, expected)
        if any(row["gateway_id"] != target_gateway_id for row in rows):
            raise ValueError("新网关绑定尚未完成，旧入口继续保留。")
        signature = configuration_signature(db)
    stage("RETIRING_SOURCE_LISTENERS")
    gateway, topology = exits.desired(settings, {"gateway_id": source_id, "group_id": None})
    if {row["exit_id"] for row in rows} & {g["id"] for g in topology}:
        raise ValueError("原网关配置仍包含迁移线路，请检查绑定。")
    results, digest = exits.apply_remote(settings, gateway, topology, secrets.token_hex(16), stage)
    report = deployment.inspect(gateway, SecretStore(settings.secret_directory), "check")
    with connect(settings.database_path) as db:
        db.execute("BEGIN IMMEDIATE")
        if configuration_signature(db) != signature:
            raise ValueError("清理旧入口期间配置变化，请重新验证。")
        for route in topology:
            result = results.get(route["id"], {})
            db.execute(
                """UPDATE exit_groups SET config_hash=?,current_exit_ip=?,latency_ms=?,
                checked_at=? WHERE id=? AND gateway_id=?""",
                (
                    digest,
                    result.get("exit_ip"),
                    result.get("latency_ms"),
                    int(time.time()),
                    route["id"],
                    source_id,
                ),
            )
        db.execute(
            "UPDATE gateways SET health_json=?,checked_at=? WHERE id=?",
            (json.dumps(report), int(time.time()), source_id),
        )
        audit(
            db,
            actor,
            "gateway.migration.source_retired",
            json.dumps(
                {
                    "source_gateway_id": source_id,
                    "groups": [row["id"] for row in rows],
                }
            ),
        )
    return {"gateway_id": source_id, "retired_routes": sorted(row["exit_id"] for row in rows)}
