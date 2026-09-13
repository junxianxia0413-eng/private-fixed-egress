import ipaddress
import json
import re
import secrets
import sqlite3
import time
from datetime import UTC, date, datetime
from urllib.parse import unquote, urlsplit

from controller.services.database import audit, connect
from controller.services.secrets import SecretStore
from gateways.ssh import GatewayError, connect_gateway, execute

ERRORS = {
    "AUTH_METHOD_REJECTED": "代理未接受用户名密码认证，请核对协议和端口。",
    "AUTH_FAILED": "SOCKS5 用户名或密码认证失败。",
    "CONNECT_REJECTED": "代理拒绝互联网连接。",
    "TIMEOUT": "检测超时，请检查代理服务和网络。",
    "TLS_FAILED": "出口检测的 HTTPS 证书验证失败。",
    "UNREACHABLE": "无法连接代理或出口检测服务。",
    "INVALID_ENDPOINT": "代理地址未解析为可用的公网 IPv4。",
    "UNSTABLE_EXIT": "两个检测服务返回不同出口，暂不能作为固定出口使用。",
    "IP_SERVICE_ERROR": "出口检测服务暂不可用。",
    "INVALID_EXIT_IP": "检测服务未返回有效公网 IPv4。",
}


def public_ip(value):
    result = ipaddress.ip_address(value)
    if result.version != 4 or not result.is_global:
        raise ValueError("需要公网 IPv4 地址。")
    return str(result)


def parse_socks5_uri(value):
    value = value.strip()
    if not 1 <= len(value) <= 2048 or any(character.isspace() for character in value):
        raise ValueError("SOCKS5 链接格式不正确。")
    try:
        parsed = urlsplit(value)
        port = parsed.port
        username = unquote(parsed.username or "", errors="strict")
        password = unquote(parsed.password or "", errors="strict")
    except (UnicodeDecodeError, ValueError):
        raise ValueError("SOCKS5 链接格式不正确。") from None
    if (
        parsed.scheme.lower() != "socks5"
        or not parsed.hostname
        or port is None
        or parsed.path not in ("", "/")
        or parsed.query
        or parsed.fragment
        or not username
        or not password
    ):
        raise ValueError("请粘贴 socks5://用户名:密码@地址:端口 格式的完整链接。")
    return {
        "host": parsed.hostname,
        "port": str(port),
        "username": username,
        "password": password,
    }


def connection_data(data, current=None, credentials=None):
    supplied = parse_socks5_uri(data["proxy_uri"]) if data.get("proxy_uri", "").strip() else {}
    current = current or {}
    credentials = credentials or {}
    host = supplied.get("host") or data.get("host", "").strip() or current.get("host", "")
    try:
        host = public_ip(host)
    except ValueError:
        if len(host) > 253 or not re.fullmatch(
            r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}", host
        ):
            raise ValueError("请填写公网 IPv4 或域名。") from None
    try:
        port = int(supplied.get("port") or data.get("port", "") or current.get("port", ""))
        if not 1 <= port <= 65535:
            raise ValueError
    except (TypeError, ValueError):
        raise ValueError("请填写有效端口。") from None
    values = {}
    for key in ("username", "password"):
        values[key] = supplied.get(key) or data.get(key, "") or credentials.get(key, "")
        if not isinstance(values[key], str) or not 1 <= len(values[key].encode()) <= 255:
            raise ValueError("SOCKS5 用户名和密码各需 1–255 字节。")
    return {"host": host, "port": port, **values}


def optional_data(data, current=None):
    current = current or {}
    optional = {
        key: (data.get(key, "").strip() if key in data else current.get(key, ""))
        for key in ("country", "city", "provider")
    }
    if any(len(value) > 80 for value in optional.values()):
        raise ValueError("国家、城市和服务商各最多 80 个字符。")
    raw_expiry = data.get("expires_on", "").strip() if "expires_on" in data else current.get(
        "expires_on"
    )
    expiry = raw_expiry or None
    if expiry:
        try:
            expiry = date.fromisoformat(expiry).isoformat()
        except ValueError:
            raise ValueError("到期日格式应为 YYYY-MM-DD。") from None
    return {**optional, "expires_on": expiry}


def register(settings, data, actor):
    name = data.get("name", "").strip()
    if not 1 <= len(name) <= 64:
        raise ValueError("名称需为 1–64 个字符。")
    connection = connection_data(data)
    try:
        gateway_id = int(data.get("gateway_id", ""))
    except ValueError:
        raise ValueError("请选择网关。") from None
    optional = optional_data(data)
    expected = data.get("expected_exit_ip", "").strip() or None
    if expected:
        expected = public_ip(expected)
    store = SecretStore(settings.secret_directory)
    reference = store.put({key: connection[key] for key in ("username", "password")})
    try:
        with connect(settings.database_path) as db:
            gateway = db.execute("SELECT id FROM gateways WHERE id=?", (gateway_id,)).fetchone()
            if not gateway:
                raise ValueError("未找到所选网关。")
            row = db.execute(
                """INSERT INTO isp_exits(name,host,port,secret_ref,gateway_id,
                country,city,provider,expires_on,expected_exit_ip,created_at)
                VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    name,
                    connection["host"],
                    connection["port"],
                    reference,
                    gateway_id,
                    optional["country"],
                    optional["city"],
                    optional["provider"],
                    optional["expires_on"],
                    expected,
                    int(time.time()),
                ),
            )
            audit(db, actor, "isp.created", f"isp_id={row.lastrowid}")
            return row.lastrowid
    except Exception as exc:
        store.delete(reference)
        if isinstance(exc, sqlite3.IntegrityError):
            raise ValueError("该 ISP 名称已存在。") from None
        raise


def rename(settings, isp_id, name, actor):
    name = name.strip()
    if not 1 <= len(name) <= 64:
        raise ValueError("名称需为 1–64 个字符。")
    try:
        with connect(settings.database_path) as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT name FROM isp_exits WHERE id=?", (isp_id,)).fetchone()
            if not row:
                raise ValueError("未找到 ISP。")
            db.execute("UPDATE isp_exits SET name=? WHERE id=?", (name, isp_id))
            audit(
                db,
                actor,
                "isp.renamed",
                json.dumps(
                    {"isp_id": isp_id, "before": row["name"], "after": name},
                    ensure_ascii=False,
                ),
            )
    except sqlite3.IntegrityError:
        raise ValueError("该 ISP 名称已存在。") from None


def update_connection(settings, isp_id, data, actor):
    store = SecretStore(settings.secret_directory)
    with connect(settings.database_path) as db:
        current_row = db.execute("SELECT * FROM isp_exits WHERE id=?", (isp_id,)).fetchone()
        if not current_row:
            raise ValueError("未找到 ISP。")
        current = dict(current_row)
        if db.execute(
            "SELECT 1 FROM isp_jobs WHERE isp_id=? AND state IN ('QUEUED','RUNNING')", (isp_id,)
        ).fetchone():
            raise ValueError("该 ISP 正在检测，请稍后再编辑。")
        if db.execute(
            "SELECT 1 FROM exit_jobs WHERE gateway_id=? AND state IN ('QUEUED','RUNNING')",
            (current["gateway_id"],),
        ).fetchone():
            raise ValueError("网关正在应用配置，请稍后再编辑。")
        gateway = dict(
            db.execute("SELECT * FROM gateways WHERE id=?", (current["gateway_id"],)).fetchone()
        )
        old_credentials = store.get(current["secret_ref"])
    connection = connection_data(data, current, old_credentials)
    optional = optional_data(data, current)
    report = probe_connection(settings, connection, gateway)
    if current["expected_exit_ip"] and report["exit_ip"] != current["expected_exit_ip"]:
        raise ValueError("新连接的出口 IP 与已锁定 IP 不一致，原连接信息已保留。")
    new_reference = store.put(
        {key: connection[key] for key in ("username", "password")}
    )
    old_reference = current["secret_ref"]
    try:
        with connect(settings.database_path) as db:
            db.execute("BEGIN IMMEDIATE")
            latest = db.execute(
                "SELECT secret_ref,expected_exit_ip FROM isp_exits WHERE id=?", (isp_id,)
            ).fetchone()
            if not latest or latest["secret_ref"] != old_reference:
                raise ValueError("连接信息已被其他操作修改，请刷新后重试。")
            expected = latest["expected_exit_ip"] or report["exit_ip"]
            db.execute(
                """UPDATE isp_exits SET host=?,port=?,secret_ref=?,country=?,city=?,provider=?,
                expires_on=?,expected_exit_ip=?,current_exit_ip=?,latency_ms=?,status='HEALTHY',
                last_error='',tested_at=? WHERE id=?""",
                (
                    connection["host"],
                    connection["port"],
                    new_reference,
                    optional["country"],
                    optional["city"],
                    optional["provider"],
                    optional["expires_on"],
                    expected,
                    report["exit_ip"],
                    report["latency_ms"],
                    int(time.time()),
                    isp_id,
                ),
            )
            db.execute(
                """INSERT INTO isp_checks(isp_id,gateway_id,occurred_at,status,expected_ip,
                observed_ip,latency_ms,error) VALUES (?,?,?,?,?,?,?,?)""",
                (
                    isp_id,
                    current["gateway_id"],
                    int(time.time()),
                    "HEALTHY",
                    expected,
                    report["exit_ip"],
                    report["latency_ms"],
                    "",
                ),
            )
            audit(
                db,
                actor,
                "isp.connection.updated",
                json.dumps(
                    {
                        "isp_id": isp_id,
                        "before": f"{current['host']}:{current['port']}",
                        "after": f"{connection['host']}:{connection['port']}",
                    },
                    ensure_ascii=False,
                ),
            )
            affected = db.execute(
                "SELECT id FROM exit_groups WHERE isp_id=? AND applied=1 ORDER BY id LIMIT 1",
                (isp_id,),
            ).fetchone()
            if affected:
                db.execute(
                    """INSERT INTO exit_jobs(group_id,gateway_id,actor,transaction_id,created_at)
                    VALUES (?,?,?,?,?)""",
                    (
                        affected["id"],
                        current["gateway_id"],
                        actor,
                        secrets.token_hex(16),
                        int(time.time()),
                    ),
                )
                audit(db, actor, "exit.apply.queued", f"group_id={affected['id']}")
    except Exception:
        store.delete(new_reference)
        raise
    store.delete(old_reference)
    return affected["id"] if affected else None


def enqueue(settings, isp_id, actor):
    try:
        with connect(settings.database_path) as db:
            db.execute("BEGIN IMMEDIATE")
            if not db.execute("SELECT id FROM isp_exits WHERE id=?", (isp_id,)).fetchone():
                raise ValueError("未找到 ISP。")
            row = db.execute(
                "INSERT INTO isp_jobs(isp_id,actor,created_at) VALUES (?,?,?)",
                (isp_id, actor, int(time.time())),
            )
            audit(db, actor, "isp.test.queued", f"isp_id={isp_id}")
            return row.lastrowid
    except sqlite3.IntegrityError:
        raise ValueError("该 ISP 正在检测，请稍后刷新。") from None


def snapshot(settings):
    with connect(settings.database_path) as db:
        rows = db.execute("""SELECT i.id,i.name,i.host,i.port,i.country,i.city,i.provider,
            i.expires_on,i.expected_exit_ip,i.current_exit_ip,i.latency_ms,i.status,i.last_error,
            i.tested_at,g.name AS gateway_name FROM isp_exits i JOIN gateways g ON i.gateway_id=g.id
            ORDER BY i.id""").fetchall()
        active = {
            r[0]
            for r in db.execute("SELECT isp_id FROM isp_jobs WHERE state IN ('QUEUED','RUNNING')")
        }
        checks = [
            dict(r)
            for r in db.execute("""SELECT c.*,i.name FROM isp_checks c
            JOIN isp_exits i ON i.id=c.isp_id ORDER BY c.id DESC LIMIT 30""")
        ]
    values = []
    today = datetime.now(UTC).date()
    for row in rows:
        value = dict(row)
        value["busy"] = row["id"] in active
        value["stale"] = not row["tested_at"] or time.time() - row["tested_at"] > 300
        value["last_test"] = (
            datetime.fromtimestamp(row["tested_at"], UTC).strftime("%m-%d %H:%M:%S UTC")
            if row["tested_at"]
            else "尚未检测"
        )
        value["days_left"] = (
            (date.fromisoformat(row["expires_on"]) - today).days if row["expires_on"] else None
        )
        if value["status"] == "HEALTHY" and value["stale"]:
            value["status"] = "UNKNOWN"
        values.append(value)
    return values, checks


def probe_connection(settings, connection, gateway):
    store = SecretStore(settings.secret_directory)
    with connect_gateway(gateway, "proxyadmin", store.get(gateway["managed_ref"])) as client:
        output = execute(
            client,
            "/usr/local/sbin/pfem-isp-probe",
            stdin=json.dumps(connection).encode(),
            timeout=65,
        )
    report = json.loads(output)
    if report.get("ok") is not True:
        raise GatewayError(ERRORS.get(report.get("error"), "SOCKS5 检测失败，原出口身份保持不变。"))
    ip = public_ip(report["exit_ip"])
    latency = float(report["latency_ms"])
    if not 0 <= latency <= 65000:
        raise GatewayError("检测耗时数据异常。")
    return {"exit_ip": ip, "latency_ms": latency}


def probe(settings, isp, gateway):
    credentials = SecretStore(settings.secret_directory).get(isp["secret_ref"])
    return probe_connection(
        settings,
        {"host": isp["host"], "port": isp["port"], **credentials},
        gateway,
    )


def recover(db):
    for row in db.execute("SELECT * FROM isp_jobs WHERE state='RUNNING'").fetchall():
        db.execute(
            "UPDATE isp_jobs SET state='FAILED',error=?,finished_at=? WHERE id=?",
            ("控制台重启中断检测", int(time.time()), row["id"]),
        )
        db.execute(
            "UPDATE isp_exits SET status='UNKNOWN',last_error=? WHERE id=?",
            ("上次检测已中断，请重新检测。", row["isp_id"]),
        )
        audit(db, "system", "isp.test.interrupted", f"isp_id={row['isp_id']}")


def schedule_due(settings):
    with connect(settings.database_path) as db:
        db.execute("BEGIN IMMEDIATE")
        for row in db.execute(
            """SELECT id FROM isp_exits WHERE tested_at IS NOT NULL
            AND tested_at<=? AND NOT EXISTS (SELECT 1 FROM isp_jobs
            WHERE isp_id=isp_exits.id AND state IN ('QUEUED','RUNNING'))""",
            (int(time.time()) - 60,),
        ).fetchall():
            db.execute(
                "INSERT INTO isp_jobs(isp_id,actor,created_at) VALUES (?,'system',?)",
                (row["id"], int(time.time())),
            )


def run_next(settings):
    with connect(settings.database_path) as db:
        db.execute("BEGIN IMMEDIATE")
        job = db.execute(
            "SELECT * FROM isp_jobs WHERE state='QUEUED' ORDER BY id LIMIT 1"
        ).fetchone()
        if not job:
            return False
        isp = dict(db.execute("SELECT * FROM isp_exits WHERE id=?", (job["isp_id"],)).fetchone())
        gateway = dict(
            db.execute("SELECT * FROM gateways WHERE id=?", (isp["gateway_id"],)).fetchone()
        )
        db.execute("UPDATE isp_jobs SET state='RUNNING' WHERE id=?", (job["id"],))
        db.execute("UPDATE isp_exits SET status='CHECKING',last_error='' WHERE id=?", (isp["id"],))
    actual, latency, error = None, None, ""
    try:
        report = probe(settings, isp, gateway)
        actual, latency = report["exit_ip"], report["latency_ms"]
    except Exception as exc:
        error = str(exc) if isinstance(exc, GatewayError) else "检测异常，请稍后重试。"
    with connect(settings.database_path) as db:
        db.execute("BEGIN IMMEDIATE")
        # Read identity again inside the committing transaction; never trust stale snapshots.
        current = db.execute(
            "SELECT expected_exit_ip,expires_on FROM isp_exits WHERE id=?", (isp["id"],)
        ).fetchone()
        expected = current["expected_exit_ip"] or actual
        if actual and expected != actual:
            error = "EXIT IP CHANGED：当前出口与固定出口不一致，禁止当作正常节点使用。"
        if (
            current["expires_on"]
            and date.fromisoformat(current["expires_on"]) < datetime.now(UTC).date()
        ):
            error = error or "ISP 已到期，请核实服务有效期。"
        status = "CRITICAL" if error else "HEALTHY"
        db.execute(
            """UPDATE isp_exits SET expected_exit_ip=?,current_exit_ip=?,latency_ms=?,
            status=?,last_error=?,tested_at=? WHERE id=?""",
            (expected, actual, latency, status, error, int(time.time()), isp["id"]),
        )
        db.execute(
            """INSERT INTO isp_checks(isp_id,gateway_id,occurred_at,status,expected_ip,
            observed_ip,latency_ms,error) VALUES (?,?,?,?,?,?,?,?)""",
            (isp["id"], gateway["id"], int(time.time()), status, expected, actual, latency, error),
        )
        db.execute(
            "UPDATE isp_jobs SET state=?,error=?,finished_at=? WHERE id=?",
            ("FAILED" if error else "SUCCEEDED", error, int(time.time()), job["id"]),
        )
        audit(
            db,
            job["actor"],
            "isp.test.failed" if error else "isp.test.succeeded",
            f"isp_id={isp['id']}",
        )
    return True
