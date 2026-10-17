import re
import sqlite3
import time

import pytest
from fastapi.testclient import TestClient

from controller.config import Settings
from controller.main import create_app
from controller.models.schema import MIGRATIONS
from controller.services.auth import digest, set_administrator
from controller.services.database import backup, connect, migrate

PASSWORD = "test-only-password-which-is-never-a-default"


@pytest.fixture
def settings(tmp_path):
    result = Settings(
        database_path=tmp_path / "controller.db", public_url="http://testserver", environment="test"
    )
    migrate(result.database_path)
    set_administrator(result, "admin", PASSWORD)
    return result


@pytest.fixture
def client(settings):
    with TestClient(create_app(settings), follow_redirects=False) as result:
        yield result


def csrf(response):
    return re.search(r'name="csrf" value="([^"]+)"', response.text).group(1)


def login(client, password=PASSWORD):
    token = csrf(client.get("/login"))
    return client.post("/login", data={"username": "admin", "password": password, "csrf": token})


def test_authentication_rotation_logout_and_revocation(client, settings):
    assert client.get("/").status_code == 303
    token = csrf(client.get("/login"))
    anonymous = client.cookies.get(settings.cookie_name)
    response = client.post(
        "/login", data={"username": "admin", "password": PASSWORD, "csrf": token}
    )
    assert response.status_code == 303
    authenticated = client.cookies.get(settings.cookie_name)
    assert authenticated != anonymous
    page = client.get("/")
    assert "System Online" in page.text and "控制台在线" in page.text
    assert "网络状态" in page.text or "检测与告警" in page.text
    assert "HttpOnly" in response.headers["set-cookie"]
    assert "SameSite=strict" in response.headers["set-cookie"]
    with connect(settings.database_path) as db:
        assert db.execute("SELECT token_hash FROM sessions").fetchone()[0] == digest(authenticated)
        assert (
            db.execute("SELECT password_hash FROM administrator")
            .fetchone()[0]
            .startswith("$argon2id$")
        )
    assert client.post("/logout", data={"csrf": csrf(page)}).status_code == 303
    client.cookies.set(settings.cookie_name, authenticated)
    assert client.get("/").status_code == 303


@pytest.mark.parametrize(
    "headers", [{"Origin": "https://evil.example"}, {"Sec-Fetch-Site": "cross-site"}]
)
def test_cross_origin_login_rejected(client, headers):
    token = csrf(client.get("/login"))
    assert (
        client.post(
            "/login",
            headers=headers,
            data={
                "username": "admin",
                "password": PASSWORD,
                "csrf": token,
            },
        ).status_code
        == 403
    )


def test_csrf_required_for_login_and_logout(client):
    client.get("/login")
    assert (
        client.post("/login", data={"username": "admin", "password": PASSWORD}).status_code == 403
    )
    assert login(client).status_code == 303
    assert client.post("/logout", data={}).status_code == 403
    assert client.get("/").status_code == 200


def test_wrong_password_limited_across_restart(client, settings):
    for _ in range(5):
        assert login(client, "wrong-password").status_code == 401
    with TestClient(create_app(settings), follow_redirects=False) as restarted:
        response = login(restarted)
        assert response.status_code == 429
        assert response.headers["retry-after"] == "900"
    with connect(settings.database_path) as db:
        db.execute("UPDATE login_attempts SET attempted_at=?", (int(time.time()) - 901,))
    assert login(client).status_code == 303


def test_global_login_limit(client, settings):
    with connect(settings.database_path) as db:
        db.executemany(
            "INSERT INTO login_attempts(source, attempted_at) VALUES (?, ?)",
            [(f"ip-{i}", int(time.time())) for i in range(30)],
        )
    assert login(client).status_code == 429


def test_session_expiry(client, settings):
    login(client)
    with connect(settings.database_path) as db:
        db.execute("UPDATE sessions SET expires_at=0")
    assert client.get("/").status_code == 303


def test_admin_reset_revokes_sessions_and_old_password(client, settings):
    login(client)
    set_administrator(settings, "admin", PASSWORD + "-new", reset=True)
    assert client.get("/").status_code == 303
    assert login(client, PASSWORD).status_code == 401
    assert login(client, PASSWORD + "-new").status_code == 303


def test_restart_preserves_session_and_audit(client, settings):
    login(client)
    with TestClient(create_app(settings), follow_redirects=False) as restarted:
        restarted.cookies.update(client.cookies)
        page = restarted.get("/")
        assert page.status_code == 200
        assert "auth.login" in page.text


def test_migrations_repeat_without_losing_data(settings):
    migrate(settings.database_path)
    migrate(settings.database_path)
    with connect(settings.database_path) as db:
        assert db.execute("PRAGMA user_version").fetchone()[0] == len(MIGRATIONS)
        assert db.execute("SELECT COUNT(*) FROM administrator").fetchone()[0] == 1
        assert db.execute("PRAGMA journal_mode").fetchone()[0] == "wal"


def test_direct_exit_migration_preserves_existing_routes_and_subscriptions(tmp_path):
    path = tmp_path / "legacy.db"
    db = sqlite3.connect(path)
    try:
        for number, migration in enumerate(MIGRATIONS[:10], 1):
            for statement in migration:
                db.execute(statement)
            db.execute(f"PRAGMA user_version={number}")
        now = int(time.time())
        db.execute(
            """INSERT INTO gateways
            (id,name,host,ssh_port,location,bootstrap_user,host_key,managed_ref,created_at)
            VALUES (1,'gw','45.32.20.164',22,'Tokyo','root','key','managed',?)""",
            (now,),
        )
        db.execute(
            """INSERT INTO isp_exits
            (id,name,host,port,secret_ref,gateway_id,expected_exit_ip,created_at)
            VALUES (1,'isp','43.246.197.96',443,'isp-secret',1,'43.246.197.96',?)""",
            (now,),
        )
        db.execute(
            """INSERT INTO exit_groups
            (id,name,gateway_id,isp_id,secret_ref,applied,created_at)
            VALUES (1,'exit',1,1,'probe-secret',1,?)""",
            (now,),
        )
        db.execute("INSERT INTO devices VALUES (1,'phone','Phone','iOS','','',?)", (now,))
        db.execute(
            """INSERT INTO subscription_groups
            (id,name,exit_id,state,created_at,client_ref,token_ref,token_hash,deployed_exit_id)
            VALUES (1,'phones',1,'READY',?,'client','token','hash',1)""",
            (now,),
        )
        db.execute("INSERT INTO group_devices VALUES (1,1,1)")
        db.commit()
    finally:
        db.close()
    migrate(path)
    with connect(path) as db:
        exit_row = db.execute("SELECT * FROM exit_groups").fetchone()
        group_row = db.execute("SELECT * FROM subscription_groups").fetchone()
        assert exit_row["exit_type"] == "ISP_PROXY" and exit_row["isp_id"] == 1
        assert group_row["exit_id"] == 1 and group_row["deployed_exit_id"] == 1
        assert group_row["ai_exit_id"] is None and group_row["ai_providers"] == "[]"
        assert db.execute("PRAGMA foreign_key_check").fetchall() == []


def test_newer_schema_rejected(settings):
    with connect(settings.database_path) as db:
        db.execute("PRAGMA user_version=99")
    with pytest.raises(RuntimeError, match="newer"):
        migrate(settings.database_path)


def test_backup_restores_real_login_and_invalidates_sessions(client, settings, tmp_path):
    login(client)
    destination = tmp_path / "backup.db"
    backup(settings.database_path, destination)
    with sqlite3.connect(destination) as db:
        assert db.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        assert db.execute("SELECT COUNT(*) FROM sessions").fetchone()[0] == 0
        assert db.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0] >= 2
    restored_settings = Settings(
        database_path=destination, public_url="http://testserver", environment="test"
    )
    with TestClient(create_app(restored_settings), follow_redirects=False) as restored:
        restored.cookies.update(client.cookies)
        assert restored.get("/").status_code == 303
        assert login(restored).status_code == 303
    with pytest.raises(FileExistsError):
        backup(settings.database_path, destination)


def test_production_https_and_secure_cookie(tmp_path):
    settings = Settings(
        database_path=tmp_path / "prod.db",
        public_url="https://network.example.com",
        environment="production",
    )
    migrate(settings.database_path)
    set_administrator(settings, "admin", PASSWORD)
    with TestClient(create_app(settings), base_url=settings.public_url) as client:
        response = client.get("/login")
        assert "__Host-pfem_session=" in response.headers["set-cookie"]
        assert "Secure" in response.headers["set-cookie"]
        assert "strict-transport-security" in response.headers
        assert (
            client.get("http://network.example.com/login", follow_redirects=False).status_code
            == 307
        )


def test_security_headers_hosts_and_oversized_input(client):
    response = client.get("/login")
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["referrer-policy"] == "same-origin"
    assert response.headers["x-frame-options"] == "DENY"
    assert "frame-ancestors 'none'" in response.headers["content-security-policy"]
    assert client.get("/", headers={"Host": "evil.example"}).status_code == 400
    assert client.post("/login", content=b"a" * 17000).status_code == 413
    assert client.post("/login", content=iter([b"a" * 9000, b"a" * 9000])).status_code == 413
    assert client.get("/docs").status_code == 404
    assert client.get("/openapi.json").status_code == 404


def test_database_failure_not_reported_as_online(client, monkeypatch):
    def unavailable(*args, **kwargs):
        raise sqlite3.OperationalError("sensitive path must never be returned")

    monkeypatch.setattr("controller.main.connect", unavailable)
    response = client.get("/healthz")
    assert response.status_code == 503
    assert "sensitive" not in response.text


def test_uninitialized_dashboard_closed(tmp_path):
    settings = Settings(
        database_path=tmp_path / "empty.db", public_url="http://testserver", environment="test"
    )
    with TestClient(create_app(settings), follow_redirects=False) as client:
        assert client.get("/").status_code == 303
        assert client.get("/login").status_code == 503


def test_password_and_production_settings_validation(settings):
    with pytest.raises(ValueError):
        set_administrator(settings, "admin", "short", reset=True)
    with pytest.raises(ValueError, match="already exists"):
        set_administrator(settings, "other", PASSWORD)
    with pytest.raises(ValueError, match="HTTPS"):
        Settings(environment="production")
    with pytest.raises(ValueError, match="loopback"):
        Settings(public_url="http://0.0.0.0")
