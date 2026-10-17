# ruff: noqa: F811
import base64
import json
import time
from urllib.parse import parse_qs, unquote, urlsplit

import pytest
import yaml

from controller.services import exits, groups, subscriptions
from controller.services.database import connect
from controller.services.secrets import SecretStore
from gateways.configuration import client_uuid, render, validate
from tests.test_controller import csrf, login
from tests.test_exits import group_data, topology  # noqa: F401
from tests.test_gateways import client, data, settings  # noqa: F401
from tests.test_groups import subscription_data  # noqa: F401
from tests.test_isps import isp_data  # noqa: F401


def test_recent_actual_route_check_can_serve_subscription_during_isp_probe_timeout(
    settings, subscription_data,
):
    identifier = groups.register(settings, subscription_data, "admin")
    subscriptions.activate(settings, identifier, "admin")
    token = subscriptions.link(settings, identifier).rsplit("/", 1)[1]
    now = int(time.time())
    with connect(settings.database_path) as db:
        db.execute("UPDATE subscription_groups SET state='READY',deployed_exit_id=exit_id")
        route_id = db.execute("SELECT exit_id FROM subscription_groups").fetchone()[0]
        db.execute("UPDATE isp_exits SET status='CRITICAL',current_exit_ip=NULL")
        report = {"healthy": True, "guard": {
            "checked_at": now,
            "groups": [{"id": route_id, "healthy": True, "ingress_open": True,
                        "result": {"exit_ip": "1.1.1.1"}}],
        }}
        db.execute("UPDATE gateways SET health_json=?", (json.dumps(report),))
    assert subscriptions.payload(settings, token)
    for change in ("stale", "mismatch", "soft_failure", "closed", "invalid", "future"):
        value = json.loads(json.dumps(report))
        if change == "stale":
            value["guard"]["checked_at"] = now - 121
        elif change == "future":
            value["guard"]["checked_at"] = now + 1000
        elif change == "mismatch":
            value["guard"]["groups"][0]["result"]["exit_ip"] = "8.8.4.4"
        elif change == "soft_failure":
            value["guard"]["groups"][0]["healthy"] = False
        elif change == "closed":
            value["guard"]["groups"][0]["ingress_open"] = False
        else:
            value = []
        with connect(settings.database_path) as db:
            db.execute("UPDATE gateways SET health_json=?", (json.dumps(value),))
        with pytest.raises(ValueError):
            subscriptions.payload(settings, token)


def test_subscription_has_one_gateway_node_and_rotated_token_is_revoked(
    settings, subscription_data, isp_data
):
    identifier = groups.register(settings, subscription_data, "admin")
    subscriptions.activate(settings, identifier, "admin")
    link = subscriptions.link(settings, identifier)
    token = link.rsplit("/", 1)[1]
    with pytest.raises(ValueError):
        subscriptions.payload(settings, token)
    with connect(settings.database_path) as db:
        db.execute("UPDATE subscription_groups SET state='READY',deployed_exit_id=exit_id")
        group = dict(db.execute("SELECT * FROM subscription_groups").fetchone())
        assert token not in "\n".join(db.iterdump())
    content = base64.b64decode(subscriptions.payload(settings, token)).decode()
    nodes = [urlsplit(value) for value in content.strip().splitlines()]
    assert len(nodes) == 2 and content.startswith("vless://")
    node = nodes[0]
    password = SecretStore(settings.secret_directory).get(group["client_ref"])["password"]
    query = parse_qs(node.query)
    assert node.hostname == "8.8.8.8" and node.port == 443
    assert node.username == client_uuid(password)
    assert query == {
        "encryption": ["none"],
        "security": ["tls"],
        "type": ["ws"],
        "host": ["8.8.8.8"],
        "sni": ["8.8.8.8"],
        "peer": ["8.8.8.8"],
        "path": ["/pfem-ws/13001"],
    }
    assert unquote(node.fragment).endswith("443 主入口")
    assert nodes[1].port == 8443
    assert unquote(nodes[1].fragment).endswith("8443 备用入口")
    assert isp_data["password"] not in content and password not in content
    subscriptions.rotate(settings, identifier, "admin")
    assert subscriptions.payload(settings, token) is None
    assert subscriptions.payload(
        settings, subscriptions.link(settings, identifier).rsplit("/", 1)[1]
    )
    assert group["client_ref"] not in json.dumps(groups.snapshot(settings))


def test_subscription_link_requires_csrf_and_secrets_never_appear_in_inventory(
    client, settings, subscription_data
):
    identifier = groups.register(settings, subscription_data, "admin")
    assert client.post(f"/groups/{identifier}/link").status_code == 401
    login(client)
    assert client.post(f"/groups/{identifier}/activate").status_code == 403
    token = csrf(client.get("/groups"))
    assert client.post(f"/groups/{identifier}/activate", data={"csrf": token}).status_code == 303
    response = client.post(f"/groups/{identifier}/link", data={"csrf": token})
    assert response.status_code == 200 and response.headers["referrer-policy"] == "no-referrer"
    assert "data:image/svg+xml;base64," in response.text and "扫描二维码" in response.text
    link = subscriptions.link(settings, identifier)
    assert link in response.text and link not in client.get("/api/groups").text
    assert client.get("/sub/not-a-token").status_code == 404
    assert client.get(link).status_code == 503


def test_one_subscription_url_negotiates_shadowrocket_clash_and_browser(
    client, settings, subscription_data
):
    identifier = groups.register(settings, subscription_data, "admin")
    subscriptions.activate(settings, identifier, "admin")
    with connect(settings.database_path) as db:
        db.execute("UPDATE subscription_groups SET state='READY',deployed_exit_id=exit_id")
    link = subscriptions.link(settings, identifier)

    legacy = client.get(link, headers={"user-agent": "Shadowrocket/2.2"})
    assert legacy.status_code == 200
    assert base64.b64decode(legacy.text).decode().startswith("vless://")
    assert legacy.headers["cache-control"] == "no-store"
    assert legacy.headers["vary"] == "User-Agent, Accept"

    clash = client.get(link, headers={"user-agent": "clash-verge/v2.4.0"})
    document = yaml.safe_load(clash.text)
    assert clash.status_code == 200 and clash.headers["content-type"].startswith("text/yaml")
    assert document["proxies"][0]["type"] == "vless"
    assert document["proxies"][0]["server"] == "8.8.8.8"
    assert document["proxies"][0]["ws-opts"]["path"] == "/pfem-ws/13001"
    assert len(document["proxies"]) == 2
    assert [proxy["port"] for proxy in document["proxies"]] == [443, 8443]
    assert all("tfo" not in proxy for proxy in document["proxies"])
    assert document["proxies"][0]["client-fingerprint"] == "chrome"
    assert document["tcp-concurrent"] is True
    assert document["keep-alive-interval"] == 15
    assert document["proxy-groups"][0]["type"] == "fallback"
    assert document["proxy-groups"][0]["interval"] == 120
    assert document["rules"][0].startswith("MATCH,")

    browser = client.get(
        link,
        headers={"user-agent": "Mozilla/5.0 Chrome/140", "accept": "text/html"},
    )
    browser_html = browser.content.decode()
    assert browser.status_code == 200 and "这一个地址" in browser_html
    assert "不要把 443 和 8443" in browser_html and "系统代理" in browser_html
    assert f"{link}?format=clash" in browser_html
    explicit = client.get(link + "?format=clash")
    assert yaml.safe_load(explicit.text)["proxies"][0]["name"].endswith("443 主入口")
    assert client.get(link + "?format=unknown").status_code == 400


def test_gateway_direct_exit_can_serve_the_same_subscription_formats(
    settings, subscription_data, monkeypatch
):
    monkeypatch.setattr(
        exits,
        "detect_direct",
        lambda *_: ("8.8.8.8", 12.0, ["https://one.test", "https://two.test"]),
    )
    with connect(settings.database_path) as db:
        gateway_id = db.execute("SELECT id FROM gateways").fetchone()[0]
    direct_id = exits.register(
        settings,
        {
            "name": "DIRECT-01",
            "gateway_id": str(gateway_id),
            "exit_type": "GATEWAY_DIRECT",
        },
        "admin",
    )
    with connect(settings.database_path) as db:
        db.execute(
            """UPDATE exit_groups SET applied=1,status='HEALTHY',
            current_exit_ip=direct_expected_ip,checked_at=? WHERE id=?""",
            (int(time.time()), direct_id),
        )
    direct_group = {
        **subscription_data,
        "name": "DIRECT-GROUP",
        "exit_id": str(direct_id),
    }
    identifier = groups.register(settings, direct_group, "admin")
    subscriptions.activate(settings, identifier, "admin")
    with connect(settings.database_path) as db:
        db.execute(
            """UPDATE subscription_groups SET state='READY',deployed_exit_id=exit_id
            WHERE id=?""",
            (identifier,),
        )
    token = subscriptions.link(settings, identifier).rsplit("/", 1)[1]
    assert base64.b64decode(subscriptions.payload(settings, token)).decode().startswith("vless://")
    assert (
        yaml.safe_load(subscriptions.payload(settings, token, "clash"))["proxies"][0]["type"]
        == "vless"
    )


def test_subscription_qr_contains_svg_without_putting_link_in_image_url():
    link = "https://example.test/sub/" + "A" * 43
    image = subscriptions.qr_data(link)
    assert image.startswith("data:image/svg+xml;base64,")
    svg = base64.b64decode(image.split(",", 1)[1])
    assert b"<svg" in svg and b"<path" in svg and link.encode() not in svg


def test_phone_entry_requires_lease_and_cannot_directly_dial_other_hosts(topology):
    topology[0]["clients"] = [{"id": 1, "password": "A" * 43}]
    config, firewall = render(topology, 995)
    inbound = next(i for i in config["inbounds"] if i["type"] == "shadowsocks")
    tls_inbound = next(i for i in config["inbounds"] if i["type"] == "vless")
    assert inbound["listen_port"] == 20001 and inbound["network"] == "tcp"
    assert tls_inbound["listen"] == "127.0.0.1" and tls_inbound["listen_port"] == 13001
    assert tls_inbound["transport"] == {"type": "ws", "path": "/pfem-ws/13001"}
    assert "pfem_tls_live { type inet_service; }" in firewall
    assert "tcp dport != @pfem_live drop" in firewall
    assert "tcp dport != @pfem_tls_live drop" in firewall
    assert "ct direction reply tcp sport { 20001 } accept" in firewall
    assert config["route"]["rules"][1]["inbound"] == [
        "exit-1",
        "subscription-1",
        "subscription-tls-1",
    ]
    assert all(o["type"] == "socks" for o in config["outbounds"])
    topology.append({**topology[0], "id": 2})
    with pytest.raises(ValueError):
        validate(topology)
