# ruff: noqa: F811
import base64
import json
from urllib.parse import parse_qs, unquote, urlsplit

import pytest

from controller.services import groups, subscriptions
from controller.services.database import connect
from controller.services.secrets import SecretStore
from gateways.configuration import client_uuid, render, validate
from tests.test_controller import csrf, login
from tests.test_exits import group_data, topology  # noqa: F401
from tests.test_gateways import client, data, settings  # noqa: F401
from tests.test_groups import subscription_data  # noqa: F401
from tests.test_isps import isp_data  # noqa: F401


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
    assert len(content.strip().splitlines()) == 1 and content.startswith("vless://")
    node = urlsplit(content.strip())
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
    assert unquote(node.fragment).endswith("443 稳定通道")
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
