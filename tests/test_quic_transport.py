# ruff: noqa: F811
"""Verify protocol additions preserve identities and cannot bypass fixed exits."""

import base64
import json
import time
from urllib.parse import parse_qs, unquote, urlsplit

import yaml

from controller.services import groups, subscriptions
from controller.services.database import connect
from gateways.configuration import QUIC_OBFS_PORT_BASE, QUIC_PORT_BASE, quic_obfs_password, render
from tests.test_exits import (
    group_data,  # noqa: F401
    topology,  # noqa: F401
)
from tests.test_gateways import data, settings  # noqa: F401
from tests.test_groups import subscription_data  # noqa: F401
from tests.test_isps import isp_data  # noqa: F401


def test_quic_retains_subscription_url_credentials_and_fixed_exit(settings, subscription_data):
    identifier = groups.register(settings, subscription_data, "admin")
    subscriptions.activate(settings, identifier, "admin")
    url = subscriptions.link(settings, identifier)
    original_qr = subscriptions.qr_data(url)
    token = url.rsplit("/", 1)[1]
    with connect(settings.database_path) as db:
        db.execute("UPDATE subscription_groups SET state='READY',deployed_exit_id=exit_id")
        db.execute(
            "UPDATE gateways SET health_json=?",
            (
                json.dumps(
                    {
                        "healthy": True,
                        "quic_ready": True,
                        "checked_at": time.time(),
                    }
                ),
            ),
        )
        before = [dict(row) for row in db.execute("SELECT * FROM subscription_groups")]
    nodes = base64.b64decode(subscriptions.payload(settings, token)).decode().splitlines()
    assert [urlsplit(node).scheme for node in nodes] == ["hysteria2", "vless", "vless"]
    quic = urlsplit(nodes[0])
    clash = yaml.safe_load(subscriptions.payload(settings, token, "clash"))
    assert quic.port == QUIC_PORT_BASE + identifier
    assert parse_qs(quic.query)["insecure"] == ["0"]
    assert "1.1.1.1" in unquote(quic.fragment)
    assert clash["proxies"][0]["type"] == "hysteria2"
    assert clash["proxies"][0]["password"] == quic.username
    assert clash["proxies"][0]["skip-cert-verify"] is False
    assert clash["proxies"][0]["udp"] is False
    assert clash["proxy-groups"][0]["type"] == "fallback"
    assert clash["proxy-groups"][0]["proxies"] == [p["name"] for p in clash["proxies"]]
    assert subscriptions.link(settings, identifier) == url
    assert subscriptions.qr_data(url) == original_qr
    with connect(settings.database_path) as db:
        assert [dict(row) for row in db.execute("SELECT * FROM subscription_groups")] == before
        db.execute(
            "UPDATE gateways SET health_json=?",
            (
                json.dumps(
                    {
                        "healthy": True,
                        "quic_ready": True,
                        "quic_obfs_ready": True,
                        "checked_at": time.time(),
                    }
                ),
            ),
        )
        db.commit()
        stable = base64.b64decode(subscriptions.payload(settings, token)).decode().splitlines()
        assert len(stable) == 4 and stable[1:] == nodes
        stable_uri = urlsplit(stable[0])
        assert stable_uri.port == QUIC_OBFS_PORT_BASE + identifier
        assert parse_qs(stable_uri.query)["obfs"] == ["salamander"]
        assert parse_qs(stable_uri.query)["obfs-password"] == [quic_obfs_password(quic.username)]
        clash_stable = yaml.safe_load(subscriptions.payload(settings, token, "clash"))
        assert clash_stable["proxies"][1:] == clash["proxies"]
        assert clash_stable["proxies"][0]["obfs"] == "salamander"
        assert clash_stable["proxies"][0]["obfs-password"] == quic_obfs_password(quic.username)
        assert subscriptions.qr_data(subscriptions.link(settings, identifier)) == original_qr
        for report in (
            {},
            {"healthy": True, "quic_ready": True, "checked_at": time.time() - 121},
            {"healthy": True, "quic_ready": True, "checked_at": time.time() + 600},
        ):
            db.execute("UPDATE gateways SET health_json=?", (json.dumps(report),))
            db.commit()
            assert len(base64.b64decode(subscriptions.payload(settings, token)).splitlines()) == 2


def test_quic_uses_guarded_ports_and_same_isp_route(topology):
    topology[0]["clients"] = [{"id": 6, "password": "A" * 43}]
    config, firewall = render(topology, 995, quic=True)
    inbound = next(row for row in config["inbounds"] if row["type"] == "hysteria2")
    assert inbound["listen_port"] == 23006
    assert inbound["users"][0]["password"] == "A" * 43
    assert "insecure" not in inbound["tls"]
    route = next(
        row for row in config["route"]["rules"] if "subscription-quic-6" in row.get("inbound", [])
    )
    assert route["outbound"] == "isp-1"
    assert config["route"]["rules"][-1] == {"action": "reject"}
    assert all(row["type"] == "socks" for row in config["outbounds"])
    assert "udp dport != @pfem_quic_live drop" in firewall
    assert "ct direction reply udp sport { 23006, 25006 } accept" in firewall
    obfs = next(r for r in config["inbounds"] if r.get("tag") == "subscription-quic-obfs-6")
    assert obfs["listen_port"] == 25006
    assert obfs["obfs"] == {"type": "salamander", "password": quic_obfs_password("A" * 43)}
    assert "udp dport 25001-26000" in firewall
    assert "subscription-quic-obfs-6" in route["inbound"]
    assert "meta skuid 995 ip daddr != 127.0.0.0/8 reject" in firewall
    topology[0]["enabled"] = False
    disabled, _ = render(topology, 995, quic=True)
    route = next(
        row for row in disabled["route"]["rules"] if "subscription-quic-6" in row.get("inbound", [])
    )
    assert route["action"] == "reject" and "outbound" not in route
