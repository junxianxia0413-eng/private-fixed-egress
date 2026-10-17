from unittest.mock import MagicMock

import pytest

from gateways import deployment, ingress
from gateways.ssh import GatewayError
from scripts.deployment import render_caddy


def test_new_gateway_has_two_tls_entries_without_a_controller_dependency():
    config = ingress.prepare("8.8.8.8", "")
    assert "https://8.8.8.8, https://8.8.8.8:8443" in config
    assert "profile shortlived" in config
    assert "path_regexp pfem_ws" in config and "127.0.0.1:{re.pfem_ws.1}" in config
    assert "127.0.0.1:8000" not in config


def test_shared_controller_keeps_its_existing_routes():
    config = render_caddy("8.8.8.8")
    assert ingress.prepare("8.8.8.8", config) == config
    with pytest.raises(ValueError):
        ingress.prepare("1.1.1.1", config)


def test_only_the_factory_caddy_site_can_be_replaced():
    factory = "# The Caddyfile\n:80 {\n root * /usr/share/caddy\n file_server\n}\n"
    assert "profile shortlived" in ingress.prepare("8.8.8.8", factory)
    with pytest.raises(ValueError, match="Unmanaged"):
        ingress.prepare("8.8.8.8", "# The Caddyfile\nexample.com { reverse_proxy :8000 }")


@pytest.mark.parametrize("host", ["127.0.0.1", "8.8.8.8\n{", "https://8.8.8.8", "10.0.0.1"])
def test_ingress_rejects_private_hosts_and_config_injection(host):
    with pytest.raises(ValueError):
        ingress.render(host)


def test_deployment_cannot_succeed_if_public_tls_entry_is_unreachable(monkeypatch):
    connection = MagicMock()
    connection.request.side_effect = TimeoutError
    monkeypatch.setattr(deployment.http.client, "HTTPSConnection", lambda *a, **k: connection)
    with pytest.raises(GatewayError, match="443"):
        deployment.verify_ingress({"host": "8.8.8.8"})
    connection.close.assert_called_once()
