import pytest

from scripts.deployment import render_caddy, target_kind


@pytest.mark.parametrize("target", ["network.example.com", "jp-01.example.com"])
def test_dns_config_remains_supported(target):
    assert target_kind(target) == "dns"
    assert f"{target} {{" in render_caddy(target)
    assert "profile shortlived" not in render_caddy(target)
    assert "path_regexp pfem_ws" in render_caddy(target)
    assert "127.0.0.1:{re.pfem_ws.1}" in render_caddy(target)


def test_ip_uses_public_acme_with_shortlived_profile():
    rendered = render_caddy("8.8.8.8")
    assert "https://8.8.8.8 {" in rendered
    assert "profile shortlived" in rendered
    assert "https://acme-v02.api.letsencrypt.org/directory" in rendered
    assert "tls internal" not in rendered
    assert "reverse_proxy 127.0.0.1:8000" in rendered


@pytest.mark.parametrize(
    "target",
    [
        "127.0.0.1",
        "10.0.0.1",
        "192.168.1.1",
        "0.0.0.0",
        "203.0.113.10",
        "999.1.1.1",
        "2001:4860:4860::8888",
        "https://example.com",
        "example.com:443",
        "example.com/path",
        "example.com\n{",
        "$(whoami).com",
        "-x.example.com",
        "",
        "x.local",
        "x.internal",
        "x.test",
        "a" * 64 + ".com",
    ],
)
def test_invalid_targets_cannot_enter_caddy_or_shell(target):
    with pytest.raises(ValueError):
        target_kind(target)
