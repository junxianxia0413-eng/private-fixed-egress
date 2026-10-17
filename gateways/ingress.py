"""Prepare a public HTTPS ingress for a standalone Gateway without replacing a Controller."""

import http.client
import ipaddress
import json
import sys
from pathlib import Path

MARKER = "# Managed by Private Fixed-Egress Network Manager"


def render(host):
    address = ipaddress.ip_address(host)
    if address.version != 4 or not address.is_global:
        raise ValueError("A public Gateway IPv4 is required")
    return f"""{MARKER}
https://{address}, https://{address}:8443 {{
    tls {{
        issuer acme {{
            dir https://acme-v02.api.letsencrypt.org/directory
            profile shortlived
        }}
    }}
    route {{
        @pfem_ws path_regexp pfem_ws ^/pfem-ws/(13[0-9]{{3}}|14000)$
        reverse_proxy @pfem_ws 127.0.0.1:{{re.pfem_ws.1}}
        respond /healthz "Gateway online" 200
        respond "Private Gateway" 404
    }}
}}
"""


def prepare(host, existing):
    candidate = render(host)
    if existing and MARKER in existing.splitlines():
        if host not in existing or "path_regexp pfem_ws" not in existing:
            raise ValueError("Existing managed ingress does not match the Gateway")
        # Keep the Controller reverse proxy and any existing verified site settings.
        return existing
    factory = " ".join(
        line.strip()
        for line in existing.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    )
    if factory and factory not in {
        ":80 { root * /usr/share/caddy file_server }",
        ":80 { root /usr/share/caddy file_server }",
    }:
        raise ValueError("Unmanaged Caddy site requires review")
    return candidate


def check_https(host):
    try:
        render(host)
        connection = http.client.HTTPSConnection(host, 443, timeout=3)
        try:
            connection.request("GET", "/healthz")
            response = connection.getresponse()
            response.read(128)
            return response.status == 200
        finally:
            connection.close()
    except Exception:
        return False


if __name__ == "__main__":
    value = json.loads(Path(sys.argv[1]).read_text())
    if set(value) != {"host"}:
        raise SystemExit(64)
    host = value["host"]
    if sys.argv[2] == "host":
        render(host)
        print(host)
    elif sys.argv[2] == "config":
        path = Path("/etc/caddy/Caddyfile")
        print(prepare(host, path.read_text() if path.exists() else ""), end="")
    else:
        raise SystemExit(64)
