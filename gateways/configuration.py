"""Render only supported, fail-closed topology from validated structured inputs."""

import ipaddress
import re


def address(value):
    ip = ipaddress.ip_address(value)
    if ip.version != 4 or not ip.is_global:
        raise ValueError("Public IPv4 required")
    return str(ip)


def validate(groups):
    if not isinstance(groups, list) or len(groups) > 20:
        raise ValueError("At most 20 exit groups per Gateway")
    seen = set()
    clients_seen = set()
    for group in groups:
        if set(group) - {"clients"} != {
            "id",
            "enabled",
            "server",
            "port",
            "username",
            "password",
            "expected_ip",
            "probe_username",
            "probe_password",
        }:
            raise ValueError("Invalid group fields")
        identifier = group["id"]
        if type(identifier) is not int or not 1 <= identifier <= 1000 or identifier in seen:
            raise ValueError("Invalid or duplicate group id")
        seen.add(identifier)
        if (
            type(group["enabled"]) is not bool
            or type(group["port"]) is not int
            or not 1 <= group["port"] <= 65535
        ):
            raise ValueError("Invalid group state or port")
        address(group["server"])
        address(group["expected_ip"])
        for key in ("username", "password", "probe_username", "probe_password"):
            if not isinstance(group[key], str) or not 1 <= len(group[key].encode()) <= 255:
                raise ValueError("Invalid credentials")
        if not re.fullmatch("[a-zA-Z0-9_-]{32,128}", group["probe_password"]):
            raise ValueError("Generated probe credential required")
        clients = group.get("clients", [])
        if not isinstance(clients, list) or len(clients) > 20:
            raise ValueError("Invalid subscription clients")
        for client in clients:
            if (
                set(client) != {"id", "password"}
                or type(client["id"]) is not int
                or not 1 <= client["id"] <= 1000
                or client["id"] in clients_seen
            ):
                raise ValueError("Invalid subscription identity")
            if not isinstance(client["password"], str) or not re.fullmatch(
                "[a-zA-Z0-9_-]{40,128}", client["password"]
            ):
                raise ValueError("Generated subscription credential required")
            clients_seen.add(client["id"])
    if len(clients_seen) > 20:
        raise ValueError("At most 20 subscriptions per Gateway")
    return groups


def render(groups, proxy_uid):
    validate(groups)
    if type(proxy_uid) is not int or not 1 <= proxy_uid < 65536:
        raise ValueError("Invalid service UID")
    config = {
        "log": {"level": "warn"},
        "inbounds": [
            {"type": "socks", "tag": "health", "listen": "127.0.0.1", "listen_port": 10810}
        ],
        "outbounds": [],
        "route": {"rules": [{"inbound": ["health"], "action": "reject"}]},
    }
    allowed = set()
    public_ports = []
    ports = [10810]
    for group in groups:
        identifier = group["id"]
        tag = f"exit-{identifier}"
        port = 12000 + identifier
        ports.append(port)
        config["inbounds"].append(
            {
                "type": "socks",
                "tag": tag,
                "listen": "127.0.0.1",
                "listen_port": port,
                "users": [
                    {"username": group["probe_username"], "password": group["probe_password"]}
                ],
            }
        )
        inbound_tags = [tag]
        for client in group.get("clients", []):
            client_tag = f"subscription-{client['id']}"
            public_ports.append(20000 + client["id"])
            inbound_tags.append(client_tag)
            config["inbounds"].append(
                {
                    "type": "shadowsocks",
                    "tag": client_tag,
                    "listen": "0.0.0.0",
                    "listen_port": 20000 + client["id"],
                    "network": "tcp",
                    "method": "aes-128-gcm",
                    "password": client["password"],
                }
            )
        if group["enabled"]:
            outbound = f"isp-{identifier}"
            config["outbounds"].append(
                {
                    "type": "socks",
                    "tag": outbound,
                    "server": group["server"],
                    "server_port": group["port"],
                    "version": "5",
                    "username": group["username"],
                    "password": group["password"],
                    "network": "tcp",
                }
            )
            config["route"]["rules"].append(
                {"inbound": inbound_tags, "action": "route", "outbound": outbound}
            )
            allowed.add((group["server"], group["port"]))
        else:
            config["route"]["rules"].append({"inbound": inbound_tags, "action": "reject"})
    config["route"]["rules"].append({"action": "reject"})
    firewall = [
        "add table inet pfem_guard",
        "flush table inet pfem_guard",
        "add set inet pfem_guard pfem_live { type inet_service; flags timeout; timeout 70s; }",
        "add chain inet pfem_guard input { type filter hook input priority -10; policy accept; }",
        'add rule inet pfem_guard input iifname != "lo" tcp dport 20001-21000 '
        "tcp dport != @pfem_live drop",
        'add rule inet pfem_guard input iifname != "lo" tcp dport { '
        + ", ".join(map(str, ports))
        + " } drop",
        "add chain inet pfem_guard output { type filter hook output priority -10; policy accept; }",
    ]
    if public_ports:
        firewall.append(
            f"add rule inet pfem_guard output meta skuid {proxy_uid} "
            "ct direction reply tcp sport { " + ", ".join(map(str, public_ports)) + " } accept"
        )
    for ip, port in sorted(allowed):
        firewall.append(
            f"add rule inet pfem_guard output meta skuid {proxy_uid} "
            f"ip daddr {ip} tcp dport {port} accept"
        )
    firewall.extend(
        [
            f"add rule inet pfem_guard output meta skuid {proxy_uid} "
            "ip daddr != 127.0.0.0/8 reject",
            f"add rule inet pfem_guard output meta skuid {proxy_uid} ip6 daddr != ::1 reject",
        ]
    )
    return config, "\n".join(firewall) + "\n"
