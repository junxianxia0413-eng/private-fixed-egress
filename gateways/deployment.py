"""Pin software and host identity; never interpolate submitted fields into shell commands."""

import json
from pathlib import Path

from gateways.ssh import GatewayError, connect_gateway, execute

FILES = Path(__file__).resolve().parent
INITIAL_CONFIG = {
    "log": {"level": "warn"},
    "inbounds": [{"type": "socks", "tag": "health", "listen": "127.0.0.1", "listen_port": 10810}],
    "route": {"rules": [{"action": "reject"}]},
}
ADMIN = "sudo -n /usr/local/sbin/pfem-gateway-admin "


def health(client, action="status"):
    if action not in {"status", "reconcile", "restart", "harden", "commit-harden"}:
        raise ValueError("Unknown remote action")
    result = json.loads(execute(client, ADMIN + action, timeout=45))
    if not isinstance(result, dict) or result.get("healthy") is not True:
        raise GatewayError("网关核心检测未通过；请检查服务、配置和本机代理端口。")
    # Only return known fields from the remote host, never arbitrary diagnostic data.
    return {
        "probe_available": result.get("probe_available", False),
        "config_api": result.get("config_api", False),
        "phone_api": result.get("phone_api", False),
        "guard": {
            k: result.get("guard", {}).get(k)
            for k in (
                "healthy",
                "degraded",
                "checked_at",
                "groups",
                "results",
                "public_ports",
                "tls_ports",
                "transaction",
            )
        },
        **{
            k: result[k]
            for k in (
                "healthy",
                "service",
                "config_valid",
                "proxy_port",
                "cpu_percent",
                "ram_percent",
                "disk_percent",
                "version",
                "checked_at",
                "isp_bound",
                "egress_blocked",
                "ssh_key_only",
                "firewall",
            )
        },
    }


def bootstrap(gateway, credentials, managed):
    with connect_gateway(gateway, "root", credentials) as client:
        directory = execute(client, "mktemp -d /tmp/pfem-bootstrap.XXXXXXXX").strip()
        # The directory is returned by the server, so validate it before using it as code.
        import re

        if not re.fullmatch(r"/tmp/pfem-bootstrap\.[a-zA-Z0-9]{8}", directory):
            raise GatewayError("远程临时目录异常，已停止部署。")
        with client.open_sftp() as sftp:
            for name in (
                "bootstrap.sh",
                "remote_admin.py",
                "remote_probe.py",
                "gateway.service",
                "firewall.service",
                "configuration.py",
                "transactions.py",
                "recover.service",
                "__init__.py",
                "guard.py",
                "quality.py",
                "guard.service",
                "guard.timer",
            ):
                with sftp.open(f"{directory}/{name}", "w") as file:
                    file.write((FILES / name).read_bytes())
            for name, content in {
                "management.pub": "restrict " + managed["public_key"] + "\n",
                "recovery.pub": managed["recovery_public_key"] + "\n",
                "initial.json": json.dumps(INITIAL_CONFIG),
            }.items():
                with sftp.open(f"{directory}/{name}", "w") as file:
                    file.write(content)
        # Clean only the exact mktemp directory, including on failure; no submitted paths.
        result = execute(
            client,
            f"cd {directory} && bash bootstrap.sh; code=$?; rm -rf -- {directory}; exit $code",
            timeout=900,
        )
        if "PFEM_BOOTSTRAP_OK" not in result:
            raise GatewayError("部署未完成，请检测状态后重试。")


def deploy(gateway, store, stage):
    managed = store.get(gateway["managed_ref"])
    stage("CONNECTING")
    try:
        with connect_gateway(gateway, "proxyadmin", managed) as client:
            report = health(client, "reconcile")
            if (
                not report["probe_available"]
                or not report["config_api"]
                or report["phone_api"] != 8
            ):
                raise GatewayError("网关需要更新管理组件。")
    except GatewayError:
        # Recovery key first: a previous attempt may have installed keys already.
        stage("INSTALLING")
        try:
            bootstrap(gateway, {"private_key": managed["recovery_private_key"]}, managed)
        except GatewayError:
            if not gateway["bootstrap_ref"]:
                raise
            bootstrap(gateway, store.get(gateway["bootstrap_ref"]), managed)
    stage("VERIFYING_KEYS")
    with connect_gateway(gateway, "root", {"private_key": managed["recovery_private_key"]}):
        pass
    with connect_gateway(gateway, "proxyadmin", managed) as client:
        health(client)
        stage("HARDENING")
        health(client, "harden")
    # A remote rollback timer restores the SSH settings unless fresh connections succeed.
    with connect_gateway(gateway, "root", {"private_key": managed["recovery_private_key"]}):
        pass
    with connect_gateway(gateway, "proxyadmin", managed) as client:
        health(client, "commit-harden")
        stage("CHECKING")
        return health(client)


def inspect(gateway, store, kind):
    with connect_gateway(gateway, "proxyadmin", store.get(gateway["managed_ref"])) as client:
        report = health(client, "restart" if kind == "restart" else "status")
        if report["ssh_key_only"] is not True:
            raise GatewayError("SSH 密钥登录保护尚未完成，请重新部署。")
        return report
