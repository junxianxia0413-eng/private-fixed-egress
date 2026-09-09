import base64
import hashlib
import io
import time

import paramiko
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


class GatewayError(Exception):
    """Safe, operator-readable error; never include remote command output or secrets."""


def generate_key():
    key = Ed25519PrivateKey.generate()
    private = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.OpenSSH,
        serialization.NoEncryption(),
    ).decode()
    public = (
        key.public_key()
        .public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH)
        .decode()
    )
    return private, public


def parse_host_key(value: str):
    parts = value.strip().split()
    if len(parts) != 2 or parts[0] != "ssh-ed25519":
        raise ValueError("Provide the server's ssh-ed25519 public host key")
    try:
        return paramiko.Ed25519Key(data=base64.b64decode(parts[1], validate=True))
    except Exception:
        raise ValueError("Invalid SSH host key") from None


def fingerprint(key):
    return "SHA256:" + base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode().rstrip("=")


def connect_gateway(gateway, username, credentials):
    client = paramiko.SSHClient()
    host = gateway["host"]
    key_host = host if gateway["ssh_port"] == 22 else f"[{host}]:{gateway['ssh_port']}"
    client.get_host_keys().add(key_host, "ssh-ed25519", parse_host_key(gateway["host_key"]))
    client.set_missing_host_key_policy(paramiko.RejectPolicy())
    try:
        pkey = None
        if credentials.get("private_key"):
            pkey = paramiko.Ed25519Key.from_private_key(io.StringIO(credentials["private_key"]))
        client.connect(
            host,
            port=gateway["ssh_port"],
            username=username,
            pkey=pkey,
            password=credentials.get("password"),
            look_for_keys=False,
            allow_agent=False,
            timeout=12,
            auth_timeout=15,
            banner_timeout=15,
        )
        client.get_transport().set_keepalive(20)
        return client
    except paramiko.BadHostKeyException:
        client.close()
        raise GatewayError("SSH 主机密钥变化，已拒绝连接。请先核实服务器身份。") from None
    except paramiko.AuthenticationException:
        client.close()
        raise GatewayError("SSH 认证失败，请核对账户或凭据。") from None
    except Exception:
        client.close()
        raise GatewayError("SSH 连接失败，请检查服务器、端口和防火墙。") from None


def execute(client, command, *, stdin=b"", timeout=30):
    channel = client.get_transport().open_session(timeout=12)
    try:
        channel.exec_command(command)
        if stdin:
            channel.sendall(stdin)
        channel.shutdown_write()
        output = bytearray()
        deadline = time.monotonic() + timeout
        while True:
            if channel.recv_ready():
                output.extend(channel.recv(32768))
            if channel.recv_stderr_ready():
                channel.recv_stderr(32768)  # Do not expose untrusted diagnostic output.
            if len(output) > 1048576:
                raise GatewayError("远程输出超过限制，操作已停止。")
            if (
                channel.exit_status_ready()
                and not channel.recv_ready()
                and not channel.recv_stderr_ready()
            ):
                break
            if time.monotonic() > deadline:
                raise GatewayError("远程操作超时；请检测状态后重试。")
            time.sleep(0.05)
        code = channel.recv_exit_status()
        if code:
            raise GatewayError(f"远程操作失败（状态码 {code}），保留当前配置，可检测后重试。")
        return output.decode("utf-8")
    finally:
        channel.close()
