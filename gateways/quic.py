"""Reuse the gateway's verified, automatically renewed HTTPS identity for QUIC."""

import hashlib
import ipaddress
import json
import os
import pwd
import re
import socket
import ssl
import subprocess
import time
from pathlib import Path

BASE = Path("/etc/pfem-gateway")
TLS = BASE / "quic-tls"
MARKER = BASE / "quic-v1"
CADDY = Path("/var/lib/caddy/.local/share/caddy/certificates")
CERTIFICATE = TLS / "certificate.pem"
KEY = TLS / "key.pem"
METADATA = TLS / "identity.json"


def identity():
    try:
        value = json.loads(METADATA.read_text())
        if (
            MARKER.read_text().strip() != "1"
            or value.get("version") != 1
            or not ipaddress.ip_address(value["host"]).is_global
            or value["not_after"] - time.time() < 300
            or not CERTIFICATE.is_file()
            or not KEY.is_file()
        ):
            return None
        return value
    except (OSError, ValueError, KeyError, TypeError):
        return None


def ready():
    if identity() is None:
        return False
    try:
        config = json.loads((BASE / "config.json").read_text())
        return any(row.get("type") == "hysteria2" for row in config.get("inbounds", []))
    except (OSError, ValueError, TypeError):
        return False


def obfs_ready():
    if not ready():
        return False
    try:
        config = json.loads((BASE / "config.json").read_text())
        return any(
            row.get("type") == "hysteria2" and row.get("obfs", {}).get("type") == "salamander"
            for row in config.get("inbounds", [])
        )
    except (OSError, ValueError, TypeError, AttributeError):
        return False


def atomic(path, content, gid, mode=0o640):
    stage = path.with_name(path.name + ".new")
    with stage.open("wb") as output:
        output.write(content)
        output.flush()
        os.fsync(output.fileno())
    os.chown(stage, 0, gid)
    stage.chmod(mode)
    os.replace(stage, path)


def sync_certificate():
    """Verify the live CA chain, IP and matching private key before copying it."""
    host = (BASE / "https-ingress-v1").read_text().strip()
    if ipaddress.ip_address(host).version != 4 or not ipaddress.ip_address(host).is_global:
        raise ValueError("Invalid gateway identity")
    # IP addresses are not sent as TLS SNI. Caddy selects its IP certificate from
    # the connection's local address, so connect to the gateway's public IP.
    with socket.create_connection((host, 443), timeout=8) as connection:
        with ssl.create_default_context().wrap_socket(connection, server_hostname=host) as tls:
            live_der = tls.getpeercert(binary_form=True)
            not_after = ssl.cert_time_to_seconds(tls.getpeercert()["notAfter"])
    if not_after - time.time() < 3600:
        raise ValueError("Gateway certificate must have at least one hour remaining")
    selected = None
    for candidate in CADDY.glob(f"*/{host}/{host}.crt"):
        chain = candidate.read_bytes()
        leaf = re.search(b"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", chain, re.S)
        if leaf and ssl.PEM_cert_to_DER_cert(leaf[0].decode()) == live_der:
            selected = (chain, candidate.with_suffix(".key").read_bytes())
            break
    if selected is None:
        raise ValueError("No Caddy certificate matches the verified live identity")
    chain, key = selected
    public_certificate = subprocess.run(
        ["openssl", "x509", "-pubkey", "-noout"],
        input=chain,
        capture_output=True,
        timeout=8,
        check=True,
    ).stdout
    public_key = subprocess.run(
        ["openssl", "pkey", "-pubout"],
        input=key,
        capture_output=True,
        timeout=8,
        check=True,
    ).stdout
    if public_key != public_certificate:
        raise ValueError("Gateway TLS key does not match its certificate")
    gid = pwd.getpwnam("pfem-proxy").pw_gid
    TLS.mkdir(mode=0o750, exist_ok=True)
    os.chown(TLS, 0, gid)
    # sing-box watches both certificate files and reloads the pair after renewal.
    # Avoid rewriting unchanged files on every timer tick.
    for path, content in ((KEY, key), (CERTIFICATE, chain)):
        if not path.exists() or path.read_bytes() != content:
            atomic(path, content, gid)
    metadata = {
        "version": 1,
        "host": host,
        "not_after": not_after,
        "certificate_sha256": hashlib.sha256(live_der).hexdigest(),
    }
    atomic(METADATA, json.dumps(metadata).encode(), gid)
    atomic(MARKER, b"1\n", gid)
    return {"ok": True, "host": host, "not_after": not_after}


if __name__ == "__main__":
    try:
        print(json.dumps(sync_certificate()))
    except Exception:
        # Never print certificate source files, keys or raw subprocess errors.
        print(json.dumps({"ok": False, "error": "QUIC_CERTIFICATE_SYNC_FAILED"}))
        raise SystemExit(1) from None
