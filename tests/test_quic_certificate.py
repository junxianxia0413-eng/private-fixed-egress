"""Linux certificate renewal and lease isolation without touching host services."""

import datetime
import importlib
import ipaddress
import json
import os
import ssl
import time
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

pytestmark = pytest.mark.skipif(os.name != "posix", reason="Gateway is Linux")


def test_certificate_copy_checks_live_identity_key_and_expiry(tmp_path, monkeypatch):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    quic = importlib.import_module("gateways.quic")
    base = tmp_path / "gateway"
    base.mkdir()
    tls = base / "quic-tls"
    caddy = tmp_path / "caddy"
    source = caddy / "provider" / "8.8.8.8"
    source.mkdir(parents=True)
    for key, value in {
        "BASE": base,
        "TLS": tls,
        "CADDY": caddy,
        "MARKER": base / "quic-v1",
        "CERTIFICATE": tls / "certificate.pem",
        "KEY": tls / "key.pem",
        "METADATA": tls / "identity.json",
    }.items():
        monkeypatch.setattr(quic, key, value)
    (base / "https-ingress-v1").write_text("8.8.8.8\n")
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "8.8.8.8")])
    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(12)
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("8.8.8.8"))]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    pem = cert.public_bytes(serialization.Encoding.PEM)
    private = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    (source / "8.8.8.8.crt").write_bytes(pem)
    (source / "8.8.8.8.key").write_bytes(private)
    connection = MagicMock()
    tls_connection = MagicMock()
    tls_connection.getpeercert.side_effect = lambda binary_form=False: (
        ssl.PEM_cert_to_DER_cert(pem.decode())
        if binary_form
        else {"notAfter": (now + datetime.timedelta(days=1)).strftime("%b %d %H:%M:%S %Y GMT")}
    )
    context = MagicMock()
    context.wrap_socket.return_value.__enter__.return_value = tls_connection
    connect_socket = MagicMock(return_value=connection)
    monkeypatch.setattr(quic.socket, "create_connection", connect_socket)
    monkeypatch.setattr(quic.ssl, "create_default_context", lambda: context)
    monkeypatch.setattr(quic.pwd, "getpwnam", lambda _: SimpleNamespace(pw_gid=os.getgid()))
    monkeypatch.setattr(quic.os, "chown", lambda *a: None)
    assert quic.sync_certificate()["ok"] is True
    assert connect_socket.call_args.args[0] == ("8.8.8.8", 443)
    assert context.wrap_socket.call_args.kwargs["server_hostname"] == "8.8.8.8"
    assert quic.KEY.read_bytes() == private
    assert quic.KEY.stat().st_mode & 0o777 == 0o640
    assert quic.identity()["host"] == "8.8.8.8"
    (base / "config.json").write_text('{"inbounds":[{"type":"hysteria2"}]}')
    assert quic.ready() is True
    original = quic.KEY.read_bytes()
    other = ec.generate_private_key(ec.SECP256R1())
    (source / "8.8.8.8.key").write_bytes(
        other.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    with pytest.raises(ValueError, match="does not match"):
        quic.sync_certificate()
    assert quic.KEY.read_bytes() == original
    metadata = json.loads(quic.METADATA.read_text())
    metadata["not_after"] = time.time() - 1
    quic.METADATA.write_text(json.dumps(metadata))
    assert quic.ready() is False


def test_quic_leases_close_on_unverified_exit_or_certificate(monkeypatch):
    guard = importlib.import_module("gateways.guard")
    quic = importlib.import_module("gateways.quic")
    writes = []

    def command(args, **kwargs):
        if args[-1] == "-":
            writes.append(kwargs["input"].decode())
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(guard.subprocess, "run", command)
    monkeypatch.setattr(quic, "ready", lambda: True)
    guard.lease([20006], [13006])
    assert "23006 timeout 70s" in writes[-1]
    assert "25006 timeout 70s" in writes[-1]
    assert "13006" in writes[-1]
    guard.lease([], [])
    assert "flush set inet pfem_guard pfem_quic_live" in writes[-1]
    assert "add element" not in writes[-1]
    monkeypatch.setattr(quic, "ready", lambda: False)
    guard.lease([20006], [13006])
    assert "23006" not in writes[-1] and "13006" in writes[-1]
