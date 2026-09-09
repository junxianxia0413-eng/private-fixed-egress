#!/usr/bin/python3
"""SOCKS5 authentication and TLS exit checks from the Gateway; secrets arrive on stdin."""

import http.client
import ipaddress
import json
import socket
import ssl
import struct
import sys
import time

TARGETS = ("api.ipify.org", "icanhazip.com")


class ProbeError(Exception):
    pass


def receive(sock, size):
    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise ProbeError("PROTOCOL_ERROR")
        data.extend(chunk)
    return bytes(data)


def endpoint(host):
    addresses = {row[4][0] for row in socket.getaddrinfo(host, None, socket.AF_INET)}
    if not addresses or any(not ipaddress.ip_address(ip).is_global for ip in addresses):
        raise ProbeError("INVALID_ENDPOINT")
    return sorted(addresses)[0]


def open_tunnel(address, port, username, password, target):
    sock = socket.create_connection((address, port), timeout=10)
    try:
        sock.sendall(b"\x05\x01\x02")
        if receive(sock, 2) != b"\x05\x02":
            raise ProbeError("AUTH_METHOD_REJECTED")
        sock.sendall(
            b"\x01" + bytes([len(username)]) + username + bytes([len(password)]) + password
        )
        if receive(sock, 2) != b"\x01\x00":
            raise ProbeError("AUTH_FAILED")
        domain = target.encode("ascii")
        sock.sendall(b"\x05\x01\x00\x03" + bytes([len(domain)]) + domain + struct.pack("!H", 443))
        reply = receive(sock, 4)
        if reply[:3] != b"\x05\x00\x00":
            raise ProbeError("CONNECT_REJECTED")
        sizes = {1: 4, 4: 16}
        size = receive(sock, 1)[0] if reply[3] == 3 else sizes.get(reply[3])
        if size is None:
            raise ProbeError("PROTOCOL_ERROR")
        receive(sock, size + 2)
        return sock
    except Exception:
        sock.close()
        raise


def request_ip(config, address, target):
    began = time.monotonic()
    with open_tunnel(
        address, config["port"], config["username"].encode(), config["password"].encode(), target
    ) as tunnel:
        with ssl.create_default_context().wrap_socket(tunnel, server_hostname=target) as tls:
            tls.sendall(
                (
                    f"GET / HTTP/1.1\r\nHost: {target}\r\nConnection: close\r\n"
                    "Accept: text/plain\r\nUser-Agent: PFEM/1\r\n\r\n"
                ).encode()
            )
            response = http.client.HTTPResponse(tls)
            response.begin()
            content = response.read(129)
            if response.status != 200 or len(content) > 128:
                raise ProbeError("IP_SERVICE_ERROR")
            try:
                actual = ipaddress.ip_address(content.decode("ascii").strip())
                if actual.version != 4 or not actual.is_global:
                    raise ValueError
            except (ValueError, UnicodeError):
                raise ProbeError("INVALID_EXIT_IP") from None
    return str(actual), round((time.monotonic() - began) * 1000, 1)


def probe(config):
    try:
        if (
            not isinstance(config["port"], int)
            or not 1 <= config["port"] <= 65535
            or not isinstance(config["host"], str)
            or len(config["host"]) > 253
            or any(not 1 <= len(config[k].encode()) <= 255 for k in ("username", "password"))
        ):
            raise ProbeError("INVALID_INPUT")
        address = endpoint(config["host"])
        first, latency1 = request_ip(config, address, TARGETS[0])
        second, latency2 = request_ip(config, address, TARGETS[1])
        if first != second:
            return {
                "ok": False,
                "error": "UNSTABLE_EXIT",
                "exit_ip": first,
                "second_exit_ip": second,
            }
        return {
            "ok": True,
            "exit_ip": first,
            "latency_ms": round((latency1 + latency2) / 2, 1),
            "sources": list(TARGETS),
        }
    except ProbeError as exc:
        return {"ok": False, "error": str(exc)}
    except TimeoutError:
        return {"ok": False, "error": "TIMEOUT"}
    except ssl.SSLError:
        return {"ok": False, "error": "TLS_FAILED"}
    except OSError:
        return {"ok": False, "error": "UNREACHABLE"}
    except Exception:
        return {"ok": False, "error": "PROBE_FAILED"}


def main():
    try:
        raw = sys.stdin.buffer.read(8193)
        if len(raw) > 8192:
            raise ValueError
        config = json.loads(raw)
    except (ValueError, TypeError):
        print(json.dumps({"ok": False, "error": "INVALID_INPUT"}))
        return
    print(json.dumps(probe(config)))


if __name__ == "__main__":
    main()
