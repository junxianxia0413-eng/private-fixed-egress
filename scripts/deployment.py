"""Validate a public deployment target and render Caddy without shell interpolation."""

import argparse
import ipaddress
import re
from pathlib import Path


def target_kind(target: str) -> str:
    try:
        address = ipaddress.ip_address(target)
    except ValueError:
        if len(target) > 253 or not re.fullmatch(
            r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}", target
        ):
            raise ValueError("Use a DNS hostname or a public IPv4 address") from None
        if target.lower().endswith((".local", ".localhost", ".internal", ".test", ".invalid")):
            raise ValueError("A public DNS hostname is required") from None
        return "dns"
    if address.version != 4 or not address.is_global:
        raise ValueError("IP certificates require a public IPv4 address in this installer")
    return "ipv4"


def render_caddy(target: str) -> str:
    kind = target_kind(target)
    template = "Caddyfile.ip.template" if kind == "ipv4" else "Caddyfile.template"
    path = Path(__file__).resolve().parents[1] / "deploy" / template
    return path.read_text(encoding="utf-8").replace("__DOMAIN__", target)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=["validate", "caddy"])
    parser.add_argument("target")
    args = parser.parse_args()
    try:
        print(target_kind(args.target) if args.action == "validate" else render_caddy(args.target))
    except ValueError as exc:
        raise SystemExit(str(exc)) from None


if __name__ == "__main__":
    main()
