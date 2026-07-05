from __future__ import annotations

import argparse
import json
from .domain import inspect_domain, inspect_dns, inspect_tls, inspect_web
from .ip import inspect_ip
from .phone import inspect_phone
from .username import inspect_username


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="spytx",
        description="SpyTX public-intelligence terminal toolkit.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    ip_cmd = sub.add_parser("ip", help="Inspect a public IP address.")
    ip_cmd.add_argument("target")

    domain_cmd = sub.add_parser("domain", help="Normalize and inspect a domain.")
    domain_cmd.add_argument("target")

    dns_cmd = sub.add_parser("dns", help="Resolve common DNS records.")
    dns_cmd.add_argument("target")

    tls_cmd = sub.add_parser("tls", help="Inspect a TLS certificate.")
    tls_cmd.add_argument("target")
    tls_cmd.add_argument("--port", type=int, default=443)

    web_cmd = sub.add_parser("web", help="Inspect basic web posture.")
    web_cmd.add_argument("target")

    phone_cmd = sub.add_parser("phone", help="Inspect safe phone metadata.")
    phone_cmd.add_argument("number")
    phone_cmd.add_argument("region", nargs="?")

    username_cmd = sub.add_parser("username", help="Build public username review links.")
    username_cmd.add_argument("username")

    return parser


def run(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "ip":
        payload = inspect_ip(args.target)
    elif args.command == "domain":
        payload = inspect_domain(args.target)
    elif args.command == "dns":
        payload = inspect_dns(args.target)
    elif args.command == "tls":
        payload = inspect_tls(args.target, args.port)
    elif args.command == "web":
        payload = inspect_web(args.target)
    elif args.command == "phone":
        payload = inspect_phone(args.number, args.region)
    elif args.command == "username":
        payload = inspect_username(args.username)
    else:
        parser.error(f"unknown command: {args.command}")

    print(json.dumps({"ok": True, "result": payload}, indent=2, ensure_ascii=True))
    return 0


def main() -> None:
    raise SystemExit(run())
