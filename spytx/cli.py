from __future__ import annotations

import argparse
import json

from .phone import inspect_phone
from .public_intel import (
    inspect_batch_ip,
    inspect_check_ip,
    inspect_contacts,
    inspect_deep_ip,
    inspect_domain,
    inspect_dns,
    inspect_ip,
    inspect_lookup,
    inspect_my_ip,
    inspect_name,
    inspect_rdap,
    inspect_social,
    inspect_tls,
    inspect_web,
    inspect_whois,
)
from .username import inspect_username


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="spytx",
        description="SpyTX public-intelligence terminal toolkit.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    ip_cmd = sub.add_parser("ip", help="Inspect a public IP address.")
    ip_cmd.add_argument("target")

    deepip_cmd = sub.add_parser("deepip", help="Inspect IP metadata with local risk hints.")
    deepip_cmd.add_argument("target")

    checkip_cmd = sub.add_parser("checkip", help="Check visible public IP metadata.")
    checkip_cmd.add_argument("target")

    batchip_cmd = sub.add_parser("batchip", help="Inspect multiple IP/domain targets.")
    batchip_cmd.add_argument("targets", nargs="+")

    domain_cmd = sub.add_parser("domain", help="Normalize and inspect a domain.")
    domain_cmd.add_argument("target")

    lookup_cmd = sub.add_parser("lookup", help="Inspect an IP or domain.")
    lookup_cmd.add_argument("target")

    dns_cmd = sub.add_parser("dns", help="Resolve common DNS records.")
    dns_cmd.add_argument("target")

    whois_cmd = sub.add_parser("whois", help="Build public registration review links.")
    whois_cmd.add_argument("target")

    contacts_cmd = sub.add_parser("contacts", help="Build public contact review links.")
    contacts_cmd.add_argument("target")

    intel_cmd = sub.add_parser("intel", help="Run a compact public intel lookup.")
    intel_cmd.add_argument("target")

    tls_cmd = sub.add_parser("tls", help="Inspect a TLS certificate.")
    tls_cmd.add_argument("target")
    tls_cmd.add_argument("--port", type=int, default=443)

    web_cmd = sub.add_parser("web", help="Inspect basic web posture.")
    web_cmd.add_argument("target")

    phone_cmd = sub.add_parser("phone", help="Inspect safe phone metadata.")
    phone_cmd.add_argument("number")
    phone_cmd.add_argument("region", nargs="?")

    social_cmd = sub.add_parser("social", help="Build public social/name review links.")
    social_cmd.add_argument("value")

    name_cmd = sub.add_parser("name", help="Build exact-name review links.")
    name_cmd.add_argument("value")

    username_cmd = sub.add_parser("username", help="Build public username review links.")
    username_cmd.add_argument("username")

    rdap_cmd = sub.add_parser("rdap", help="Build public RDAP review links.")
    rdap_cmd.add_argument("target")

    sub.add_parser("myip", help="Inspect this network public IP.")

    return parser


def run(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "ip":
        payload = inspect_ip(args.target)
    elif args.command == "deepip":
        payload = inspect_deep_ip(args.target)
    elif args.command == "checkip":
        payload = inspect_check_ip(args.target)
    elif args.command == "batchip":
        payload = inspect_batch_ip(args.targets)
    elif args.command == "domain":
        payload = inspect_domain(args.target)
    elif args.command == "lookup":
        payload = inspect_lookup(args.target)
    elif args.command == "dns":
        payload = inspect_dns(args.target)
    elif args.command == "whois":
        payload = inspect_whois(args.target)
    elif args.command == "contacts":
        payload = inspect_contacts(args.target)
    elif args.command == "intel":
        payload = inspect_lookup(args.target)
    elif args.command == "tls":
        payload = inspect_tls(args.target, args.port)
    elif args.command == "web":
        payload = inspect_web(args.target)
    elif args.command == "phone":
        payload = inspect_phone(args.number, args.region)
    elif args.command == "social":
        payload = inspect_social(args.value)
    elif args.command == "name":
        payload = inspect_name(args.value)
    elif args.command == "username":
        payload = inspect_username(args.username)
    elif args.command == "rdap":
        payload = inspect_rdap(args.target)
    elif args.command == "myip":
        payload = inspect_my_ip()
    else:
        parser.error(f"unknown command: {args.command}")

    print(json.dumps({"ok": True, "result": payload}, indent=2, ensure_ascii=True))
    return 0


def main() -> None:
    raise SystemExit(run())
