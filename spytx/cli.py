from __future__ import annotations

import argparse
import json

from .geo import (
    copy_geo,
    copy_gmaps,
    inspect_best_geo,
    inspect_geo,
    inspect_geo_sources,
    inspect_precision,
    save_geo_map,
)
from .phone import inspect_phone
from .public_intel import (
    inspect_batch_ip,
    inspect_bgp,
    inspect_check_ip,
    inspect_contacts,
    inspect_ct,
    inspect_deep_ip,
    inspect_domain,
    inspect_dns,
    inspect_engines,
    inspect_external,
    inspect_ip,
    inspect_ip_health,
    inspect_lookup,
    inspect_my_ip,
    inspect_name,
    inspect_rdap,
    inspect_reverse_ip,
    inspect_ripe,
    inspect_social,
    inspect_tls,
    inspect_trace,
    inspect_web,
    inspect_whois,
)
from .reports import export_record, list_records, show_record, write_record
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

    sub.add_parser("iphealth", help="Show public IP module status.")
    sub.add_parser("engines", help="Show available SpyTX modules.")

    geo_cmd = sub.add_parser("geo", help="Inspect public network geolocation.")
    geo_cmd.add_argument("target")

    bestgeo_cmd = sub.add_parser("bestgeo", help="Select strongest public geolocation estimate.")
    bestgeo_cmd.add_argument("target")

    sources_cmd = sub.add_parser("providers", help="Compare public geolocation sources.")
    sources_cmd.add_argument("target")

    precision_cmd = sub.add_parser("precision", help="Score geolocation agreement.")
    precision_cmd.add_argument("target")

    copygeo_cmd = sub.add_parser("copygeo", help="Print copyable coordinate estimate.")
    copygeo_cmd.add_argument("target")

    copygmaps_cmd = sub.add_parser("copygmaps", help="Print public map link.")
    copygmaps_cmd.add_argument("target")

    map_cmd = sub.add_parser("map", help="Save a local geolocation report.")
    map_cmd.add_argument("target")

    batchip_cmd = sub.add_parser("batchip", help="Inspect multiple IP/domain targets.")
    batchip_cmd.add_argument("targets", nargs="+")

    domain_cmd = sub.add_parser("domain", help="Normalize and inspect a domain.")
    domain_cmd.add_argument("target")

    lookup_cmd = sub.add_parser("lookup", help="Inspect an IP or domain.")
    lookup_cmd.add_argument("target")

    dns_cmd = sub.add_parser("dns", help="Resolve common DNS records.")
    dns_cmd.add_argument("target")

    ct_cmd = sub.add_parser("ct", help="Build certificate transparency review links.")
    ct_cmd.add_argument("target")

    bgp_cmd = sub.add_parser("bgp", help="Build public routing review links.")
    bgp_cmd.add_argument("target")

    ripe_cmd = sub.add_parser("ripe", help="Build RIPE review links.")
    ripe_cmd.add_argument("target")

    reverseip_cmd = sub.add_parser("reverseip", help="Build reverse host review links.")
    reverseip_cmd.add_argument("target")

    external_cmd = sub.add_parser("external", help="Build external public review links.")
    external_cmd.add_argument("target")

    trace_cmd = sub.add_parser("trace", help="Sample local network path.")
    trace_cmd.add_argument("target")

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

    webcheck_cmd = sub.add_parser("webcheck", help="Inspect basic web posture.")
    webcheck_cmd.add_argument("target")

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

    history_cmd = sub.add_parser("history", help="List local result records.")
    history_cmd.add_argument("limit", nargs="?", type=int, default=10)

    show_cmd = sub.add_parser("show", help="Show a local result record.")
    show_cmd.add_argument("record_id", type=int)

    export_cmd = sub.add_parser("export", help="Export a local result record.")
    export_cmd.add_argument("record_id", type=int)
    export_cmd.add_argument("format", nargs="?", default="json", choices=["json", "txt"])

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
    elif args.command == "iphealth":
        payload = inspect_ip_health()
    elif args.command == "engines":
        payload = inspect_engines()
    elif args.command == "geo":
        payload = inspect_geo(args.target)
    elif args.command == "bestgeo":
        payload = inspect_best_geo(args.target)
    elif args.command == "providers":
        payload = inspect_geo_sources(args.target)
    elif args.command == "precision":
        payload = inspect_precision(args.target)
    elif args.command == "copygeo":
        payload = copy_geo(args.target)
    elif args.command == "copygmaps":
        payload = copy_gmaps(args.target)
    elif args.command == "map":
        payload = save_geo_map(args.target)
    elif args.command == "batchip":
        payload = inspect_batch_ip(args.targets)
    elif args.command == "domain":
        payload = inspect_domain(args.target)
    elif args.command == "lookup":
        payload = inspect_lookup(args.target)
    elif args.command == "dns":
        payload = inspect_dns(args.target)
    elif args.command == "ct":
        payload = inspect_ct(args.target)
    elif args.command == "bgp":
        payload = inspect_bgp(args.target)
    elif args.command == "ripe":
        payload = inspect_ripe(args.target)
    elif args.command == "reverseip":
        payload = inspect_reverse_ip(args.target)
    elif args.command == "external":
        payload = inspect_external(args.target)
    elif args.command == "trace":
        payload = inspect_trace(args.target)
    elif args.command == "whois":
        payload = inspect_whois(args.target)
    elif args.command == "contacts":
        payload = inspect_contacts(args.target)
    elif args.command == "intel":
        payload = inspect_lookup(args.target)
    elif args.command == "tls":
        payload = inspect_tls(args.target, args.port)
    elif args.command in {"web", "webcheck"}:
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
    elif args.command == "history":
        payload = list_records(args.limit)
    elif args.command == "show":
        payload = show_record(args.record_id)
    elif args.command == "export":
        payload = export_record(args.record_id, args.format)
    else:
        parser.error(f"unknown command: {args.command}")

    envelope: dict[str, object] = {"ok": True, "result": payload}
    if args.command not in {"history", "show", "export"}:
        envelope["record_id"] = write_record(args.command, payload)
    print(json.dumps(envelope, indent=2, ensure_ascii=True))
    return 0


def main() -> None:
    raise SystemExit(run())
