from __future__ import annotations

import json
import os
import shlex
import sys
from typing import Callable

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


BLUE = "\033[94m"
CYAN = "\033[96m"
RED = "\033[91m"
WHITE = "\033[97m"
DIM = "\033[90m"
RESET = "\033[0m"


def clear_screen() -> None:
    if sys.stdout.isatty():
        os.system("cls" if os.name == "nt" else "clear")


def boot_screen() -> None:
    clear_screen()
    print(f"{BLUE}   _____             _______  __{RESET}")
    print(f"{BLUE}  / ___/____  __  __/_  __/ |/ /{RESET}")
    print(f"{RED}  \\__ \\/ __ \\/ / / / / /  |   / {RESET}")
    print(f"{RED} ___/ / /_/ / /_/ / / /  /   |  {RESET}")
    print(f"{WHITE}/____/ .___/\\__, / /_/  /_/|_|  {RESET}")
    print(f"{WHITE}    /_/    /____/              {RESET}")
    print(f"{WHITE}SpyTX public intelligence terminal toolkit{RESET}")
    print()
    print(f"{CYAN}[OK]{RESET} SpyTX terminal loaded")
    print(f"{CYAN}[OK]{RESET} Public metadata scope active")
    print(f"{CYAN}[OK]{RESET} Commands ready")
    print()


def dashboard() -> None:
    print(f"{WHITE}+------------------------------+---------------------------------+------------------------------+{RESET}")
    print(f"{WHITE}|{RESET} {BLUE}[01] IP INTEL{RESET}              {WHITE}|{RESET} {RED}[02] DOMAIN / DNS{RESET}             {WHITE}|{RESET} {CYAN}[03] WEB POSTURE{RESET}          {WHITE}|{RESET}")
    print(f"{WHITE}|{RESET} /ip /deepip /checkip       {WHITE}|{RESET} /domain /lookup /dns /whois    {WHITE}|{RESET} /webcheck /tls /rdap       {WHITE}|{RESET}")
    print(f"{WHITE}+------------------------------+---------------------------------+------------------------------+{RESET}")
    print(f"{WHITE}|{RESET} {BLUE}[04] PHONE META{RESET}            {WHITE}|{RESET} {RED}[05] SOCIAL / NAME{RESET}            {WHITE}|{RESET} {CYAN}[06] REPORTS{RESET}              {WHITE}|{RESET}")
    print(f"{WHITE}|{RESET} /phone <number> [region]    {WHITE}|{RESET} /social <name> /name <name>    {WHITE}|{RESET} JSON audit output          {WHITE}|{RESET}")
    print(f"{WHITE}+------------------------------+---------------------------------+------------------------------+{RESET}")
    print(f"{WHITE}|{RESET} {BLUE}[07] NETWORK{RESET}               {WHITE}|{RESET} {RED}[08] HELP{RESET}                     {WHITE}|{RESET} {CYAN}[09] EXIT{RESET}                 {WHITE}|{RESET}")
    print(f"{WHITE}|{RESET} myip /batchip targets       {WHITE}|{RESET} help / menu / clear            {WHITE}|{RESET} exit / quit                 {WHITE}|{RESET}")
    print(f"{WHITE}+------------------------------+---------------------------------+------------------------------+{RESET}")
    print()


def run_terminal() -> None:
    boot_screen()
    dashboard()
    while True:
        try:
            raw = input(f"{CYAN}SpyTX>{RESET} ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            print("bye")
            return
        if not raw:
            continue
        if raw.lower() in {"exit", "quit", "q"}:
            print("bye")
            return
        if raw.lower() in {"help", "menu", "dashboard"}:
            dashboard()
            continue
        if raw.lower() in {"clear", "cls"}:
            boot_screen()
            dashboard()
            continue
        _dispatch(raw)


def _dispatch(raw: str) -> None:
    parts = shlex.split(raw)
    command = parts[0].lower().lstrip("/")
    args = parts[1:]
    handlers: dict[str, Callable[[list[str]], dict[str, object]]] = {
        "ip": _ip,
        "deepip": _deepip,
        "checkip": _checkip,
        "batchip": _batchip,
        "domain": _domain,
        "lookup": _lookup,
        "intel": _lookup,
        "dns": _dns,
        "whois": _whois,
        "contacts": _contacts,
        "tls": _tls,
        "rdap": _rdap,
        "web": _web,
        "webcheck": _web,
        "phone": _phone,
        "social": _social,
        "name": _name,
        "username": _social,
        "myip": _myip,
    }
    handler = handlers.get(command)
    if handler is None:
        print(f"{RED}Unknown command.{RESET} Type help for the dashboard.")
        return
    try:
        payload = handler(args)
    except Exception as exc:
        print(f"{RED}Error:{RESET} {exc}")
        return
    _print_payload(payload)


def _print_payload(payload: dict[str, object]) -> None:
    print(f"{WHITE}+-- result -------------------------------------------------------------------+{RESET}")
    print(json.dumps(payload, indent=2, ensure_ascii=True))
    print(f"{WHITE}+-----------------------------------------------------------------------------+{RESET}")


def _require(args: list[str], usage: str, minimum: int = 1) -> None:
    if len(args) < minimum:
        raise ValueError(f"usage: {usage}")


def _ip(args: list[str]) -> dict[str, object]:
    _require(args, "ip <address>")
    return inspect_ip(args[0])


def _deepip(args: list[str]) -> dict[str, object]:
    _require(args, "deepip <ip|domain>")
    return inspect_deep_ip(args[0])


def _checkip(args: list[str]) -> dict[str, object]:
    _require(args, "checkip <ip|domain>")
    return inspect_check_ip(args[0])


def _batchip(args: list[str]) -> dict[str, object]:
    _require(args, "batchip <target1> <target2> ...")
    return inspect_batch_ip(args)


def _domain(args: list[str]) -> dict[str, object]:
    _require(args, "domain <host>")
    return inspect_domain(args[0])


def _lookup(args: list[str]) -> dict[str, object]:
    _require(args, "lookup <ip|domain>")
    return inspect_lookup(args[0])


def _dns(args: list[str]) -> dict[str, object]:
    _require(args, "dns <host>")
    return inspect_dns(args[0])


def _whois(args: list[str]) -> dict[str, object]:
    _require(args, "whois <domain>")
    return inspect_whois(args[0])


def _contacts(args: list[str]) -> dict[str, object]:
    _require(args, "contacts <domain>")
    return inspect_contacts(args[0])


def _tls(args: list[str]) -> dict[str, object]:
    _require(args, "tls <host> [port]")
    port = int(args[1]) if len(args) > 1 else 443
    return inspect_tls(args[0], port)


def _rdap(args: list[str]) -> dict[str, object]:
    _require(args, "rdap <ip|domain>")
    return inspect_rdap(args[0])


def _web(args: list[str]) -> dict[str, object]:
    _require(args, "web <host>")
    return inspect_web(args[0])


def _phone(args: list[str]) -> dict[str, object]:
    _require(args, "phone <number> [region]")
    region = args[1] if len(args) > 1 else None
    return inspect_phone(args[0], region)


def _social(args: list[str]) -> dict[str, object]:
    _require(args, "social <username|full name>")
    return inspect_social(" ".join(args))


def _name(args: list[str]) -> dict[str, object]:
    _require(args, "name <full name>")
    return inspect_name(" ".join(args))


def _myip(args: list[str]) -> dict[str, object]:
    if args:
        raise ValueError("usage: myip")
    return inspect_my_ip()
