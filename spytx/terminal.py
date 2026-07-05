from __future__ import annotations

import json
import os
from typing import Callable

from .domain import inspect_domain, inspect_dns, inspect_tls, inspect_web
from .ip import inspect_ip
from .phone import inspect_phone
from .username import inspect_username


BLUE = "\033[94m"
CYAN = "\033[96m"
RED = "\033[91m"
WHITE = "\033[97m"
DIM = "\033[90m"
RESET = "\033[0m"


def clear_screen() -> None:
    os.system("cls" if os.name == "nt" else "clear")


def boot_screen() -> None:
    clear_screen()
    print(f"{BLUE}  _______  _______  __   __  _______  __   __ {RESET}")
    print(f"{BLUE} |       ||       ||  | |  ||       ||  |_|  |{RESET}")
    print(f"{RED} |  _____||    _  ||  |_|  ||_     _||       |{RESET}")
    print(f"{RED} | |_____ |   |_| ||       |  |   |  |       |{RESET}")
    print(f"{WHITE}|_____  ||    ___||_     _|  |   |  |       |{RESET}")
    print(f"{WHITE} _____| ||   |      |   |    |   |  | ||_|| |{RESET}")
    print(f"{WHITE}|_______||___|      |___|    |___|  |_|   |_|{RESET}")
    print()
    print(f"{CYAN}[OK]{RESET} SpyTX terminal loaded")
    print(f"{CYAN}[OK]{RESET} Public metadata scope active")
    print(f"{CYAN}[OK]{RESET} Commands ready")
    print()


def dashboard() -> None:
    print(f"{WHITE}+----------------------+----------------------+----------------------+{RESET}")
    print(f"{WHITE}|{RESET} {BLUE}[01] IP{RESET}              {WHITE}|{RESET} {RED}[02] DOMAIN{RESET}          {WHITE}|{RESET} {CYAN}[03] DNS{RESET}             {WHITE}|{RESET}")
    print(f"{WHITE}|{RESET} ip <address>        {WHITE}|{RESET} domain <host>       {WHITE}|{RESET} dns <host>          {WHITE}|{RESET}")
    print(f"{WHITE}+----------------------+----------------------+----------------------+{RESET}")
    print(f"{WHITE}|{RESET} {BLUE}[04] TLS{RESET}             {WHITE}|{RESET} {RED}[05] WEB{RESET}             {WHITE}|{RESET} {CYAN}[06] PHONE{RESET}           {WHITE}|{RESET}")
    print(f"{WHITE}|{RESET} tls <host>          {WHITE}|{RESET} web <host>          {WHITE}|{RESET} phone <num> [CC]    {WHITE}|{RESET}")
    print(f"{WHITE}+----------------------+----------------------+----------------------+{RESET}")
    print(f"{WHITE}|{RESET} {BLUE}[07] USERNAME{RESET}        {WHITE}|{RESET} {RED}[08] HELP{RESET}            {WHITE}|{RESET} {CYAN}[09] EXIT{RESET}            {WHITE}|{RESET}")
    print(f"{WHITE}|{RESET} username <name>     {WHITE}|{RESET} help                {WHITE}|{RESET} exit                {WHITE}|{RESET}")
    print(f"{WHITE}+----------------------+----------------------+----------------------+{RESET}")
    print()


def run_terminal() -> None:
    boot_screen()
    dashboard()
    while True:
        try:
            raw = input(f"{CYAN}spytx>{RESET} ").strip()
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
        _dispatch(raw)


def _dispatch(raw: str) -> None:
    parts = raw.split()
    command = parts[0].lower()
    args = parts[1:]
    handlers: dict[str, Callable[[list[str]], dict[str, object]]] = {
        "ip": _ip,
        "domain": _domain,
        "dns": _dns,
        "tls": _tls,
        "web": _web,
        "phone": _phone,
        "username": _username,
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
    print(json.dumps(payload, indent=2, ensure_ascii=True))


def _require(args: list[str], usage: str, minimum: int = 1) -> None:
    if len(args) < minimum:
        raise ValueError(f"usage: {usage}")


def _ip(args: list[str]) -> dict[str, object]:
    _require(args, "ip <address>")
    return inspect_ip(args[0])


def _domain(args: list[str]) -> dict[str, object]:
    _require(args, "domain <host>")
    return inspect_domain(args[0])


def _dns(args: list[str]) -> dict[str, object]:
    _require(args, "dns <host>")
    return inspect_dns(args[0])


def _tls(args: list[str]) -> dict[str, object]:
    _require(args, "tls <host> [port]")
    port = int(args[1]) if len(args) > 1 else 443
    return inspect_tls(args[0], port)


def _web(args: list[str]) -> dict[str, object]:
    _require(args, "web <host>")
    return inspect_web(args[0])


def _phone(args: list[str]) -> dict[str, object]:
    _require(args, "phone <number> [region]")
    region = args[1] if len(args) > 1 else None
    return inspect_phone(args[0], region)


def _username(args: list[str]) -> dict[str, object]:
    _require(args, "username <name>")
    return inspect_username(args[0])
