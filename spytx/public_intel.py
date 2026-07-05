from __future__ import annotations

import socket
import ipaddress
import os
import subprocess
from datetime import datetime, timezone
from urllib.parse import quote_plus
from urllib.request import Request, urlopen

from .domain import inspect_domain, inspect_dns, inspect_tls, inspect_web, normalize_domain
from .geo import inspect_best_geo
from .ip import inspect_ip
from .phone import inspect_phone
from .username import inspect_username


def inspect_lookup(target: str) -> dict[str, object]:
    value = target.strip()
    try:
        ipaddress.ip_address(value)
    except ValueError:
        domain = normalize_domain(value)
        return {
            "kind": "domain",
            "data": {
                "domain": inspect_domain(domain),
                "dns": inspect_dns(domain),
                "web": inspect_web(domain),
            },
        }
    return {"kind": "ip", "data": inspect_deep_ip(value)}


def inspect_deep_ip(target: str) -> dict[str, object]:
    base = inspect_ip(_resolve_ip(target))
    geo = inspect_best_geo(str(base["ip"]))
    return {
        **base,
        "geo": geo["best"],
        "precision": geo["precision"],
        "maps": geo["maps"],
        "risk": {
            "publicly_routable": base["is_global"],
            "private_or_reserved": not base["is_global"],
            "note": "Risk hints are based on local address classification and reverse DNS only.",
        },
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "scope": "public IP metadata with local risk hints",
    }


def inspect_check_ip(target: str) -> dict[str, object]:
    data = inspect_deep_ip(target)
    data["check"] = {
        "network_visibility": "visible public address only" if data["is_global"] else "non-public address",
        "hidden_origin": "not available from public metadata",
    }
    return data


def inspect_batch_ip(targets: list[str]) -> dict[str, object]:
    results = []
    for target in targets:
        try:
            results.append({"target": target, "ok": True, "result": inspect_deep_ip(target)})
        except Exception as exc:
            results.append({"target": target, "ok": False, "error": str(exc)})
    return {"count": len(results), "results": results}


def inspect_ip_health() -> dict[str, object]:
    return {
        "status": "ready",
        "geo_sources": ["ipwho.is", "ipinfo.io"],
        "network_checks": ["reverse_dns", "local_address_flags", "geo_agreement"],
        "scope": "public network metadata modules",
    }


def inspect_engines() -> dict[str, object]:
    return {
        "modules": [
            "ip",
            "deepip",
            "checkip",
            "geo",
            "bestgeo",
            "providers",
            "precision",
            "copygeo",
            "copygmaps",
            "map",
            "domain",
            "dns",
            "ct",
            "bgp",
            "ripe",
            "reverseip",
            "trace",
            "external",
            "tls",
            "web",
            "phone",
            "social",
            "name",
        ],
        "scope": "SpyTX public-intelligence engines",
    }


def inspect_whois(target: str) -> dict[str, object]:
    domain = normalize_domain(target)
    return {
        "domain": domain,
        "links": {
            "iana": f"https://www.iana.org/whois?q={quote_plus(domain)}",
            "lookup": f"https://lookup.icann.org/en/lookup?name={quote_plus(domain)}",
        },
        "scope": "public registration review links",
    }


def inspect_contacts(target: str) -> dict[str, object]:
    domain = normalize_domain(target)
    links = [
        f"https://{domain}/.well-known/security.txt",
        f"https://{domain}/security.txt",
        f"https://{domain}/contact",
        f"https://{domain}/about",
    ]
    return {
        "domain": domain,
        "links": links,
        "scope": "public contact and security disclosure locations",
    }


def inspect_ct(target: str) -> dict[str, object]:
    domain = normalize_domain(target)
    return {
        "domain": domain,
        "links": {
            "crtsh": f"https://crt.sh/?q={quote_plus(domain)}",
        },
        "scope": "public certificate transparency review links",
    }


def inspect_bgp(target: str) -> dict[str, object]:
    ip = _resolve_ip(target)
    query = quote_plus(ip)
    return {
        "target": target,
        "ip": ip,
        "links": {
            "bgp_tools": f"https://bgp.tools/ip/{query}",
            "he_net": f"https://bgp.he.net/ip/{query}",
        },
        "scope": "public routing review links",
    }


def inspect_ripe(target: str) -> dict[str, object]:
    value = target.strip()
    query = quote_plus(value)
    return {
        "target": value,
        "links": {
            "routing": f"https://stat.ripe.net/{query}",
            "database": f"https://apps.db.ripe.net/db-web-ui/query?searchtext={query}",
        },
        "scope": "public RIPE review links",
    }


def inspect_reverse_ip(target: str) -> dict[str, object]:
    domain = normalize_domain(target)
    query = quote_plus(domain)
    return {
        "domain": domain,
        "links": {
            "viewdns": f"https://viewdns.info/reverseip/?host={query}&t=1",
            "crtsh": f"https://crt.sh/?q={query}",
        },
        "scope": "public reverse host review links",
    }


def inspect_external(target: str) -> dict[str, object]:
    value = target.strip()
    query = quote_plus(value)
    return {
        "target": value,
        "links": {
            "wayback": f"https://web.archive.org/web/*/{query}",
            "urlscan": f"https://urlscan.io/search/#{query}",
            "otx": f"https://otx.alienvault.com/indicator/domain/{query}",
            "threatminer": f"https://www.threatminer.org/domain.php?q={query}",
        },
        "scope": "public external review links",
    }


def inspect_trace(target: str) -> dict[str, object]:
    value = target.strip()
    if not value:
        raise ValueError("target is required")
    command = ["tracert", "-d", "-h", "8", value] if os.name == "nt" else ["traceroute", "-n", "-m", "8", value]
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=20, check=False)
        lines = [line.rstrip() for line in result.stdout.splitlines() if line.strip()]
        if not lines and result.stderr:
            lines = [line.rstrip() for line in result.stderr.splitlines() if line.strip()]
        return {
            "target": value,
            "command": command[0],
            "exit_code": result.returncode,
            "hops": lines,
            "scope": "local network path sample",
        }
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {
            "target": value,
            "command": command[0],
            "error": str(exc),
            "hops": [],
            "scope": "local network path sample",
        }


def inspect_social(value: str) -> dict[str, object]:
    text = value.strip().strip('"')
    if " " in text:
        return inspect_name(text)
    return inspect_username(text)


def inspect_name(name: str) -> dict[str, object]:
    value = " ".join(name.strip().strip('"').split())
    if len(value) < 2:
        raise ValueError("name is required")
    query = quote_plus(f'"{value}"')
    compact = "".join(part.lower() for part in value.split())
    dotted = ".".join(part.lower() for part in value.split())
    return {
        "name": value,
        "search_links": [
            f"https://www.google.com/search?q={query}",
            f"https://www.bing.com/search?q={query}",
            f"https://duckduckgo.com/?q={query}",
        ],
        "username_variants": sorted({compact, dotted, value.lower().replace(" ", "_")}),
        "scope": "public exact-name review links only",
    }


def inspect_my_ip() -> dict[str, object]:
    endpoints = [
        "https://checkip.amazonaws.com",
        "https://ifconfig.me/ip",
    ]
    for endpoint in endpoints:
        try:
            request = Request(endpoint, headers={"User-Agent": "SpyTX/1.0"})
            with urlopen(request, timeout=8) as response:
                body = response.read().decode("utf-8", errors="replace")
            ip = body.strip()
            if ip:
                return inspect_deep_ip(str(ip))
        except Exception:
            continue
    raise RuntimeError("unable to detect public IP")


def inspect_rdap(target: str) -> dict[str, object]:
    value = target.strip()
    query = quote_plus(value)
    return {
        "target": value,
        "links": {
            "arin": f"https://search.arin.net/rdap/?query={query}",
            "ripe": f"https://apps.db.ripe.net/db-web-ui/query?searchtext={query}",
        },
        "scope": "public RDAP review links",
    }


def _resolve_ip(target: str) -> str:
    value = target.strip()
    try:
        socket.inet_pton(socket.AF_INET, value)
        return value
    except OSError:
        pass
    try:
        socket.inet_pton(socket.AF_INET6, value)
        return value
    except OSError:
        pass
    return socket.gethostbyname(normalize_domain(value))
