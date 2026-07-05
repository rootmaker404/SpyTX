from __future__ import annotations

import ipaddress
import socket


def inspect_ip(target: str) -> dict[str, object]:
    address = ipaddress.ip_address(target.strip())
    reverse_name = None
    try:
        reverse_name = socket.gethostbyaddr(str(address))[0]
    except (socket.herror, socket.gaierror):
        pass

    return {
        "ip": str(address),
        "version": address.version,
        "is_global": address.is_global,
        "is_private": address.is_private,
        "is_loopback": address.is_loopback,
        "is_multicast": address.is_multicast,
        "reverse_dns": reverse_name,
        "scope": "public IP metadata",
    }
