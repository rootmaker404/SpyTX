from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone
from http.client import HTTPConnection, HTTPSConnection
from urllib.parse import urlparse


def normalize_domain(target: str) -> str:
    value = target.strip()
    if not value:
        raise ValueError("domain is required")
    parsed = urlparse(value if "://" in value else f"//{value}")
    host = parsed.hostname or value
    host = host.strip().lower().rstrip(".")
    if not host or any(part == "" for part in host.split(".")):
        raise ValueError("invalid domain")
    return host


def inspect_domain(target: str) -> dict[str, object]:
    domain = normalize_domain(target)
    addresses = sorted({*socket.gethostbyname_ex(domain)[2]})
    return {
        "domain": domain,
        "addresses": addresses,
        "scope": "public DNS resolution",
    }


def inspect_dns(target: str) -> dict[str, object]:
    domain = normalize_domain(target)
    records: dict[str, list[str]] = {"A": [], "AAAA": []}
    for family, key in ((socket.AF_INET, "A"), (socket.AF_INET6, "AAAA")):
        try:
            infos = socket.getaddrinfo(domain, None, family, socket.SOCK_STREAM)
        except socket.gaierror:
            continue
        records[key] = sorted({info[4][0] for info in infos})
    return {
        "domain": domain,
        "records": records,
        "scope": "public DNS resolution",
    }


def inspect_tls(target: str, port: int = 443) -> dict[str, object]:
    domain = normalize_domain(target)
    context = ssl.create_default_context()
    with socket.create_connection((domain, port), timeout=8) as sock:
        with context.wrap_socket(sock, server_hostname=domain) as wrapped:
            cert = wrapped.getpeercert()
    return {
        "domain": domain,
        "port": port,
        "subject": cert.get("subject", []),
        "issuer": cert.get("issuer", []),
        "not_before": cert.get("notBefore"),
        "not_after": cert.get("notAfter"),
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "scope": "public TLS certificate metadata",
    }


def inspect_web(target: str) -> dict[str, object]:
    domain = normalize_domain(target)
    result = _request_head(domain, use_tls=True) or _request_head(domain, use_tls=False)
    if result is None:
        return {
            "domain": domain,
            "reachable": False,
            "scope": "public web response metadata",
        }
    return result


def _request_head(domain: str, *, use_tls: bool) -> dict[str, object] | None:
    connection_cls = HTTPSConnection if use_tls else HTTPConnection
    scheme = "https" if use_tls else "http"
    try:
        connection = connection_cls(domain, timeout=8)
        connection.request("HEAD", "/", headers={"User-Agent": "SpyTX/1.0"})
        response = connection.getresponse()
        headers = {key.lower(): value for key, value in response.getheaders()}
        connection.close()
    except OSError:
        return None
    return {
        "domain": domain,
        "url": f"{scheme}://{domain}/",
        "reachable": True,
        "status": response.status,
        "server": headers.get("server"),
        "content_type": headers.get("content-type"),
        "security_headers": {
            "strict_transport_security": "strict-transport-security" in headers,
            "content_security_policy": "content-security-policy" in headers,
            "x_frame_options": "x-frame-options" in headers,
            "x_content_type_options": "x-content-type-options" in headers,
        },
        "scope": "public web response metadata",
    }
