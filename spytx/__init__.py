from __future__ import annotations

from .domain import inspect_domain, inspect_dns, inspect_tls, inspect_web
from .ip import inspect_ip
from .phone import inspect_phone
from .username import inspect_username

__all__ = [
    "inspect_domain",
    "inspect_dns",
    "inspect_ip",
    "inspect_phone",
    "inspect_tls",
    "inspect_username",
    "inspect_web",
]
