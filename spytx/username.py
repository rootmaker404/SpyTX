from __future__ import annotations

import re


_USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{2,64}$")


def inspect_username(username: str) -> dict[str, object]:
    value = username.strip().lstrip("@")
    if not _USERNAME_RE.match(value):
        raise ValueError("username must be 2-64 characters using letters, numbers, dot, dash, or underscore")
    return {
        "username": value,
        "links": [
            f"https://github.com/{value}",
            f"https://www.reddit.com/user/{value}",
            f"https://www.instagram.com/{value}/",
            f"https://x.com/{value}",
            f"https://www.tiktok.com/@{value}",
        ],
        "scope": "public profile review links only",
    }
