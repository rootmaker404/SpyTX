from __future__ import annotations

import ipaddress
import math
import socket
from datetime import datetime, timezone
from html import escape
from pathlib import Path
from typing import Any
from urllib.request import Request, urlopen

from .domain import normalize_domain
from .ip import inspect_ip


def inspect_geo(target: str) -> dict[str, object]:
    ip = resolve_address(target)
    base = inspect_ip(ip)
    sources = [_from_ipwho(ip), _from_ipinfo(ip)]
    good = [item for item in sources if item.get("ok")]
    best = choose_best_geo(good)
    return {
        "target": target,
        "ip": ip,
        "base": base,
        "geo": best,
        "sources": sources,
        "precision": precision_grade(good),
        "maps": maps_link(best),
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "scope": "public network geolocation metadata",
    }


def inspect_best_geo(target: str) -> dict[str, object]:
    data = inspect_geo(target)
    return {
        "target": data["target"],
        "ip": data["ip"],
        "best": data["geo"],
        "precision": data["precision"],
        "maps": data["maps"],
        "scope": data["scope"],
    }


def inspect_geo_sources(target: str) -> dict[str, object]:
    data = inspect_geo(target)
    return {
        "target": data["target"],
        "ip": data["ip"],
        "sources": data["sources"],
        "scope": "public geolocation source comparison",
    }


def inspect_precision(target: str) -> dict[str, object]:
    data = inspect_geo(target)
    return {
        "target": data["target"],
        "ip": data["ip"],
        "precision": data["precision"],
        "scope": "public geolocation agreement score",
    }


def copy_geo(target: str) -> dict[str, object]:
    data = inspect_best_geo(target)
    best = data.get("best") or {}
    lat = best.get("latitude") if isinstance(best, dict) else None
    lon = best.get("longitude") if isinstance(best, dict) else None
    value = f"{lat},{lon}" if lat is not None and lon is not None else ""
    return {
        "target": data["target"],
        "ip": data["ip"],
        "value": value,
        "scope": "copyable public coordinate estimate",
    }


def copy_gmaps(target: str) -> dict[str, object]:
    data = inspect_best_geo(target)
    return {
        "target": data["target"],
        "ip": data["ip"],
        "value": data["maps"],
        "scope": "public map link for network-level estimate",
    }


def save_geo_map(target: str, output_dir: str | Path = "output") -> dict[str, object]:
    data = inspect_best_geo(target)
    best = data.get("best") or {}
    lat = best.get("latitude") if isinstance(best, dict) else None
    lon = best.get("longitude") if isinstance(best, dict) else None
    if lat is None or lon is None:
        raise ValueError("no coordinate estimate available")
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    safe_ip = str(data["ip"]).replace(":", "_").replace(".", "_")
    path = out_dir / f"geo_{safe_ip}.html"
    path.write_text(_map_html(data), encoding="utf-8")
    return {
        "target": data["target"],
        "ip": data["ip"],
        "file": str(path),
        "maps": data["maps"],
        "scope": "local public geolocation report",
    }


def choose_best_geo(sources: list[dict[str, object]]) -> dict[str, object] | None:
    points = [item for item in sources if _has_coordinate(item)]
    if not points:
        return None
    if len(points) == 1:
        return _geo_payload(points[0], confidence=0.62)

    lat = sum(float(item["latitude"]) for item in points) / len(points)
    lon = sum(float(item["longitude"]) for item in points) / len(points)
    ranked = sorted(points, key=lambda item: _distance_km(lat, lon, float(item["latitude"]), float(item["longitude"])))
    spread = max(_distance_km(lat, lon, float(item["latitude"]), float(item["longitude"])) for item in points)
    confidence = 0.9 if spread <= 40 else 0.75 if spread <= 150 else 0.55
    payload = _geo_payload(ranked[0], confidence=confidence)
    payload["source_count"] = len(points)
    payload["spread_km"] = round(spread, 2)
    return payload


def precision_grade(sources: list[dict[str, object]]) -> dict[str, object]:
    points = [item for item in sources if _has_coordinate(item)]
    if not points:
        return {"grade": "D", "source_count": 0, "note": "no coordinate estimate"}
    if len(points) == 1:
        return {"grade": "C", "source_count": 1, "note": "single public source"}
    lat = sum(float(item["latitude"]) for item in points) / len(points)
    lon = sum(float(item["longitude"]) for item in points) / len(points)
    spread = max(_distance_km(lat, lon, float(item["latitude"]), float(item["longitude"])) for item in points)
    grade = "A" if spread <= 40 else "B" if spread <= 150 else "C"
    return {
        "grade": grade,
        "source_count": len(points),
        "spread_km": round(spread, 2),
        "note": "network-level estimate, not device GPS",
    }


def maps_link(best: dict[str, object] | None) -> str | None:
    if not best or best.get("latitude") is None or best.get("longitude") is None:
        return None
    return f"https://www.google.com/maps/search/?query={best['latitude']},{best['longitude']}"


def resolve_address(target: str) -> str:
    value = target.strip()
    try:
        ipaddress.ip_address(value)
        return value
    except ValueError:
        return socket.gethostbyname(normalize_domain(value))


def _from_ipwho(ip: str) -> dict[str, object]:
    try:
        data = _get_json(f"https://ipwho.is/{ip}")
        if not data.get("success", True):
            return {"source": "ipwho.is", "ok": False, "error": str(data.get("message", "lookup failed"))}
        connection = data.get("connection") if isinstance(data.get("connection"), dict) else {}
        tz = data.get("timezone") if isinstance(data.get("timezone"), dict) else {}
        return {
            "source": "ipwho.is",
            "ok": True,
            "ip": ip,
            "country": data.get("country"),
            "region": data.get("region"),
            "city": data.get("city"),
            "postal": data.get("postal"),
            "latitude": data.get("latitude"),
            "longitude": data.get("longitude"),
            "timezone": tz.get("id"),
            "asn": connection.get("asn"),
            "isp": connection.get("isp"),
            "org": connection.get("org"),
        }
    except Exception as exc:
        return {"source": "ipwho.is", "ok": False, "error": str(exc)}


def _from_ipinfo(ip: str) -> dict[str, object]:
    try:
        data = _get_json(f"https://ipinfo.io/{ip}/json")
        lat = lon = None
        loc = str(data.get("loc", ""))
        if "," in loc:
            lat_raw, lon_raw = loc.split(",", 1)
            lat = _number(lat_raw)
            lon = _number(lon_raw)
        org = str(data.get("org", "")).strip() or None
        return {
            "source": "ipinfo.io",
            "ok": True,
            "ip": ip,
            "country": data.get("country"),
            "region": data.get("region"),
            "city": data.get("city"),
            "postal": data.get("postal"),
            "latitude": lat,
            "longitude": lon,
            "timezone": data.get("timezone"),
            "asn": org.split(" ", 1)[0] if org else None,
            "isp": org,
            "org": org,
        }
    except Exception as exc:
        return {"source": "ipinfo.io", "ok": False, "error": str(exc)}


def _get_json(url: str) -> dict[str, Any]:
    import json

    request = Request(url, headers={"User-Agent": "SpyTX/1.0"})
    with urlopen(request, timeout=8) as response:
        return json.loads(response.read().decode("utf-8", errors="replace"))


def _geo_payload(item: dict[str, object], *, confidence: float) -> dict[str, object]:
    return {
        "source": item.get("source"),
        "country": item.get("country"),
        "region": item.get("region"),
        "city": item.get("city"),
        "postal": item.get("postal"),
        "latitude": item.get("latitude"),
        "longitude": item.get("longitude"),
        "timezone": item.get("timezone"),
        "asn": item.get("asn"),
        "isp": item.get("isp"),
        "org": item.get("org"),
        "confidence": confidence,
    }


def _has_coordinate(item: dict[str, object]) -> bool:
    return item.get("latitude") is not None and item.get("longitude") is not None


def _number(value: object) -> float | None:
    try:
        return float(str(value).strip())
    except (TypeError, ValueError):
        return None


def _distance_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    radius = 6371.0
    dlat = math.radians(lat2 - lat1)
    dlon = math.radians(lon2 - lon1)
    a = (
        math.sin(dlat / 2) ** 2
        + math.cos(math.radians(lat1)) * math.cos(math.radians(lat2)) * math.sin(dlon / 2) ** 2
    )
    return radius * 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))


def _map_html(data: dict[str, object]) -> str:
    best = data["best"] if isinstance(data.get("best"), dict) else {}
    lat = escape(str(best.get("latitude")))
    lon = escape(str(best.get("longitude")))
    title = escape(f"SpyTX geo report for {data.get('ip')}")
    link = escape(str(data.get("maps") or ""))
    return f"""<!doctype html>
<html lang="en">
<meta charset="utf-8">
<title>{title}</title>
<body style="background:#05070a;color:#e5e7eb;font-family:Consolas,monospace;padding:32px">
<h1>{title}</h1>
<p>Coordinate estimate: {lat}, {lon}</p>
<p><a style="color:#7dd3fc" href="{link}">Open map link</a></p>
<p>Network-level public geolocation only. Not device GPS.</p>
</body>
</html>
"""
