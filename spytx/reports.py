from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


DEFAULT_DIR = Path("output")
RECORDS_FILE = "records.jsonl"


def write_record(command: str, payload: dict[str, object], *, output_dir: str | Path = DEFAULT_DIR) -> int:
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / RECORDS_FILE
    next_id = _next_id(path)
    record = {
        "id": next_id,
        "command": command,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "result": payload,
    }
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, ensure_ascii=True) + "\n")
    return next_id


def list_records(limit: int = 10, *, output_dir: str | Path = DEFAULT_DIR) -> dict[str, object]:
    records = _read_all(Path(output_dir) / RECORDS_FILE)
    return {
        "count": len(records),
        "items": records[-limit:],
        "scope": "local SpyTX result records",
    }


def show_record(record_id: int, *, output_dir: str | Path = DEFAULT_DIR) -> dict[str, object]:
    for record in _read_all(Path(output_dir) / RECORDS_FILE):
        if int(record.get("id", -1)) == record_id:
            return record
    raise ValueError(f"record not found: {record_id}")


def export_record(record_id: int, fmt: str = "json", *, output_dir: str | Path = DEFAULT_DIR) -> dict[str, object]:
    fmt = fmt.lower()
    if fmt not in {"json", "txt"}:
        raise ValueError("format must be json or txt")
    record = show_record(record_id, output_dir=output_dir)
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"record_{record_id}.{fmt}"
    if fmt == "json":
        path.write_text(json.dumps(record, indent=2, ensure_ascii=True), encoding="utf-8")
    else:
        path.write_text(_plain_text(record), encoding="utf-8")
    return {
        "id": record_id,
        "file": str(path),
        "format": fmt,
        "scope": "local SpyTX export",
    }


def _read_all(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    records: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        if not line.strip():
            continue
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return records


def _next_id(path: Path) -> int:
    records = _read_all(path)
    if not records:
        return 1
    return max(int(record.get("id", 0)) for record in records) + 1


def _plain_text(record: dict[str, Any]) -> str:
    return "\n".join(
        [
            f"SpyTX record #{record.get('id')}",
            f"command: {record.get('command')}",
            f"created_at: {record.get('created_at')}",
            "",
            json.dumps(record.get("result"), indent=2, ensure_ascii=True),
            "",
        ]
    )
