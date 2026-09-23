import hashlib
import json
from pathlib import Path
from typing import Any

from .models import canonical

VOLATILE_FIELDS = {"observed_at"}


def stable_record(item: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in item.items() if key not in VOLATILE_FIELDS}


def load_inventory(path: str) -> list[dict[str, Any]]:
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(value, dict):
        value = value.get("assets", value.get("records", []))
    if not isinstance(value, list) or any(not isinstance(item, dict) for item in value):
        raise ValueError("inventory must be a JSON array or an object with an assets array")
    return value


def inventory_key(item: dict[str, Any]) -> str:
    for field in ("id", "url", "asset", "host"):
        if field in item and isinstance(item[field], str) and item[field].strip():
            return item[field].strip().lower()
    return "sha256:" + hashlib.sha256(canonical(item).encode()).hexdigest()[:24]


def diff_inventory(previous: list[dict[str, Any]], current: list[dict[str, Any]]) -> dict[str, Any]:
    old = {inventory_key(item): item for item in previous}
    new = {inventory_key(item): item for item in current}
    added = [new[key] for key in sorted(new.keys() - old.keys())]
    removed = [old[key] for key in sorted(old.keys() - new.keys())]
    changed = [
        {"key": key, "before": old[key], "after": new[key]}
        for key in sorted(old.keys() & new.keys())
        if canonical(stable_record(old[key])) != canonical(stable_record(new[key]))
    ]
    return {
        "added": added,
        "removed": removed,
        "changed": changed,
        "counts": {"added": len(added), "removed": len(removed), "changed": len(changed)},
    }


def write_diff(previous_path: str, current_path: str, output: str) -> dict[str, Any]:
    result = diff_inventory(load_inventory(previous_path), load_inventory(current_path))
    Path(output).write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return result
