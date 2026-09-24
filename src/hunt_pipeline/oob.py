import hashlib
import json
import os
import re
import secrets
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def oob_state_path(program: str, base: str = "state") -> Path:
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", program)
    path = Path(base)
    path.mkdir(parents=True, exist_ok=True)
    return path / f"{safe}-oob.json"


def load_oob_state(program: str, base: str = "state") -> dict[str, Any]:
    path = oob_state_path(program, base)
    if not path.exists():
        return {"program": program, "tokens": []}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(data, dict):
            return data
    except (OSError, json.JSONDecodeError):
        pass
    return {"program": program, "tokens": []}


def save_oob_state(program: str, data: dict[str, Any], base: str = "state") -> None:
    path = oob_state_path(program, base)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def generate_token(program: str, domain: str | None = None, base: str = "state") -> dict[str, str]:
    token = secrets.token_hex(8)
    callback_domain = domain or os.environ.get("OOB_DOMAIN", "") or os.environ.get("INTERACTSH_DOMAIN", "")
    if not callback_domain:
        callback_domain = "oob.invalid"
    callback_domain = callback_domain.strip().lower().lstrip(".")
    url = f"https://{token}.{callback_domain}/"
    data = load_oob_state(program, base)
    data["tokens"].append({"token": token, "url": url, "created_at": now(), "checked_at": None, "hits": 0})
    if len(data["tokens"]) > 50:
        data["tokens"] = data["tokens"][-50:]
    save_oob_state(program, data, base)
    return {"token": token, "url": url}


def poll_interactsh(token: str) -> list[dict[str, Any]]:
    endpoint = os.environ.get("INTERACTSH_POLL_URL", "").strip()
    api_token = os.environ.get("INTERACTSH_TOKEN", "").strip()
    if not endpoint or not api_token:
        return []
    headers = {"Authorization": api_token, "Content-Type": "application/json"}
    payload = json.dumps({"token": token}).encode("utf-8")
    request = Request(endpoint, data=payload, headers=headers)
    try:
        with urlopen(request, timeout=20) as response:
            data = json.loads(response.read().decode("utf-8"))
            if isinstance(data, dict) and isinstance(data.get("data"), list):
                return data["data"]
            if isinstance(data, list):
                return data
    except (HTTPError, URLError, OSError, json.JSONDecodeError, ValueError):
        return []
    return []


def check_token(program: str, token: str, base: str = "state") -> dict[str, Any]:
    data = load_oob_state(program, base)
    for entry in data.get("tokens", []):
        if entry.get("token") == token:
            hits = poll_interactsh(token)
            entry["checked_at"] = now()
            entry["hits"] = len(hits)
            entry["raw"] = hits[:3]
            save_oob_state(program, data, base)
            return {"token": token, "hits": len(hits), "verified": len(hits) > 0, "raw": hits[:1]}
    return {"token": token, "hits": 0, "verified": False}


def cleanup_expired(program: str, base: str = "state", ttl_hours: int = 72) -> int:
    data = load_oob_state(program, base)
    cutoff = datetime.now(timezone.utc) - timedelta(hours=ttl_hours)
    original = len(data.get("tokens", []))
    kept = []
    for entry in data.get("tokens", []):
        try:
            created = datetime.fromisoformat(str(entry.get("created_at", "")).replace("Z", "+00:00"))
            if created >= cutoff:
                kept.append(entry)
        except (ValueError, TypeError):
            continue
    data["tokens"] = kept
    save_oob_state(program, data, base)
    return original - len(kept)
