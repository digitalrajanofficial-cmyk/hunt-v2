import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .scope import ScopeError, ScopePolicy


def load_seed_urls(path: str, limit: int = 100) -> list[str]:
    if limit < 1 or limit > 1000:
        raise ValueError("limit must be between 1 and 1000")
    urls = []
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        value = line.strip()
        if not value or value.startswith("#"):
            continue
        if value not in urls:
            urls.append(value)
        if len(urls) > limit:
            raise ValueError(f"seed file contains more than {limit} unique URLs")
    if not urls:
        raise ValueError("seed file contains no URLs")
    return urls


def asset_id(url: str) -> str:
    return "asset_" + hashlib.sha256(url.encode("utf-8")).hexdigest()[:20]


def collect(policy: ScopePolicy, urls: list[str], method: str = "GET", limit: int = 100) -> dict[str, Any]:
    if limit < 1 or limit > 1000:
        raise ValueError("limit must be between 1 and 1000")
    method = method.upper()
    assets = []
    for url in urls[:limit]:
        record = {
            "id": asset_id(url),
            "url": url,
            "method": method,
            "observed_at": datetime.now(timezone.utc).isoformat(),
            "source": "safe-probe",
        }
        try:
            result = policy.probe(url, method)
            record.update(
                {
                    "status": result["status"],
                    "body_sha256": result["body_sha256"],
                    "body_bytes": result["body_bytes"],
                    "truncated": result["truncated"],
                    "response_headers": {
                        key: value
                        for key, value in result["headers"].items()
                        if key in {"content-type", "location", "server", "x-powered-by", "content-length"}
                    },
                }
            )
        except ScopeError as exc:
            record.update({"status": None, "error": str(exc)})
        assets.append(record)
    return {
        "program": policy.program,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "method": method,
        "assets": assets,
    }


def write_inventory(path: str, inventory: dict[str, Any]) -> None:
    Path(path).write_text(json.dumps(inventory, indent=2) + "\n", encoding="utf-8")
