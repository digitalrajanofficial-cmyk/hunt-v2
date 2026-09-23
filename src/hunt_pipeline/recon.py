import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .collector import asset_id
from .scope import ScopeError, ScopePolicy


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    records = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        value = json.loads(line)
        if isinstance(value, dict):
            records.append(value)
    return records


def _read_lines(path: Path) -> list[str]:
    return [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip() and not line.lstrip().startswith("#")]


def _url_from_host(host: str) -> str:
    return host if host.startswith(("http://", "https://")) else f"https://{host}/"


def _asset(url: str, source: str, metadata: dict[str, Any] | None = None) -> dict[str, Any]:
    value = {
        "id": asset_id(url),
        "url": url,
        "source": source,
        "observed_at": datetime.now(timezone.utc).isoformat(),
    }
    if metadata:
        value["metadata"] = metadata
    return value


def parse_recon_directory(input_dir: str, policy: ScopePolicy, limit: int = 1000) -> list[dict[str, Any]]:
    if limit < 1 or limit > 1000:
        raise ValueError("limit must be between 1 and 1000")
    root = Path(input_dir)
    assets: dict[str, dict[str, Any]] = {}
    for path in sorted(root.glob("*")):
        if not path.is_file():
            continue
        candidates: list[tuple[str, str, dict[str, Any] | None]] = []
        if path.name == "subfinder.txt":
            candidates.extend(("subfinder", _url_from_host(host), None) for host in _read_lines(path))
        elif path.name == "urls.txt":
            candidates.extend(("archive", url, None) for url in _read_lines(path))
        elif path.name == "dnsx.jsonl":
            for record in _read_jsonl(path):
                host = record.get("host") or record.get("input")
                if isinstance(host, str):
                    candidates.append(("dnsx", _url_from_host(host), {"addresses": record.get("a", [])}))
        elif path.name == "httpx.jsonl":
            for record in _read_jsonl(path):
                url = record.get("url") or record.get("input") or record.get("host")
                if isinstance(url, str):
                    metadata = {
                        key: record[key]
                        for key in ("status_code", "title", "webserver", "tech")
                        if key in record
                    }
                    candidates.append(("httpx", _url_from_host(url), metadata or None))
        for source, url, metadata in candidates:
            try:
                scheme, host, port = policy.validate_url(url)
            except ScopeError:
                continue
            normalized = url
            if not normalized.endswith("/") and policy.require_https:
                normalized = normalized.rstrip("/")
            record = _asset(normalized, source, metadata)
            record["host"] = host
            record["scheme"] = scheme
            record["port"] = port
            assets[record["id"]] = record
            if len(assets) >= limit:
                return list(assets.values())
    return list(assets.values())


def merge_inventories(base: dict[str, Any], extra_assets: list[dict[str, Any]]) -> dict[str, Any]:
    merged = {asset_id(item["url"]): item for item in base.get("assets", []) if isinstance(item, dict) and isinstance(item.get("url"), str)}
    for item in extra_assets:
        merged[item["id"]] = item
    return {
        "program": base.get("program"),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "method": base.get("method", "passive"),
        "assets": list(merged.values()),
    }


def import_recon(input_dir: str, policy: ScopePolicy, base: dict[str, Any] | None = None, limit: int = 1000) -> dict[str, Any]:
    assets = parse_recon_directory(input_dir, policy, limit)
    if base is None:
        return {
            "program": policy.program,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "method": "passive",
            "assets": assets,
        }
    return merge_inventories(base, assets)


def write_recon_output(path: str, inventory: dict[str, Any]) -> None:
    Path(path).write_text(json.dumps(inventory, indent=2) + "\n", encoding="utf-8")
