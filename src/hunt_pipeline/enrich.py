import re
import json
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, parse_qs


SENSITIVE_PARAMS = {"id", "user_id", "uid", "email", "account", "order_id", "invoice", "token", "key", "api_key", "password", "auth", "session", "role", "admin", "debug"}
TECH_PATTERNS = {
    "graphql": re.compile(r"/graphql|__schema|graphql", re.I),
    "swagger": re.compile(r"swagger|openapi|api-docs", re.I),
    "oauth": re.compile(r"oauth|authorize|token", re.I),
    "jwt": re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
    "admin": re.compile(r"/admin|/dashboard|/manage", re.I),
    "upload": re.compile(r"/upload|multipart", re.I),
    "s3": re.compile(r"s3\.amazonaws|storage\.googleapis|\.blob\.core\.windows\.net", re.I),
}
HEADER_TECH = {
    "x-powered-by": "generic",
    "server": "server",
    "x-aspnet-version": "aspnet",
    "x-generator": "generic",
}
SECURITY_HEADERS = ["content-security-policy", "strict-transport-security", "x-frame-options", "x-content-type-options", "referrer-policy"]


def extract_params(url: str) -> list[str]:
    try:
        qs = parse_qs(urlsplit(url).query)
        return sorted(qs.keys())
    except ValueError:
        return []


def detect_tech(url: str, headers: dict[str, Any] | None = None) -> list[str]:
    tech: set[str] = set()
    for name, pattern in TECH_PATTERNS.items():
        if pattern.search(url):
            tech.add(name)
    if headers:
        lower_headers = {k.lower(): str(v).lower() for k, v in headers.items()}
        for hdr, val in lower_headers.items():
            if hdr in HEADER_TECH:
                tech.add(f"header:{hdr}")
            if "jwt" in val or "bearer" in val:
                tech.add("jwt")
            if hdr == "content-type" and "json" in val:
                tech.add("json-api")
        missing = [h for h in SECURITY_HEADERS if h not in lower_headers]
        if missing:
            tech.add("missing-security-headers")
    params = extract_params(url)
    sensitive = [p for p in params if p.lower() in SENSITIVE_PARAMS]
    if sensitive:
        tech.add("sensitive-params")
    if params:
        tech.add(f"params:{len(params)}")
    return sorted(tech)


def enrich_asset(asset: dict[str, Any]) -> dict[str, Any]:
    url = str(asset.get("url", ""))
    headers = asset.get("response_headers") or asset.get("headers") or {}
    params = extract_params(url)
    tech = detect_tech(url, headers if isinstance(headers, dict) else None)
    interesting = []
    if any(p.lower() in SENSITIVE_PARAMS for p in params):
        interesting.append("sensitive-param")
    if any(t in tech for t in ("graphql", "swagger", "admin", "upload")):
        interesting.append("high-value-endpoint")
    if "missing-security-headers" in tech:
        interesting.append("missing-headers")
    return {
        "params": params,
        "tech": tech,
        "interesting": sorted(set(interesting)),
        "param_count": len(params),
    }


def enrich_inventory(inventory: dict[str, Any]) -> dict[str, Any]:
    assets = inventory.get("assets", [])
    enriched = []
    for asset in assets:
        if not isinstance(asset, dict):
            enriched.append(asset)
            continue
        new_asset = dict(asset)
        new_asset["enrichment"] = enrich_asset(asset)
        enriched.append(new_asset)
    result = dict(inventory)
    result["assets"] = enriched
    result["enrichment"] = {
        "total_assets": len(enriched),
        "with_params": sum(1 for a in enriched if a.get("enrichment", {}).get("param_count", 0) > 0),
        "high_value": sum(1 for a in enriched if "high-value-endpoint" in a.get("enrichment", {}).get("interesting", [])),
        "tech_summary": {},
    }
    summary: dict[str, int] = {}
    for asset in enriched:
        for t in asset.get("enrichment", {}).get("tech", []):
            summary[t] = summary.get(t, 0) + 1
    result["enrichment"]["tech_summary"] = summary
    return result


def write_enriched(inventory: dict[str, Any], output_path: str) -> dict[str, Any]:
    enriched = enrich_inventory(inventory)
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    Path(output_path).write_text(json.dumps(enriched, indent=2) + "\n", encoding="utf-8")
    return enriched
