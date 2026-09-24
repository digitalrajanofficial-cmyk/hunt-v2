import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .auth import AuthProvider
from .oob import generate_token
from .scope import ScopePolicy


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _hash_body(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


def verify_lead(
    lead: dict[str, Any],
    policy: ScopePolicy,
    auth_provider: AuthProvider | None = None,
    use_oob: bool = False,
    program: str = "",
) -> dict[str, Any]:
    asset = str(lead.get("asset", "")).strip()
    result: dict[str, Any] = {
        "lead_id": lead.get("id") or lead.get("title", "")[:80],
        "asset": asset,
        "verified_at": now(),
        "reachable": False,
        "status": None,
        "evidence": None,
    }
    if not asset:
        result["error"] = "missing asset"
        return result
    try:
        policy.validate_url(asset)
    except ValueError as exc:
        result["error"] = str(exc)[:300]
        return result
    headers: dict[str, str] = {}
    if auth_provider and auth_provider.is_available():
        if lead.get("testability") == "AUTH_HELPED":
            headers.update(auth_provider.headers())
    oob_url = None
    if use_oob and program and lead.get("class") in {"SSRF", "XXE", "SSTI", "RCE"}:
        try:
            oob = generate_token(program)
            oob_url = oob["url"]
            result["oob_token"] = oob["token"]
            result["oob_url"] = oob_url
        except Exception:
            pass
    try:
        probe = policy.probe(asset, method="GET", headers=headers or None)
        probe_headers = {k.lower(): v for k, v in probe.get("headers", {}).items()}
        probe_headers.update({k.lower(): v for k, v in headers.items() if k.lower() not in probe_headers})
        result["status"] = probe.get("status")
        result["reachable"] = probe.get("status") in {200, 201, 202, 203, 204, 301, 302, 303, 307, 308}
        result["evidence"] = {
            "kind": "probe",
            "reference": asset,
            "sha256": probe.get("body_sha256"),
            "captured_at": probe.get("headers", {}).get("date", now()),
        }
        result["probe"] = {
            "status": probe.get("status"),
            "body_sha256": probe.get("body_sha256"),
            "body_bytes": probe.get("body_bytes"),
            "headers": {k: v for k, v in probe.get("headers", {}).items() if k.lower() in {"content-type", "server", "content-length"}},
        }
        if oob_url:
            result["probe"]["oob_url"] = oob_url
    except ValueError as exc:
        result["error"] = str(exc)[:500]
    except Exception as exc:
        result["error"] = f"{type(exc).__name__}: {str(exc)[:300]}"
    return result


def verify_leads(
    leads: list[dict[str, Any]],
    policy: ScopePolicy,
    auth_provider: AuthProvider | None = None,
    use_oob: bool = False,
    program: str = "",
    output_path: str | None = None,
) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for lead in leads:
        results.append(verify_lead(lead, policy, auth_provider, use_oob, program))
    if output_path:
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        Path(output_path).write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")
    return results


def load_leads(path: str) -> list[dict[str, Any]]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(data, dict) and isinstance(data.get("leads"), list):
        return data["leads"]
    if isinstance(data, list):
        return data
    raise ValueError("input must contain a leads array")
