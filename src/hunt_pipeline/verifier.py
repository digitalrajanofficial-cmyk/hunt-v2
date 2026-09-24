import base64
import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .auth import AuthProvider
from .enrich import detect_tech
from .oob import generate_token
from .scope import ScopePolicy


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _hash_body(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


def analyze_security_headers(headers: dict[str, Any]) -> list[str]:
    required = ["content-security-policy", "strict-transport-security", "x-frame-options", "x-content-type-options"]
    lower = {k.lower(): v for k, v in headers.items()}
    return [h for h in required if h not in lower]


def analyze_jwt(token: str) -> dict[str, Any]:
    parts = token.split(".")
    if len(parts) != 3:
        return {"valid": False}
    try:
        header = json.loads(base64.urlsafe_b64decode(parts[0] + "==").decode("utf-8"))
        payload = json.loads(base64.urlsafe_b64decode(parts[1] + "==").decode("utf-8"))
        issues = []
        if header.get("alg") == "none":
            issues.append("alg-none")
        if "kid" in header and ("../" in str(header["kid"]) or header["kid"].startswith("/")):
            issues.append("kid-traversal")
        if header.get("alg") and header.get("alg").startswith("HS") and "jwk" in header:
            issues.append("jwk-injection")
        return {"valid": True, "header": header, "payload_keys": list(payload.keys())[:10], "issues": issues}
    except Exception:
        return {"valid": False}


def _probe_method(policy: ScopePolicy) -> str:
    return "GET" if "GET" in policy.allowed_methods else policy.allowed_methods[0]


def check_cors(policy: ScopePolicy, url: str, extra_headers: dict[str, str] | None = None) -> dict[str, Any] | None:
    try:
        headers = {"Origin": "https://evil.example.test"}
        if extra_headers:
            headers.update(extra_headers)
        probe = policy.probe(url, method=_probe_method(policy), headers=headers)
        lower = {k.lower(): v for k, v in probe.get("headers", {}).items()}
        acao = lower.get("access-control-allow-origin", "")
        acac = lower.get("access-control-allow-credentials", "")
        return {
            "acao": acao[:200],
            "acac": acac[:20],
            "vulnerable": acao in {"*", "https://evil.example.test"} or (acao == "https://evil.example.test" and acac.lower() == "true"),
            "status": probe.get("status"),
        }
    except Exception:
        return None


def check_graphql_introspection(policy: ScopePolicy, url: str, extra_headers: dict[str, str] | None = None) -> dict[str, Any] | None:
    if "graphql" not in url.lower() and "gql" not in url.lower():
        return None
    try:
        probe = policy.probe(url, method=_probe_method(policy), headers=extra_headers)
        body_hint = str(probe.get("headers", {}).get("content-type", ""))
        return {"status": probe.get("status"), "content_type": body_hint[:80], "probe": "introspection-ready"}
    except Exception:
        return None


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
        probe = policy.probe(asset, method=_probe_method(policy), headers=headers or None)
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
        missing = analyze_security_headers(probe.get("headers", {}))
        tech = detect_tech(asset, probe.get("headers", {}))
        result["probe"] = {
            "status": probe.get("status"),
            "body_sha256": probe.get("body_sha256"),
            "body_bytes": probe.get("body_bytes"),
            "headers": {k: v for k, v in probe.get("headers", {}).items() if k.lower() in {"content-type", "server", "content-length", "access-control-allow-origin", "access-control-allow-credentials"}},
            "missing_security_headers": missing,
            "tech": tech,
        }
        if oob_url:
            result["probe"]["oob_url"] = oob_url
        if lead.get("class") in {"CORS", "MISCONFIG"}:
            cors = check_cors(policy, asset, headers or None)
            if cors:
                result["cors"] = cors
        if lead.get("class") in {"GRAPHQL", "OTHER"} and "graphql" in asset.lower():
            gql = check_graphql_introspection(policy, asset, headers or None)
            if gql:
                result["graphql"] = gql
        for hdr in probe.get("headers", {}).values():
            if isinstance(hdr, str) and re.search(r"eyJ[A-Za-z0-9_-]{10,}\.", hdr):
                m = re.search(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}", hdr)
                if m:
                    result["jwt"] = analyze_jwt(m.group(0))
                    break
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
