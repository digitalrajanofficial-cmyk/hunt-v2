import json
import re
from typing import Any

ID_PATTERN = re.compile(r"^[A-Za-z0-9._:-]{1,120}$")
HASH_PATTERN = re.compile(r"^[a-f0-9]{64}$")


class ValidationError(ValueError):
    pass


def _object(value: Any, path: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValidationError(f"{path} must be an object")
    return value


def _keys(value: dict[str, Any], required: set[str], optional: set[str], path: str) -> None:
    missing = required - value.keys()
    unknown = value.keys() - required - optional
    if missing:
        raise ValidationError(f"{path} missing fields: {', '.join(sorted(missing))}")
    if unknown:
        raise ValidationError(f"{path} unknown fields: {', '.join(sorted(unknown))}")


def _string(value: Any, path: str, maximum: int = 2000) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValidationError(f"{path} must be a non-empty string")
    if len(value) > maximum:
        raise ValidationError(f"{path} exceeds {maximum} characters")
    return value


def _string_list(value: Any, path: str, maximum_items: int = 30) -> list[str]:
    if not isinstance(value, list) or len(value) > maximum_items:
        raise ValidationError(f"{path} must be a list of at most {maximum_items} items")
    return [_string(item, f"{path}[{index}]", 500) for index, item in enumerate(value)]


def validate_lead(value: Any) -> dict[str, Any]:
    lead = _object(value, "lead")
    _keys(
        lead,
        {
            "program",
            "title",
            "asset",
            "class",
            "confidence",
            "source",
            "evidence",
        },
        {"id", "reasoning", "impact", "proof", "tags"},
        "lead",
    )
    for field in ("program", "title", "asset", "class", "source"):
        _string(lead[field], f"lead.{field}")
    if not ID_PATTERN.fullmatch(lead["program"]):
        raise ValidationError("lead.program has an invalid format")
    if not 0 <= lead["confidence"] <= 100 or isinstance(lead["confidence"], bool):
        raise ValidationError("lead.confidence must be an integer from 0 to 100")
    if lead["source"] not in {"recon", "manual", "model"}:
        raise ValidationError("lead.source must be recon, manual, or model")
    if "id" in lead:
        _string(lead["id"], "lead.id", 120)
        if not ID_PATTERN.fullmatch(lead["id"]):
            raise ValidationError("lead.id has an invalid format")
    for field in ("reasoning", "impact"):
        if field in lead:
            _string(lead[field], f"lead.{field}")
    if "proof" in lead:
        _string_list(lead["proof"], "lead.proof", 20)
    if "tags" in lead:
        _string_list(lead["tags"], "lead.tags", 20)
    evidence = lead["evidence"]
    if not isinstance(evidence, list) or not evidence or len(evidence) > 20:
        raise ValidationError("lead.evidence must contain between 1 and 20 items")
    for index, item in enumerate(evidence):
        entry = _object(item, f"lead.evidence[{index}]")
        _keys(entry, {"kind", "reference"}, {"sha256", "captured_at"}, f"lead.evidence[{index}]")
        _string(entry["kind"], f"lead.evidence[{index}].kind", 80)
        _string(entry["reference"], f"lead.evidence[{index}].reference", 500)
        if "sha256" in entry and not HASH_PATTERN.fullmatch(entry["sha256"]):
            raise ValidationError(f"lead.evidence[{index}].sha256 must be 64 hex characters")
        if "captured_at" in entry:
            _string(entry["captured_at"], f"lead.evidence[{index}].captured_at", 80)
    return lead


def validate_triage(value: Any) -> dict[str, Any]:
    verdict = _object(value, "triage")
    _keys(
        verdict,
        {"lead_id", "verdict", "reason", "evidence_ids"},
        {"impact", "safe_next_step", "cvss"},
        "triage",
    )
    _string(verdict["lead_id"], "triage.lead_id", 120)
    if verdict["verdict"] not in {"VALID", "INVALID", "HOLD"}:
        raise ValidationError("triage.verdict must be VALID, INVALID, or HOLD")
    _string(verdict["reason"], "triage.reason", 2000)
    evidence_ids = _string_list(verdict["evidence_ids"], "triage.evidence_ids", 20)
    if verdict["verdict"] == "VALID":
        if not evidence_ids:
            raise ValidationError("VALID triage requires at least one evidence_id")
        if "impact" not in verdict or "safe_next_step" not in verdict:
            raise ValidationError("VALID triage requires impact and safe_next_step")
    for field in ("impact", "safe_next_step", "cvss"):
        if field in verdict:
            _string(verdict[field], f"triage.{field}", 1000)
    return verdict


def canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
