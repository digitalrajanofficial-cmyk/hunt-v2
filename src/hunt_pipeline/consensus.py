import json
from collections import defaultdict
from pathlib import Path
from typing import Any

from .models import ValidationError, validate_triage


def load_model_result(path: str) -> tuple[str, list[dict[str, Any]]]:
    value = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(value, dict) or not isinstance(value.get("results"), list):
        raise ValidationError(f"{path} must contain an object with a results array")
    model = value.get("model")
    if not isinstance(model, str) or not model.strip():
        raise ValidationError(f"{path} must include a model name")
    return model, value["results"]


def combine_results(documents: list[tuple[str, list[dict[str, Any]]]], minimum_models: int = 2) -> list[dict[str, Any]]:
    if minimum_models < 2:
        raise ValidationError("minimum_models must be at least 2")
    grouped: dict[str, list[tuple[str, dict[str, Any]]]] = defaultdict(list)
    for model, results in documents:
        for result in results:
            checked = validate_triage(result)
            grouped[checked["lead_id"]].append((model, checked))
    combined = []
    for lead_id, votes in sorted(grouped.items()):
        models = {model for model, _ in votes}
        if len(models) < minimum_models:
            combined.append(
                {
                    "lead_id": lead_id,
                    "verdict": "HOLD",
                    "reason": f"Only {len(models)} independent model verdict(s) were supplied.",
                    "evidence_ids": [],
                }
            )
            continue
        verdicts = {result["verdict"] for _, result in votes}
        if len(verdicts) != 1:
            combined.append(
                {
                    "lead_id": lead_id,
                    "verdict": "HOLD",
                    "reason": "Independent models disagreed: " + ", ".join(sorted(verdicts)),
                    "evidence_ids": [],
                }
            )
            continue
        first = votes[0][1]
        result = {
            "lead_id": lead_id,
            "verdict": first["verdict"],
            "reason": "Consensus across " + ", ".join(sorted(models)) + ": " + first["reason"],
            "evidence_ids": sorted({item for _, vote in votes for item in vote["evidence_ids"]}),
        }
        for field in ("impact", "safe_next_step", "cvss"):
            if field in first:
                result[field] = first[field]
        combined.append(validate_triage(result))
    return combined


def write_consensus(documents: list[tuple[str, list[dict[str, Any]]]], output: str, minimum_models: int = 2) -> int:
    result = combine_results(documents, minimum_models)
    Path(output).write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return len(result)
