import json
import re
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from .models import ValidationError

REPO_PATTERN = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
LEAD_ID_PATTERN = re.compile(r"^[A-Za-z0-9_.:-]{1,120}$")


def validate_approval(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValidationError("approval must be an object")
    required = {"program", "lead_id", "approved", "title", "body", "reviewer"}
    missing = required - value.keys()
    unknown = value.keys() - required - {"evidence_ids"}
    if missing:
        raise ValidationError(f"approval missing fields: {', '.join(sorted(missing))}")
    if unknown:
        raise ValidationError(f"approval unknown fields: {', '.join(sorted(unknown))}")
    for field in ("program", "lead_id", "title", "body", "reviewer"):
        if not isinstance(value[field], str) or not value[field].strip():
            raise ValidationError(f"approval.{field} must be a non-empty string")
    if not isinstance(value["approved"], bool):
        raise ValidationError("approval.approved must be boolean")
    if len(value["title"]) > 200 or len(value["body"]) > 20000 or len(value["reviewer"]) > 120:
        raise ValidationError("approval text exceeds the allowed length")
    evidence_ids = value.get("evidence_ids", [])
    if not isinstance(evidence_ids, list) or any(not isinstance(item, str) or not item for item in evidence_ids):
        raise ValidationError("approval.evidence_ids must be a list of strings")
    if not LEAD_ID_PATTERN.fullmatch(value["lead_id"]):
        raise ValidationError("approval.lead_id has an invalid format")
    return value


def load_approvals(directory: str) -> list[tuple[Path, dict[str, Any]]]:
    approvals = []
    for path in sorted(Path(directory).glob("*.json")):
        value = validate_approval(json.loads(path.read_text(encoding="utf-8")))
        if value["approved"]:
            approvals.append((path, value))
    return approvals


def issue_body(approval: dict[str, Any]) -> str:
    evidence = "\n".join(f"- {item}" for item in approval.get("evidence_ids", [])) or "- None recorded"
    return (
        "## Human-approved security lead\n\n"
        f"Lead ID: `{approval['lead_id']}`\n\n"
        f"Program: `{approval['program']}`\n\n"
        f"Reviewer: `{approval['reviewer']}`\n\n"
        "### Evidence references\n"
        f"{evidence}\n\n"
        "### Approved report body\n"
        f"{approval['body']}\n"
    )


def publish_approvals(directory: str, repository: str, execute: bool = False) -> list[dict[str, Any]]:
    if not REPO_PATTERN.fullmatch(repository):
        raise ValidationError("repository must use owner/name format")
    results = []
    for path, approval in load_approvals(directory):
        body = issue_body(approval)
        if not execute:
            results.append({"file": str(path), "lead_id": approval["lead_id"], "created": False, "dry_run": True})
            continue
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".md") as handle:
            handle.write(body)
            handle.flush()
            completed = subprocess.run(
                [
                    "gh",
                    "issue",
                    "create",
                    "--repo",
                    repository,
                    "--title",
                    approval["title"],
                    "--body-file",
                    handle.name,
                ],
                text=True,
                capture_output=True,
                check=False,
            )
        if completed.returncode != 0:
            raise RuntimeError(f"GitHub issue creation failed for {path.name}: {completed.stderr.strip()}")
        results.append({"file": str(path), "lead_id": approval["lead_id"], "created": True, "url": completed.stdout.strip()})
    return results
