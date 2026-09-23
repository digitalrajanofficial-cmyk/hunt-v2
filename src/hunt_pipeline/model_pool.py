import json
import re
import subprocess
import time
from pathlib import Path
from typing import Any

from .hypothesis import validate_generated_leads
from .models import validate_triage

DEFAULT_FREE_POOL = [
    "opencode/big-pickle",
    "opencode/space-bunny-free",
    "opencode/mimo-v2.6-flash-free",
    "opencode/mimo-v2.5-free",
    "opencode/ling-3.0-flash-fin-free",
    "opencode/nemotron-3-ultra-free",
    "opencode/nemotron-3.5-lightning-free",
    "opencode/muse-spark-1.3-contributor-free",
]


def parse_pool(value: str) -> list[str]:
    models = []
    for item in value.split(","):
        model = item.strip()
        if model and model not in models:
            models.append(model)
    if not models:
        raise ValueError("model pool is empty")
    return models


def rotate_pool(pool: list[str], rotation: int) -> list[str]:
    offset = rotation % len(pool)
    return pool[offset:] + pool[:offset]


def extract_objects(text: str, key: str) -> list[dict[str, Any]]:
    decoder = json.JSONDecoder()
    results = []
    for index, character in enumerate(text):
        if character != "{":
            continue
        try:
            value, _ = decoder.raw_decode(text[index:])
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict) and isinstance(value.get(key), list):
            results.append(value)
    return results


def load_health(path: str) -> dict[str, Any]:
    try:
        value = json.loads(Path(path).read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def save_health(path: str, health: dict[str, Any]) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(health, indent=2) + "\n", encoding="utf-8")


def available_models(
    pool: list[str],
    rotation: int,
    excluded: set[str],
    health: dict[str, Any],
    cooldown_seconds: int,
) -> list[str]:
    now = time.time()
    failures = health.get("failures", {}) if isinstance(health.get("failures", {}), dict) else {}
    ordered = rotate_pool(pool, rotation)
    available = []
    for model in ordered:
        if model in excluded:
            continue
        last_failure = failures.get(model)
        if isinstance(last_failure, (int, float)) and now - last_failure < cooldown_seconds:
            continue
        available.append(model)
    if not available:
        available = [model for model in ordered if model not in excluded]
    return available


def run_model(
    agent: str,
    mode: str,
    prompt_path: str,
    output_path: str,
    pool: list[str],
    rotation: int = 0,
    timeout_seconds: int = 1200,
    excluded: set[str] | None = None,
    health_path: str = "state/model-health.json",
    inventory_path: str | None = None,
    delta_path: str | None = None,
    program: str = "",
    attempt_dir: str | None = None,
    cooldown_seconds: int = 3600,
) -> str:
    if mode not in {"hypothesis", "triage"}:
        raise ValueError("mode must be hypothesis or triage")
    if mode == "hypothesis" and (not inventory_path or not program):
        raise ValueError("hypothesis mode requires inventory_path and program")
    prompt = Path(prompt_path).read_text(encoding="utf-8")
    inventory = json.loads(Path(inventory_path).read_text(encoding="utf-8")) if inventory_path else None
    delta = json.loads(Path(delta_path).read_text(encoding="utf-8")) if delta_path else None
    health = load_health(health_path)
    failures = health.get("failures", {}) if isinstance(health.get("failures", {}), dict) else {}
    excluded = excluded or set()
    candidates = available_models(pool, rotation, excluded, health, cooldown_seconds)
    errors = []
    for model in candidates:
        try:
            completed = subprocess.run(
                ["opencode", "run", "--agent", agent, "--model", model],
                input=prompt,
                text=True,
                capture_output=True,
                timeout=timeout_seconds,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            errors.append(f"{model}: {type(exc).__name__}")
            failures[model] = time.time()
            continue
        if attempt_dir:
            attempt = Path(attempt_dir) / (re.sub(r"[^A-Za-z0-9_.-]+", "_", model) + ".txt")
            attempt.parent.mkdir(parents=True, exist_ok=True)
            attempt.write_text(completed.stdout + "\n[stderr]\n" + completed.stderr, encoding="utf-8")
        if completed.returncode != 0:
            errors.append(f"{model}: exit {completed.returncode}")
            failures[model] = time.time()
            continue
        key = "leads" if mode == "hypothesis" else "results"
        objects = extract_objects(completed.stdout, key)
        if not objects:
            errors.append(f"{model}: no {key} JSON")
            failures[model] = time.time()
            continue
        candidate = objects[-1]
        try:
            if mode == "hypothesis":
                leads = validate_generated_leads(candidate, program, inventory, delta)
                result = {"model": model, "leads": leads}
            else:
                results = [validate_triage(item) for item in candidate["results"]]
                result = {"model": model, "results": results}
        except (TypeError, ValueError) as exc:
            errors.append(f"{model}: invalid output ({exc})")
            failures[model] = time.time()
            continue
        failures.pop(model, None)
        health["failures"] = failures
        save_health(health_path, health)
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        Path(output_path).write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        return model
    health["failures"] = failures
    save_health(health_path, health)
    raise RuntimeError("all configured models failed: " + "; ".join(errors))
