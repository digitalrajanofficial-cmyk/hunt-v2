import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


STATES = ["INIT", "RECON", "SURFACE", "HYPOTHESIS", "VERIFY", "TRIAGE", "LEARN", "DONE"]
TRANSITIONS = {
    "INIT": {"inventory_collected": "RECON", "no_inventory": "RECON"},
    "RECON": {"inventory_collected": "SURFACE", "no_inventory": "RECON"},
    "SURFACE": {"delta_found": "HYPOTHESIS", "no_delta": "RECON"},
    "HYPOTHESIS": {"leads_generated": "VERIFY", "no_leads": "RECON"},
    "VERIFY": {"verified": "TRIAGE", "no_leads": "RECON"},
    "TRIAGE": {"verdicts_recorded": "LEARN", "no_verdicts": "HYPOTHESIS"},
    "LEARN": {"knowledge_updated": "RECON", "cycle_complete": "RECON"},
    "DONE": {},
}


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def state_path(program: str, base: str = "state") -> Path:
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", program)
    path = Path(base)
    path.mkdir(parents=True, exist_ok=True)
    return path / f"{safe}-state.json"


def default_state(program: str) -> dict[str, Any]:
    return {
        "program": program,
        "state": "INIT",
        "updated_at": now(),
        "history": [],
        "context": {},
    }


def load_state(program: str, base: str = "state") -> dict[str, Any]:
    path = state_path(program, base)
    if not path.exists():
        return default_state(program)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(data, dict) and data.get("program") == program and data.get("state") in STATES:
            return data
    except (OSError, json.JSONDecodeError):
        pass
    return default_state(program)


def save_state(program: str, data: dict[str, Any], base: str = "state") -> None:
    data["updated_at"] = now()
    path = state_path(program, base)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def transition(program: str, event: str, base: str = "state", metadata: dict[str, Any] | None = None) -> dict[str, Any]:
    data = load_state(program, base)
    current = data.get("state", "INIT")
    nxt = TRANSITIONS.get(current, {}).get(event)
    if not nxt:
        if event in {"disable", "done"}:
            nxt = "DONE"
        elif event in {"reset"}:
            nxt = "INIT"
        else:
            nxt = current
    entry = {"from": current, "to": nxt, "event": event, "at": now()}
    if metadata:
        entry["metadata"] = metadata
    data["history"].append(entry)
    if len(data["history"]) > 100:
        data["history"] = data["history"][-100:]
    data["state"] = nxt
    if metadata:
        data["context"].update({k: v for k, v in metadata.items() if isinstance(k, str)})
    save_state(program, data, base)
    return data


def advance_from_inventory(program: str, inventory: dict[str, Any], delta: dict[str, Any] | None, base: str = "state") -> dict[str, Any]:
    assets = inventory.get("assets", [])
    if not assets:
        return transition(program, "no_inventory", base)
    data = transition(program, "inventory_collected", base, {"asset_count": len(assets)})
    if delta and any(delta.get("counts", {}).values()):
        return transition(program, "delta_found", base, {"delta": delta.get("counts")})
    return transition(program, "no_delta", base)


def advance_from_leads(program: str, leads: list[dict[str, Any]], base: str = "state") -> dict[str, Any]:
    if leads:
        return transition(program, "leads_generated", base, {"lead_count": len(leads)})
    return transition(program, "no_leads", base)


def advance_from_verification(program: str, results: list[dict[str, Any]], base: str = "state") -> dict[str, Any]:
    if results:
        return transition(program, "verified", base, {"verified": len(results)})
    return transition(program, "no_leads", base)


def advance_from_triage(program: str, verdicts: list[dict[str, Any]], base: str = "state") -> dict[str, Any]:
    if verdicts:
        return transition(program, "verdicts_recorded", base, {"verdicts": len(verdicts)})
    return transition(program, "no_verdicts", base)
