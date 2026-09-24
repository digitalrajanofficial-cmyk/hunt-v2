import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def knowledge_dir(base: str = "knowledge") -> Path:
    path = Path(base)
    path.mkdir(parents=True, exist_ok=True)
    return path


def program_knowledge_path(program: str, base: str = "knowledge") -> Path:
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", program)
    return knowledge_dir(base) / f"{safe}.json"


def markdown_path(program: str, base: str = "knowledge") -> Path:
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", program)
    return knowledge_dir(base) / f"{safe}.md"


def default_knowledge(program: str) -> dict[str, Any]:
    return {
        "program": program,
        "updated_at": now(),
        "learnings": [],
        "rejected": [],
        "hypotheses": [],
        "inventory_summaries": [],
        "stats": {"total_leads": 0, "valid": 0, "invalid": 0},
    }


def load_knowledge(program: str, base: str = "knowledge") -> dict[str, Any]:
    path = program_knowledge_path(program, base)
    if not path.exists():
        return default_knowledge(program)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(data, dict) and data.get("program") == program:
            return data
    except (OSError, json.JSONDecodeError):
        pass
    return default_knowledge(program)


def save_knowledge(program: str, data: dict[str, Any], base: str = "knowledge") -> None:
    data["updated_at"] = now()
    path = program_knowledge_path(program, base)
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    md = markdown_path(program, base)
    lines = [f"# Knowledge {program}", f"Updated: {data['updated_at']}", ""]
    if data.get("rejected"):
        lines.append("## Rejected")
        for item in data["rejected"][-20:]:
            lines.append(f"- {item.get('class')} @ {item.get('asset')}: {item.get('reason')}")
        lines.append("")
    if data.get("learnings"):
        lines.append("## Learnings")
        for item in data["learnings"][-20:]:
            lines.append(f"- {item.get('text')}")
        lines.append("")
    md.write_text("\n".join(lines) + "\n", encoding="utf-8")


def add_learning(program: str, text: str, base: str = "knowledge") -> dict[str, Any]:
    data = load_knowledge(program, base)
    entry = {"text": text.strip()[:500], "created_at": now()}
    if entry["text"] and entry["text"] not in {x.get("text") for x in data["learnings"]}:
        data["learnings"].append(entry)
        if len(data["learnings"]) > 100:
            data["learnings"] = data["learnings"][-100:]
        save_knowledge(program, data, base)
    return data


def add_rejected(program: str, klass: str, asset: str, reason: str, base: str = "knowledge") -> dict[str, Any]:
    data = load_knowledge(program, base)
    entry = {
        "class": klass.strip().upper()[:40],
        "asset": asset.strip()[:300],
        "reason": reason.strip()[:500],
        "created_at": now(),
    }
    data["rejected"].append(entry)
    if len(data["rejected"]) > 100:
        data["rejected"] = data["rejected"][-100:]
    save_knowledge(program, data, base)
    return data


def record_hypothesis(program: str, hypothesis: dict[str, Any], base: str = "knowledge") -> dict[str, Any]:
    data = load_knowledge(program, base)
    entry = {
        "title": str(hypothesis.get("title", ""))[:200],
        "asset": str(hypothesis.get("asset", ""))[:300],
        "class": str(hypothesis.get("class", ""))[:40],
        "confidence": hypothesis.get("confidence"),
        "created_at": now(),
    }
    data["hypotheses"].append(entry)
    if len(data["hypotheses"]) > 200:
        data["hypotheses"] = data["hypotheses"][-200:]
    save_knowledge(program, data, base)
    return data


def tokenize(text: str) -> set[str]:
    return set(re.findall(r"[a-z0-9]{3,}", text.lower()))


def retrieve_context(program: str, query: str, base: str = "knowledge", limit: int = 5) -> str:
    data = load_knowledge(program, base)
    candidates: list[tuple[int, str]] = []
    query_tokens = tokenize(query)
    if not query_tokens:
        query_tokens = tokenize(program)
    for item in data.get("learnings", []):
        text = str(item.get("text", ""))
        score = len(query_tokens & tokenize(text))
        if score:
            candidates.append((score, f"LEARNING: {text}"))
    for item in data.get("rejected", []):
        text = f"{item.get('class')} {item.get('asset')} {item.get('reason')}"
        score = len(query_tokens & tokenize(text))
        if score:
            candidates.append((score, f"REJECTED {item.get('class')} @ {item.get('asset')}: {item.get('reason')}"))
    for item in data.get("hypotheses", []):
        text = f"{item.get('title')} {item.get('asset')} {item.get('class')}"
        score = len(query_tokens & tokenize(text))
        if score:
            candidates.append((score, f"HYPOTHESIS {item.get('title')} @ {item.get('asset')}"))
    candidates.sort(key=lambda x: x[0], reverse=True)
    if not candidates:
        fallback = []
        for item in data.get("learnings", [])[-3:]:
            fallback.append(f"LEARNING: {item.get('text')}")
        for item in data.get("rejected", [])[-3:]:
            fallback.append(f"REJECTED {item.get('class')} @ {item.get('asset')}: {item.get('reason')}")
        candidates = [(1, t) for t in fallback]
    selected = [text for _, text in candidates[:limit]]
    if not selected:
        return "No prior knowledge for this program."
    return "\n".join(f"- {line}" for line in selected)


def build_rag_prompt(program: str, query: str, base: str = "knowledge", limit: int = 5) -> str:
    context = retrieve_context(program, query, base, limit)
    return f"KNOWLEDGE for {program}:\n{context}"


def knowledge_hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]
