import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .knowledge import add_learning, add_rejected, load_knowledge
from .ledger import Ledger


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def compute_metrics(db_path: str) -> dict[str, Any]:
    with Ledger(db_path) as ledger:
        stats = ledger.stats()
        rows = ledger.connection.execute(
            """
            SELECT
                json_extract(payload_json, '$.class') as klass,
                COUNT(*) as cnt
            FROM leads
            GROUP BY json_extract(payload_json, '$.class')
            """
        ).fetchall()
        by_class = {row[0] or "unknown": int(row[1]) for row in rows}
        verdict_rows = ledger.connection.execute(
            """
            SELECT json_extract(verdict_json, '$.verdict') as verdict, COUNT(*) as cnt
            FROM verdicts
            GROUP BY json_extract(verdict_json, '$.verdict')
            """
        ).fetchall()
        by_verdict = {row[0] or "unknown": int(row[1]) for row in verdict_rows}
        feedback_rows = ledger.connection.execute(
            """
            SELECT outcome, COUNT(*) as cnt, COALESCE(SUM(bounty_amount),0) as total
            FROM feedback
            GROUP BY outcome
            """
        ).fetchall()
        by_feedback: dict[str, dict[str, int]] = {}
        for outcome, cnt, total in feedback_rows:
            by_feedback[outcome] = {"count": int(cnt), "bounty_total": int(total or 0)}
        recent = ledger.connection.execute(
            """
            SELECT payload_json FROM leads ORDER BY last_seen DESC LIMIT 5
            """
        ).fetchall()
        recent_titles = []
        for row in recent:
            try:
                payload = json.loads(row[0])
                recent_titles.append(str(payload.get("title", ""))[:120])
            except (json.JSONDecodeError, TypeError):
                continue
    total = stats.get("leads", 0)
    valid = stats.get("valid_verdicts", 0)
    hold = stats.get("hold_verdicts", 0)
    reported = stats.get("reported_feedback", 0)
    return {
        "generated_at": now(),
        "totals": stats,
        "by_class": by_class,
        "by_verdict": by_verdict,
        "by_feedback": by_feedback,
        "rates": {
            "valid_rate": round(valid / total, 3) if total else 0,
            "hold_rate": round(hold / total, 3) if total else 0,
            "reported_rate": round(reported / total, 3) if total else 0,
        },
        "recent_titles": recent_titles,
    }


def update_knowledge_from_metrics(program: str, db_path: str, base: str = "knowledge") -> dict[str, Any]:
    metrics = compute_metrics(db_path)
    knowledge = load_knowledge(program, base)
    for klass, count in metrics.get("by_class", {}).items():
        if klass == "unknown":
            continue
        invalid = 0
        try:
            with Ledger(db_path) as ledger:
                row = ledger.connection.execute(
                    """
                    SELECT COUNT(*) FROM verdicts
                    WHERE json_extract(verdict_json, '$.verdict') = 'INVALID'
                    AND lead_id IN (SELECT id FROM leads WHERE json_extract(payload_json, '$.class') = ? AND program = ?)
                    """,
                    (klass, program),
                ).fetchone()
                invalid = int(row[0]) if row else 0
        except Exception:
            invalid = 0
        if invalid >= 3 and count >= 3:
            add_rejected(program, klass, "*", f"auto-rejected after {invalid} INVALID verdicts", base)
            add_learning(program, f"REJECTED {klass} shows repeated INVALID outcomes", base)
    if metrics["rates"]["hold_rate"] > 0.5:
        add_learning(program, f"HIGH_HOLD rate {metrics['rates']['hold_rate']} suggests evidence gaps", base)
    if metrics["totals"].get("reported_feedback", 0) > 0:
        add_learning(program, f"REPORTED {metrics['totals']['reported_feedback']} leads", base)
    return load_knowledge(program, base)


def write_feedback_report(db_path: str, output_path: str, program: str = "") -> dict[str, Any]:
    metrics = compute_metrics(db_path)
    if program:
        update_knowledge_from_metrics(program, db_path)
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        f"# Feedback report {metrics['generated_at']}",
        "",
        f"Total leads: {metrics['totals'].get('leads', 0)}",
        f"Valid: {metrics['totals'].get('valid_verdicts', 0)} | Hold: {metrics['totals'].get('hold_verdicts', 0)} | Reported: {metrics['totals'].get('reported_feedback', 0)}",
        f"Valid rate: {metrics['rates']['valid_rate']} | Hold rate: {metrics['rates']['hold_rate']}",
        "",
        "## By class",
    ]
    for klass, cnt in sorted(metrics["by_class"].items(), key=lambda x: x[1], reverse=True)[:10]:
        lines.append(f"- {klass}: {cnt}")
    lines.append("")
    lines.append("## By verdict")
    for verdict, cnt in metrics["by_verdict"].items():
        lines.append(f"- {verdict}: {cnt}")
    lines.append("")
    lines.append("## By feedback")
    for outcome, info in metrics["by_feedback"].items():
        lines.append(f"- {outcome}: {info['count']} (bounty {info['bounty_total']})")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return metrics
