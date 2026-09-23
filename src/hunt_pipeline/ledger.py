import hashlib
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .models import canonical, validate_lead, validate_triage


class LedgerError(ValueError):
    pass


def now() -> str:
    return datetime.now(timezone.utc).isoformat()


def lead_fingerprint(lead: dict[str, Any]) -> str:
    stable = {
        "program": lead["program"],
        "title": lead["title"].strip().lower(),
        "asset": lead["asset"].strip().lower(),
        "class": lead["class"].strip().upper(),
    }
    return hashlib.sha256(canonical(stable).encode("utf-8")).hexdigest()[:24]


class Ledger:
    def __init__(self, path: str):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.connection = sqlite3.connect(self.path)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("PRAGMA foreign_keys = ON")
        self._create_schema()

    def close(self) -> None:
        self.connection.close()

    def __enter__(self) -> "Ledger":
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        self.close()

    def _create_schema(self) -> None:
        self.connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS programs (
                program TEXT PRIMARY KEY,
                config_json TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS leads (
                id TEXT PRIMARY KEY,
                program TEXT NOT NULL,
                external_id TEXT,
                fingerprint TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'NEW',
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                UNIQUE(program, fingerprint)
            );
            CREATE TABLE IF NOT EXISTS evidence (
                id TEXT PRIMARY KEY,
                lead_id TEXT NOT NULL REFERENCES leads(id),
                kind TEXT NOT NULL,
                reference TEXT NOT NULL,
                sha256 TEXT,
                captured_at TEXT,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS verdicts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                lead_id TEXT NOT NULL REFERENCES leads(id),
                model TEXT NOT NULL,
                verdict_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS feedback (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                lead_id TEXT NOT NULL REFERENCES leads(id),
                outcome TEXT NOT NULL,
                bounty_amount INTEGER,
                notes TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_type TEXT NOT NULL,
                lead_id TEXT,
                payload_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS leads_program_idx ON leads(program);
            CREATE INDEX IF NOT EXISTS verdicts_lead_idx ON verdicts(lead_id);
            """
        )

    def save_program(self, program: str, config: dict[str, Any]) -> None:
        self.connection.execute(
            "INSERT INTO programs(program, config_json, updated_at) VALUES (?, ?, ?) "
            "ON CONFLICT(program) DO UPDATE SET config_json=excluded.config_json, updated_at=excluded.updated_at",
            (program, json.dumps(config, sort_keys=True), now()),
        )
        self.connection.commit()

    def upsert_lead(self, value: dict[str, Any]) -> tuple[str, bool]:
        lead = validate_lead(value)
        fingerprint = lead_fingerprint(lead)
        lead_id = "lead_" + hashlib.sha256(f"{lead['program']}:{fingerprint}".encode()).hexdigest()[:20]
        timestamp = now()
        existing = self.connection.execute(
            "SELECT id FROM leads WHERE program = ? AND fingerprint = ?",
            (lead["program"], fingerprint),
        ).fetchone()
        if existing:
            self.connection.execute(
                "UPDATE leads SET payload_json = ?, external_id = COALESCE(?, external_id), last_seen = ? WHERE id = ?",
                (canonical(lead), lead.get("id"), timestamp, existing["id"]),
            )
            lead_id = existing["id"]
            created = False
        else:
            self.connection.execute(
                "INSERT INTO leads(id, program, external_id, fingerprint, payload_json, first_seen, last_seen) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (lead_id, lead["program"], lead.get("id"), fingerprint, canonical(lead), timestamp, timestamp),
            )
            created = True
        for item in lead["evidence"]:
            evidence_id = hashlib.sha256(f"{lead_id}:{item['reference']}".encode()).hexdigest()[:24]
            self.connection.execute(
                "INSERT INTO evidence(id, lead_id, kind, reference, sha256, captured_at, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT(id) DO UPDATE SET kind=excluded.kind, "
                "reference=excluded.reference, sha256=excluded.sha256, captured_at=excluded.captured_at",
                (
                    evidence_id,
                    lead_id,
                    item["kind"],
                    item["reference"],
                    item.get("sha256"),
                    item.get("captured_at"),
                    timestamp,
                ),
            )
        self.connection.execute(
            "INSERT INTO events(event_type, lead_id, payload_json, created_at) VALUES (?, ?, ?, ?)",
            ("lead_upserted", lead_id, canonical({"created": created, "fingerprint": fingerprint}), timestamp),
        )
        self.connection.commit()
        return lead_id, created

    def resolve_lead_id(self, reference: str) -> str:
        row = self.connection.execute(
            "SELECT id FROM leads WHERE id = ? OR external_id = ? OR fingerprint = ? LIMIT 1",
            (reference, reference, reference),
        ).fetchone()
        if row is None:
            raise LedgerError(f"unknown lead reference: {reference}")
        return row["id"]

    def record_verdict(self, value: dict[str, Any], model: str) -> str:
        verdict = validate_triage(value)
        lead_id = self.resolve_lead_id(verdict["lead_id"])
        self.connection.execute(
            "INSERT INTO verdicts(lead_id, model, verdict_json, created_at) VALUES (?, ?, ?, ?)",
            (lead_id, model, canonical(verdict), now()),
        )
        self.connection.execute(
            "UPDATE leads SET status = ? WHERE id = ?",
            (verdict["verdict"], lead_id),
        )
        self.connection.execute(
            "INSERT INTO events(event_type, lead_id, payload_json, created_at) VALUES (?, ?, ?, ?)",
            ("verdict_recorded", lead_id, canonical(verdict), now()),
        )
        self.connection.commit()
        return lead_id

    def record_feedback(
        self,
        lead_reference: str,
        outcome: str,
        notes: str = "",
        bounty_amount: int | None = None,
    ) -> str:
        if outcome not in {"REPORTED", "DUPLICATE", "INVALID", "INFORMATIVE", "BOUNTY"}:
            raise LedgerError("unsupported feedback outcome")
        if bounty_amount is not None and bounty_amount < 0:
            raise LedgerError("bounty_amount cannot be negative")
        lead_id = self.resolve_lead_id(lead_reference)
        self.connection.execute(
            "INSERT INTO feedback(lead_id, outcome, bounty_amount, notes, created_at) VALUES (?, ?, ?, ?, ?)",
            (lead_id, outcome, bounty_amount, notes, now()),
        )
        self.connection.execute(
            "INSERT INTO events(event_type, lead_id, payload_json, created_at) VALUES (?, ?, ?, ?)",
            ("feedback_recorded", lead_id, canonical({"outcome": outcome}), now()),
        )
        self.connection.commit()
        return lead_id

    def stats(self) -> dict[str, int]:
        def count(table: str, where: str = "") -> int:
            return int(self.connection.execute(f"SELECT COUNT(*) FROM {table} {where}").fetchone()[0])

        return {
            "programs": count("programs"),
            "leads": count("leads"),
            "evidence": count("evidence"),
            "valid_verdicts": count("verdicts", "WHERE json_extract(verdict_json, '$.verdict') = 'VALID'"),
            "hold_verdicts": count("verdicts", "WHERE json_extract(verdict_json, '$.verdict') = 'HOLD'"),
            "reported_feedback": count("feedback", "WHERE outcome IN ('REPORTED', 'BOUNTY')"),
        }
