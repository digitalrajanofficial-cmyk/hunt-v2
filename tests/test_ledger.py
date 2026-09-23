import tempfile
import unittest
from pathlib import Path

from hunt_pipeline.ledger import Ledger


class LedgerTests(unittest.TestCase):
    def lead(self):
        return {
            "id": "external-1",
            "program": "example",
            "title": "Example observation",
            "asset": "https://example.test/health",
            "class": "OTHER",
            "confidence": 40,
            "source": "recon",
            "evidence": [{"kind": "response", "reference": "artifact-1"}],
        }

    def test_deduplicates_same_finding(self):
        with tempfile.TemporaryDirectory() as directory:
            with Ledger(str(Path(directory) / "hunt.sqlite")) as ledger:
                first, created_first = ledger.upsert_lead(self.lead())
                second, created_second = ledger.upsert_lead(self.lead())
                self.assertTrue(created_first)
                self.assertFalse(created_second)
                self.assertEqual(first, second)
                self.assertEqual(ledger.stats()["leads"], 1)
                self.assertEqual(ledger.stats()["evidence"], 1)

    def test_records_verdict_and_feedback(self):
        with tempfile.TemporaryDirectory() as directory:
            with Ledger(str(Path(directory) / "hunt.sqlite")) as ledger:
                lead_id, _ = ledger.upsert_lead(self.lead())
                ledger.record_verdict(
                    {
                        "lead_id": lead_id,
                        "verdict": "VALID",
                        "reason": "Existing evidence is sufficient.",
                        "evidence_ids": ["artifact-1"],
                        "impact": "Unauthorized data access.",
                        "safe_next_step": "Capture a read-only reproduction.",
                    },
                    "test-model",
                )
                ledger.record_feedback(lead_id, "INFORMATIVE", "Needs human review")
                self.assertEqual(ledger.stats()["valid_verdicts"], 1)


if __name__ == "__main__":
    unittest.main()
