import unittest

from hunt_pipeline.models import ValidationError, validate_lead, validate_triage


class ModelTests(unittest.TestCase):
    def lead(self):
        return {
            "id": "lead-example-1",
            "program": "example",
            "title": "Example observation",
            "asset": "https://example.test/health",
            "class": "OTHER",
            "confidence": 40,
            "source": "recon",
            "evidence": [{"kind": "response", "reference": "artifact-1"}],
        }

    def test_valid_lead(self):
        self.assertEqual(validate_lead(self.lead())["id"], "lead-example-1")

    def test_lead_rejects_unknown_fields(self):
        value = self.lead()
        value["unexpected"] = True
        with self.assertRaises(ValidationError):
            validate_lead(value)

    def test_lead_rejects_string_confidence(self):
        value = self.lead()
        value["confidence"] = "40"
        with self.assertRaises(ValidationError):
            validate_lead(value)

    def test_valid_triage_requires_evidence(self):
        value = {
            "lead_id": "lead-example-1",
            "verdict": "VALID",
            "reason": "The response proves the behavior.",
            "evidence_ids": [],
        }
        with self.assertRaises(ValidationError):
            validate_triage(value)

    def test_valid_triage(self):
        value = {
            "lead_id": "lead-example-1",
            "verdict": "VALID",
            "reason": "The response proves the behavior.",
            "evidence_ids": ["artifact-1"],
            "impact": "Unauthorized data access.",
            "safe_next_step": "Repeat the read-only request and capture the response.",
        }
        self.assertEqual(validate_triage(value)["verdict"], "VALID")


if __name__ == "__main__":
    unittest.main()
