import unittest

from hunt_pipeline.hypothesis import validate_generated_leads


class HypothesisTests(unittest.TestCase):
    def inventory(self):
        return {
            "program": "example",
            "assets": [
                {
                    "id": "asset-1",
                    "url": "https://example.test/",
                    "status": 200,
                    "body_sha256": "a" * 64,
                }
            ],
        }

    def lead(self):
        return {
            "program": "example",
            "title": "Review public response metadata",
            "asset": "https://example.test/",
            "class": "OTHER",
            "confidence": 20,
            "source": "model",
            "reasoning": "The response metadata was observed.",
            "impact": "No impact is asserted yet.",
            "evidence": [{"kind": "response", "reference": "asset-1"}],
            "priority_score": 20,
            "priority_axes": {"impact": 2, "confidence": 3},
            "evidence_needed": "A second read-only observation.",
            "next_action": "RAG: compare the response metadata with known framework behavior.",
            "testability": "PASSIVE",
        }

    def test_valid_lead(self):
        result = validate_generated_leads({"leads": [self.lead()]}, "example", self.inventory())
        self.assertEqual(result[0]["program"], "example")

    def test_rejects_unobserved_asset(self):
        value = self.lead()
        value["asset"] = "https://outside.invalid/"
        with self.assertRaises(ValueError):
            validate_generated_leads({"leads": [value]}, "example", self.inventory())

    def test_rejects_invalid_class(self):
        value = self.lead()
        value["class"] = "UNSUPPORTED"
        with self.assertRaises(ValueError):
            validate_generated_leads({"leads": [value]}, "example", self.inventory())


if __name__ == "__main__":
    unittest.main()
