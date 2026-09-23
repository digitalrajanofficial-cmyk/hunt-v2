import unittest

from hunt_pipeline.consensus import combine_results


class ConsensusTests(unittest.TestCase):
    def verdict(self, value):
        return {
            "lead_id": "lead-1",
            "verdict": value,
            "reason": "Observed response.",
            "evidence_ids": ["artifact-1"] if value == "VALID" else [],
            "impact": "Data exposure" if value == "VALID" else None,
            "safe_next_step": "Repeat read-only request" if value == "VALID" else None,
            "gate": {
                "request_ready": True,
                "scope_confirmed": True,
                "reachable": True,
                "impact_proven": True,
                "novelty_checked": True,
                "not_rejected": True,
                "triager_accept": True,
            } if value == "VALID" else None,
        }

    def clean(self, result):
        return {key: value for key, value in result.items() if value is not None}

    def test_two_models_are_required(self):
        result = combine_results([("model-a", [self.verdict("VALID")])])
        self.assertEqual(result[0]["verdict"], "HOLD")

    def test_agreement_preserves_valid(self):
        result = combine_results(
            [
                ("model-a", [self.clean(self.verdict("VALID"))]),
                ("model-b", [self.clean(self.verdict("VALID"))]),
            ]
        )
        self.assertEqual(result[0]["verdict"], "VALID")

    def test_disagreement_becomes_hold(self):
        result = combine_results(
            [
                ("model-a", [self.clean(self.verdict("VALID"))]),
                ("model-b", [self.clean(self.verdict("HOLD"))]),
            ]
        )
        self.assertEqual(result[0]["verdict"], "HOLD")


if __name__ == "__main__":
    unittest.main()
