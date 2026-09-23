import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from hunt_pipeline.approval import load_approvals, publish_approvals, validate_approval


class ApprovalTests(unittest.TestCase):
    def approval(self):
        return {
            "program": "testfire",
            "lead_id": "lead_example-1",
            "approved": True,
            "title": "Approved lead",
            "body": "Human-reviewed report body.",
            "reviewer": "maintainer",
            "evidence_ids": ["asset-1"],
        }

    def test_validation(self):
        self.assertEqual(validate_approval(self.approval())["program"], "testfire")

    def test_dry_run_does_not_call_github(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "approval.json"
            path.write_text(json.dumps(self.approval()), encoding="utf-8")
            with patch("hunt_pipeline.approval.subprocess.run") as run:
                result = publish_approvals(directory, "owner/repository", False)
            run.assert_not_called()
            self.assertFalse(result[0]["created"])

    def test_approved_files_are_loaded(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "approval.json"
            path.write_text(json.dumps(self.approval()), encoding="utf-8")
            self.assertEqual(len(load_approvals(directory)), 1)


if __name__ == "__main__":
    unittest.main()
