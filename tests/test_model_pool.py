import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from hunt_pipeline.model_pool import DEFAULT_FREE_POOL, extract_objects, parse_pool, run_model


class ModelPoolTests(unittest.TestCase):
    def test_extracts_json_from_noise(self):
        value = extract_objects('warning\n{"results": []}\n', "results")
        self.assertEqual(value, [{"results": []}])

    def test_pool_is_rotated(self):
        pool = parse_pool("a,b,c")
        self.assertEqual(pool, ["a", "b", "c"])
        self.assertEqual(len(DEFAULT_FREE_POOL), 8)

    def test_source_analysis_uses_sanitized_finding_ids(self):
        valid = {
            "findings": [
                {
                    "finding_id": "abc123",
                    "classification": "NOISE",
                    "report_candidate": False,
                    "reason": "Example value.",
                    "safe_next_step": "REVIEW",
                }
            ]
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            prompt = root / "prompt.txt"
            findings = root / "findings.json"
            output = root / "out.json"
            prompt.write_text("prompt", encoding="utf-8")
            findings.write_text(json.dumps({"findings": [{"id": "abc123"}]}), encoding="utf-8")
            response = subprocess.CompletedProcess([], 0, json.dumps(valid), "")
            with patch("hunt_pipeline.model_pool.subprocess.run", return_value=response):
                selected = run_model(
                    agent="source",
                    mode="source",
                    prompt_path=str(prompt),
                    source_findings_path=str(findings),
                    output_path=str(output),
                    pool=["model-a"],
                    health_path=str(root / "health.json"),
                )
            self.assertEqual(selected, "model-a")
            self.assertEqual(json.loads(output.read_text())["findings"][0]["finding_id"], "abc123")

    def test_failed_model_falls_back(self):
        valid = {
            "results": [
                {
                    "lead_id": "lead-1",
                    "verdict": "HOLD",
                    "reason": "Evidence is incomplete.",
                    "evidence_ids": [],
                }
            ]
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            prompt = root / "prompt.txt"
            output = root / "out.json"
            prompt.write_text("prompt", encoding="utf-8")
            responses = [
                subprocess.CompletedProcess([], 1, "", "rate limited"),
                subprocess.CompletedProcess([], 0, json.dumps(valid), ""),
            ]
            with patch("hunt_pipeline.model_pool.subprocess.run", side_effect=responses):
                selected = run_model(
                    agent="triage",
                    mode="triage",
                    prompt_path=str(prompt),
                    output_path=str(output),
                    pool=["model-a", "model-b"],
                    health_path=str(root / "health.json"),
                    attempt_dir=str(root / "attempts"),
                )
            self.assertEqual(selected, "model-b")
            self.assertEqual(json.loads(output.read_text())["model"], "model-b")
            self.assertTrue((root / "attempts" / "model-a.txt").exists())


if __name__ == "__main__":
    unittest.main()
