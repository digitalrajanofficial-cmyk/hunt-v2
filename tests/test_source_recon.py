import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from hunt_pipeline.source_recon import (
    build_source_prompt,
    enumerate_repositories,
    run_source_recon,
    scan_repository,
    validate_source_analysis,
    validate_source_config,
)


class SourceReconTests(unittest.TestCase):
    def config(self):
        return validate_source_config(
            {
                "program": "vr",
                "authorization_reference": "test authorization",
                "enabled": True,
                "github_orgs": ["example"],
                "max_files_per_repo": 100,
                "max_findings_per_repo": 50,
            }
        )

    def test_secret_matches_are_redacted_and_urls_are_sanitized(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            aws_key = "AKIA" + ("F" * 16)
            (root / "app.py").write_text(
                f"AWS_KEY={aws_key}\n"
                "URL=https://api.example.test/v1?token=do-not-store\n"
                "INTERNAL=http://dev.example.test/private\n",
                encoding="utf-8",
            )
            result = scan_repository(root, "example/app", self.config())
        serialized = json.dumps(result)
        self.assertNotIn(aws_key, serialized)
        self.assertNotIn("do-not-store", serialized)
        self.assertIn("[REDACTED]", serialized)
        self.assertIn("https://api.example.test/v1", serialized)
        self.assertIn("internal-endpoint", serialized)

    def test_enumeration_filters_private_archived_and_forks(self):
        config = validate_source_config(
            {
                "program": "vr",
                "authorization_reference": "test authorization",
                "enabled": True,
                "github_orgs": ["example"],
                "max_repos_per_org": 1,
            }
        )
        batch = [
            {"full_name": "example/public", "private": False, "archived": False, "fork": False, "size": 10, "language": "Python"},
            {"full_name": "example/private", "private": True, "archived": False, "fork": False, "size": 10, "language": "Python"},
            {"full_name": "example/archived", "private": False, "archived": True, "fork": False, "size": 10, "language": "Python"},
        ]
        with patch("hunt_pipeline.source_recon.github_json", return_value=batch):
            repositories = enumerate_repositories(config)
        self.assertEqual([item["full_name"] for item in repositories], ["example/public"])

    def test_disabled_config_does_not_enumerate(self):
        with tempfile.TemporaryDirectory() as directory:
            config = validate_source_config({"program": "vr", "authorization_reference": "test authorization", "enabled": False, "github_orgs": []})
            with patch("hunt_pipeline.source_recon.enumerate_repositories") as enumerate_repositories:
                summary = run_source_recon(config, directory)
            enumerate_repositories.assert_not_called()
            self.assertFalse(summary["enabled"])
            self.assertEqual(summary["findings"], [])

    def test_source_analysis_rejects_unknown_finding(self):
        findings = {"findings": [{"id": "abc123", "category": "endpoint", "evidence": "https://example.test/"}]}
        with self.assertRaises(ValueError):
            validate_source_analysis(
                {
                    "findings": [
                        {
                            "finding_id": "other",
                            "classification": "NOISE",
                            "report_candidate": False,
                            "reason": "unknown",
                            "safe_next_step": "REVIEW",
                        }
                    ]
                },
                findings,
            )

    def test_source_prompt_contains_only_sanitized_json(self):
        prompt = build_source_prompt({"findings": [{"id": "abc", "evidence": "[REDACTED]"}]}, "vr")
        self.assertIn("<source_findings>", prompt)
        self.assertIn("abc", prompt)
        self.assertNotIn("secret_value", prompt)

    def test_invalid_repository_name_is_rejected(self):
        with self.assertRaises(ValueError):
            validate_source_config({"program": "vr", "authorization_reference": "test authorization", "github_repos": ["not-a-repository"]})


if __name__ == "__main__":
    unittest.main()
