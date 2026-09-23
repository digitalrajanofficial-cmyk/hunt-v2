import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from hunt_pipeline.recon_runner import recon_roots, run_safe_recon
from hunt_pipeline.scope import ScopePolicy


class ReconRunnerTests(unittest.TestCase):
    def policy(self):
        return ScopePolicy.from_dict(
            {
                "program": "vr",
                "allowed_hosts": ["www.vr.fi", "*.assets.vr.fi"],
                "allowed_methods": ["HEAD"],
                "allowed_ports": [443],
                "max_requests_per_second": 1,
                "require_https": True,
            }
        )

    def test_roots_only_come_from_allowlist(self):
        self.assertEqual(recon_roots(self.policy()), ["assets.vr.fi", "www.vr.fi"])

    def test_summary_does_not_require_dns_or_http(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch("hunt_pipeline.recon_runner.write_filtered_subfinder", return_value=1):
                summary = run_safe_recon(self.policy(), directory, run_dns=False, run_http=False)
            self.assertEqual(summary["scope_filtered_subdomains"], 1)
            self.assertEqual(summary["dnsx_records"], 0)
            self.assertEqual(json.loads(Path(directory, "summary.json").read_text())["program"], "vr")

    def test_subfinder_output_is_filtered(self):
        with tempfile.TemporaryDirectory() as directory:
            response = subprocess.CompletedProcess([], 0, "api.vr.fi\noutside.invalid\n", "")
            with patch("hunt_pipeline.recon_runner.require_tool", return_value="subfinder"):
                with patch("hunt_pipeline.recon_runner.subprocess.run", return_value=response):
                    from hunt_pipeline.recon_runner import write_filtered_subfinder
                    count = write_filtered_subfinder(self.policy(), Path(directory))
            self.assertEqual(count, 0)
            self.assertEqual(Path(directory, "subfinder.txt").read_text(), "")


if __name__ == "__main__":
    unittest.main()
