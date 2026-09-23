import json
import tempfile
import unittest
from pathlib import Path

from hunt_pipeline.recon import import_recon
from hunt_pipeline.scope import ScopePolicy


class ReconTests(unittest.TestCase):
    def policy(self):
        return ScopePolicy.from_dict(
            {
                "program": "testfire",
                "allowed_hosts": ["testfire.net", "*.assets.testfire.net"],
                "allowed_methods": ["GET", "HEAD"],
                "allowed_ports": [443],
                "max_requests_per_second": 1,
                "require_https": True,
            }
        )

    def test_imports_and_filters_passive_outputs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "subfinder.txt").write_text("testfire.net\noutside.invalid\n", encoding="utf-8")
            (root / "httpx.jsonl").write_text(
                json.dumps({"url": "https://api.assets.testfire.net", "status_code": 200, "title": "API"}) + "\n",
                encoding="utf-8",
            )
            inventory = import_recon(str(root), self.policy())
        urls = {item["url"] for item in inventory["assets"]}
        self.assertEqual(urls, {"https://testfire.net/", "https://api.assets.testfire.net"})
        self.assertNotIn("outside.invalid", " ".join(urls))

    def test_merges_with_probe_inventory(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "urls.txt").write_text("https://testfire.net/health\n", encoding="utf-8")
            base = {"program": "testfire", "assets": [{"id": "old", "url": "https://testfire.net/"}]}
            inventory = import_recon(str(root), self.policy(), base)
        self.assertEqual(len(inventory["assets"]), 2)


if __name__ == "__main__":
    unittest.main()
