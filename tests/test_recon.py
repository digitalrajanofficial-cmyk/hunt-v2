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
                "program": "example",
                "allowed_hosts": ["example.test", "*.assets.example.test"],
                "allowed_methods": ["GET", "HEAD"],
                "allowed_ports": [443],
                "max_requests_per_second": 1,
                "require_https": True,
            }
        )

    def test_imports_and_filters_passive_outputs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "subfinder.txt").write_text("example.test\noutside.invalid\n", encoding="utf-8")
            (root / "httpx.jsonl").write_text(
                json.dumps({"url": "https://api.assets.example.test", "status_code": 200, "title": "API"}) + "\n",
                encoding="utf-8",
            )
            inventory = import_recon(str(root), self.policy())
        urls = {item["url"] for item in inventory["assets"]}
        self.assertEqual(urls, {"https://example.test/", "https://api.assets.example.test"})
        self.assertNotIn("outside.invalid", " ".join(urls))

    def test_merges_with_probe_inventory(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "urls.txt").write_text("https://example.test/health\n", encoding="utf-8")
            base = {"program": "example", "assets": [{"id": "old", "url": "https://example.test/"}]}
            inventory = import_recon(str(root), self.policy(), base)
        self.assertEqual(len(inventory["assets"]), 2)


if __name__ == "__main__":
    unittest.main()
