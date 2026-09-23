import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from hunt_pipeline.collector import asset_id, collect, load_seed_urls
from hunt_pipeline.scope import ScopePolicy


class CollectorTests(unittest.TestCase):
    def policy(self):
        return ScopePolicy.from_dict(
            {
                "program": "example",
                "allowed_hosts": ["example.test"],
                "allowed_methods": ["GET", "HEAD"],
                "allowed_ports": [443],
                "max_requests_per_second": 1,
                "require_https": True,
            }
        )

    def test_seed_loader_ignores_comments_and_duplicates(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "seeds.txt"
            path.write_text("# comment\nhttps://example.test/\nhttps://example.test/\n", encoding="utf-8")
            self.assertEqual(load_seed_urls(str(path)), ["https://example.test/"])

    def test_collect_records_only_probe_metadata(self):
        result = {
            "status": 200,
            "body_sha256": "a" * 64,
            "body_bytes": 12,
            "truncated": False,
            "headers": {"content-type": "text/html", "set-cookie": "redacted"},
        }
        with patch("hunt_pipeline.collector.ScopePolicy.probe", return_value=result):
            inventory = collect(self.policy(), ["https://example.test/"])
        item = inventory["assets"][0]
        self.assertEqual(item["id"], asset_id("https://example.test/"))
        self.assertEqual(item["status"], 200)
        self.assertNotIn("set-cookie", item["response_headers"])
        self.assertNotIn("body", item)


if __name__ == "__main__":
    unittest.main()
