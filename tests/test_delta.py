import unittest

from hunt_pipeline.delta import diff_inventory


class DeltaTests(unittest.TestCase):
    def test_detects_added_removed_and_changed_assets(self):
        previous = [{"id": "a", "status": 200}, {"id": "b", "status": 200}]
        current = [{"id": "a", "status": 204}, {"id": "c", "status": 200}]
        result = diff_inventory(previous, current)
        self.assertEqual(result["counts"], {"added": 1, "removed": 1, "changed": 1})
        self.assertEqual(result["changed"][0]["key"], "a")

    def test_ignores_observation_timestamp(self):
        previous = [{"id": "a", "status": 200, "observed_at": "old"}]
        current = [{"id": "a", "status": 200, "observed_at": "new"}]
        result = diff_inventory(previous, current)
        self.assertEqual(result["counts"], {"added": 0, "removed": 0, "changed": 0})


if __name__ == "__main__":
    unittest.main()
