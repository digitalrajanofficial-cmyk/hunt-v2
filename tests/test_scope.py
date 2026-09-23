import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from hunt_pipeline.scope import ScopeError, ScopePolicy


class ScopePolicyTests(unittest.TestCase):
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

    def test_exact_and_wildcard_scope(self):
        policy = self.policy()
        self.assertTrue(policy.host_allowed("example.test"))
        self.assertTrue(policy.host_allowed("api.assets.example.test"))
        self.assertFalse(policy.host_allowed("assets.example.test"))
        self.assertFalse(policy.host_allowed("example.test.evil.invalid"))

    def test_url_scope_and_method_guards(self):
        policy = self.policy()
        self.assertEqual(policy.validate_url("https://example.test/health"), ("https", "example.test", 443))
        with self.assertRaises(ScopeError):
            policy.validate_url("http://example.test/health")
        with self.assertRaises(ScopeError):
            policy.validate_url("https://outside.invalid/health")
        with self.assertRaises(ScopeError):
            policy.probe("https://example.test/", "POST")

    def test_private_and_metadata_hosts_are_blocked(self):
        policy = self.policy()
        with self.assertRaises(ScopeError):
            policy.assert_public_host("127.0.0.1")
        with self.assertRaises(ScopeError):
            policy.assert_public_host("169.254.169.254")
        with self.assertRaises(ScopeError):
            policy.validate_url("https://metadata.google.internal/computeMetadata/v1/")

    def test_dns_rebinding_to_private_address_is_blocked(self):
        policy = self.policy()
        with patch("hunt_pipeline.scope.socket.getaddrinfo", return_value=[(2, 1, 6, "", ("10.0.0.5", 0))]):
            with self.assertRaises(ScopeError):
                policy.assert_public_host("public.example.test")


if __name__ == "__main__":
    unittest.main()
