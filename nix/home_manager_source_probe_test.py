import unittest
from pathlib import Path
from home_manager_inputs_test import PairedInputsTests
from home_manager_source_probe import probe


class ProbeTests(unittest.TestCase):
    def setUp(self):
        fixture = PairedInputsTests()
        fixture.setUp()
        self.lock = fixture.lock

    def test_exact_queries_finite_and_no_byte_claim(self):
        calls = []
        def locate(database, digest, seconds):
            calls.append((database, digest, seconds))
            return ["/nix/store/" + "a" * 32 + "-source"]
        result = probe(self.lock, locate, Path("/declared/db"))
        self.assertTrue(result["passed"])
        self.assertEqual(len(calls), 2)
        self.assertTrue(all(0 < c[2] <= 10 and c[1].startswith("sha256:") for c in calls))
        self.assertEqual(result["byte_verification"], "pending-declared-nar-action")

    def test_missing_candidate_explicit(self):
        result = probe(self.lock, lambda *args, **kwargs: [], Path("/declared/db"))
        self.assertFalse(result["passed"])
        self.assertEqual(result["source_candidates"], {"home-manager": [], "nixpkgs": []})


if __name__ == "__main__":
    unittest.main()
