import unittest

from prepare_retirement import prepare


class CustodyTests(unittest.TestCase):
    def test_before_digest_drift_refuses(self):
        with self.assertRaisesRegex(ValueError, "before digest mismatch"):
            prepare(b"changed source", "0" * 64)

    def test_noncanonical_digest_refuses(self):
        with self.assertRaisesRegex(ValueError, "noncanonical"):
            prepare(b"source", "A" * 64)


if __name__ == "__main__":
    unittest.main()
