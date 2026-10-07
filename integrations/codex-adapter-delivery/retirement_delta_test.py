import unittest

from retirement_delta import MAX_SOURCE_BYTES, transform


class RefusalTests(unittest.TestCase):
    def test_no_method_is_refused(self):
        with self.assertRaises(ValueError):
            transform(b"unrelated source")

    def test_oversized_input_is_refused(self):
        with self.assertRaises(ValueError):
            transform(b"x" * (MAX_SOURCE_BYTES + 1))

    def test_ambiguous_method_is_refused(self):
        with self.assertRaises(ValueError):
            transform(b"    pub async fn shutdown_all_threads_bounded(" * 2)


if __name__ == "__main__":
    unittest.main()
