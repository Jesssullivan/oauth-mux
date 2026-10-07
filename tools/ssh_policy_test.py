import unittest

from ssh_policy import rewrite_kex


class PolicyTest(unittest.TestCase):
    def test_allowed_subset_replaces_only_known_incompatible_hybrids(self):
        line = "KexAlgorithms mlkem768x25519-sha256,mlkem768nistp256-sha256,curve25519-sha256,mlkem1024nistp384-sha384\n"
        self.assertEqual(rewrite_kex(line), "KexAlgorithms mlkem768x25519-sha256,curve25519-sha256\n")

    def test_policy_without_incompatible_hybrids_is_byte_preserved(self):
        line = "  KexAlgorithms curve25519-sha256 # operator restriction\n"
        self.assertEqual(rewrite_kex(line), line)

    def test_never_adds_algorithm_absent_from_actual_policy(self):
        for line in [
            "KexAlgorithms mlkem768nistp256-sha256,curve25519-sha256\n",
            "KexAlgorithms mlkem768nistp256-sha256,mlkem768x25519-sha256\n",
            "KexAlgorithms +mlkem768nistp256-sha256,curve25519-sha256\n",
        ]:
            with self.subTest(line=line), self.assertRaises(ValueError):
                rewrite_kex(line)

    def test_preserves_other_policy_and_host_identity_options(self):
        for line in [
            "Ciphers aes256-gcm@openssh.com\n", "StrictHostKeyChecking yes\n",
            "PubkeyAcceptedAlgorithms ssh-ed25519\n", "IdentityFile ~/.ssh/operator-key\n",
            "Match final all\n", "# KexAlgorithms mlkem768nistp256-sha256\n",
        ]:
            with self.subTest(line=line):
                self.assertEqual(rewrite_kex(line), line)

    def test_malformed_policy_fails_closed(self):
        for line in ["KexAlgorithms\n", "KexAlgorithms one two\n"]:
            with self.subTest(line=line), self.assertRaises(ValueError):
                rewrite_kex(line)


if __name__ == "__main__":
    unittest.main()
