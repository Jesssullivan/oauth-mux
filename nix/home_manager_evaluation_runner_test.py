import unittest
import os
from pathlib import Path
import tempfile
from home_manager_evaluation_runner import evaluation_command, nix_literal, validated_artifact
from home_manager_io import read_regular


class DeclaredCommandTests(unittest.TestCase):
    def test_nix_interpolation_is_literal(self):
        self.assertEqual(nix_literal('${builtins.abort "injected"}'), '"\\${builtins.abort \\"injected\\"}"')

    def test_malicious_metadata_rejected(self):
        good = {"directory": "/declared/artifact", "narHash": "sha256-" + "A" * 43 + "=",
                "sourceRevision": "c" * 40, "channel": "development"}
        for key, value in (("directory", "/declared/${builtins.abort}"), ("channel", "development${bad}"),
                           ("directory", "/declared/../artifact"), ("sourceRevision", 1)):
            bad = dict(good)
            bad[key] = value
            with self.assertRaises(ValueError):
                validated_artifact(bad)

    def test_fifo_rejected_without_writer(self):
        with tempfile.TemporaryDirectory() as directory:
            fifo = Path(directory) / "input"
            os.mkfifo(fifo)
            with self.assertRaises(ValueError):
                read_regular(fifo)

    def test_regular_bound(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "input"
            path.write_bytes(b"{}")
            self.assertEqual(read_regular(path), b"{}")
            with self.assertRaises(ValueError):
                read_regular(path, limit=1)

    def test_offline_constraints_and_literal_inputs(self):
        sources = {name: {"source": "/nix/store/" + "a" * 32 + "-" + name}
                   for name in ("home-manager", "nixpkgs")}
        artifact = {"directory": '/nix/store/' + 'b' * 32 + '-artifact',
                    "narHash": "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                    "sourceRevision": "c" * 40, "channel": "development"}
        argv = evaluation_command("/declared/nix", "/declared/expression.nix", sources, "x86_64-linux", artifact)
        self.assertIn("--offline", argv)
        self.assertEqual(argv[argv.index("allow-import-from-derivation") + 1], "false")
        self.assertEqual(argv[argv.index("builders") + 1], "")
        self.assertEqual(argv[argv.index("substituters") + 1], "")
        self.assertEqual(argv[argv.index("max-jobs") + 1], "0")
        self.assertIn('activationUnproved', argv[-1])
        self.assertNotIn("activationPackage", argv[-1])

    def test_darwin_not_qualified(self):
        with self.assertRaises(ValueError):
            evaluation_command("nix", "expr", {}, "aarch64-darwin", {})


if __name__ == "__main__":
    unittest.main()
