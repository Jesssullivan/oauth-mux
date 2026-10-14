"""Built documentation producer parity; run only through the declared Bazel test.

Compare full bytes against actual maintained Omux, never a fixture or copied
catalog. No daemon, account, browser, provider, or OS-vault operation is invoked.
"""
from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path


OMUX = Path(sys.argv.pop(1))
RENDERER = Path(sys.argv.pop(1))
BUNDLE = Path(sys.argv.pop(1))
COMMIT = "0123456789abcdef0123456789abcdef01234567"


def invoke(executable: Path, arguments: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run([str(executable), "reference", *arguments],
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        timeout=10, check=False)


class ReferenceRendererParity(unittest.TestCase):
    def test_complete_catalog_and_framing_match_actual_cli(self) -> None:
        for arguments in ([], ["--source-commit", COMMIT, "--source-dirty", "true"],
                          ["--source-commit", COMMIT, "--source-dirty", "false"]):
            with self.subTest(arguments=arguments):
                actual = invoke(OMUX, arguments)
                rendered = invoke(RENDERER, arguments)
                self.assertEqual(actual.returncode, 0)
                self.assertEqual(rendered.returncode, 0)
                self.assertEqual(actual.stdout, rendered.stdout)
                self.assertEqual(actual.stderr, rendered.stderr)
                self.assertTrue(rendered.stdout.endswith(b"\n"))

    def test_generated_exec_bundle_matches_actual_target_cli(self) -> None:
        generated = BUNDLE.read_bytes()
        self.assertLessEqual(len(generated), 2 * 1024 * 1024)
        provenance = json.loads(generated)["provenance"]
        arguments = [] if provenance["sourceRevision"] is None else [
            "--source-commit", provenance["sourceRevision"], "--source-dirty",
            "true" if provenance["sourceDirty"] else "false"]
        actual = invoke(OMUX, arguments)
        self.assertEqual(actual.returncode, 0)
        self.assertEqual(actual.stdout, generated)

    def test_rejected_provenance_keeps_same_error_and_no_output(self) -> None:
        invalid = (["--source-commit"], ["--source-commit", COMMIT],
            ["--source-dirty", "false"],
            ["--source-commit", "", "--source-dirty", "false"],
            ["--source-commit", COMMIT.upper(), "--source-dirty", "false"],
            ["--source-commit", COMMIT, "--source-dirty", "False"],
            ["--source-dirty", "false", "--source-commit", COMMIT],
            ["--source-commit", COMMIT, "--source-dirty", "false", "extra"])
        for arguments in invalid:
            with self.subTest(arguments=arguments):
                actual = invoke(OMUX, list(arguments))
                rendered = invoke(RENDERER, list(arguments))
                self.assertNotEqual(actual.returncode, 0)
                self.assertNotEqual(rendered.returncode, 0)
                self.assertEqual(actual.stdout, b"")
                self.assertEqual(rendered.stdout, b"")
                # Stack frames belong to different entry points; the typed
                # rejection is the shared semantic contract.
                self.assertIn(b"error: InvalidArguments", actual.stderr)
                self.assertIn(b"error: InvalidArguments", rendered.stderr)


if __name__ == "__main__":
    unittest.main()
