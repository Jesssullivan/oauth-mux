"""Actual fresh reader/delegation failures; no processes or provider access."""
import hashlib
import json
import os
from pathlib import Path
import sys
import unittest
from unittest import mock

import test_installed_fresh_native_tui as fresh_tui
import test_installed_native_tui as tui
import test_installed_codex_live_continuity as runtime_support


class FreshOrdinaryContract(unittest.TestCase):
    def test_missing_or_retained_runtime_selection_is_refused_before_fixture(self):
        for arguments in ([], ["--runtime-kind=retained"], ["--runtime-kind=fresh"]):
            with self.subTest(arguments=arguments), mock.patch.object(sys, "argv", ["fixture", *arguments]), \
                    mock.patch.object(tui, "main") as fixture:
                with self.assertRaises(ValueError):
                    fresh_tui.main()
                fixture.assert_not_called()

    def test_fresh_entrypoint_preserves_child_selection_without_constructing_live_scenario(self):
        pin = Path("/public/input-pin.json")
        arguments = ["bundle", "candidate", "receipt", "session", "bus", "keyring"]
        with mock.patch.object(sys, "argv", ["fixture", *arguments]), \
                mock.patch.object(runtime_support, "runtime_arguments", return_value=("fresh", pin, arguments)), \
                mock.patch.object(runtime_support, "LiveScenario") as scenario, \
                mock.patch.object(tui, "main", return_value=0) as fixture:
            self.assertEqual(fresh_tui.main(), 0)
            keywords = fixture.call_args.kwargs
            self.assertNotIn("live", keywords)
            self.assertEqual(keywords["entrypoint_args"],
                             ("--runtime-kind=fresh", "--runtime-pin=" + str(pin)))
            scenario.assert_not_called()
            self.assertEqual(sys.argv[1:], arguments)

    def runtime_inputs(self):
        manifest = {"kind": runtime_support.FRESH_KIND}
        payload, receipt = b"public archive", json.dumps({"kind": runtime_support.FRESH_KIND}).encode()
        encoded_manifest = (json.dumps(manifest, sort_keys=True, indent=2) + "\n").encode()
        pin = {"kind": runtime_support.FRESH_KIND}
        for role, value in (("archive", payload), ("receipt", receipt), ("manifest", encoded_manifest)):
            pin[role + "_sha256"] = hashlib.sha256(value).hexdigest()
            pin[role + "_bytes"] = len(value)
        return manifest, payload, receipt, pin

    def test_actual_reader_refuses_unmatched_archive_receipt_or_manifest_provenance(self):
        for changed in ("archive", "receipt", "manifest"):
            manifest, payload, receipt, pin = self.runtime_inputs()
            pin[changed + "_sha256"] = "0" * 64
            values = {Path("/public/pin"): json.dumps(pin).encode(),
                      Path("/public/candidate"): payload, Path("/public/receipt"): receipt}
            with self.subTest(changed=changed), \
                    mock.patch.object(runtime_support, "public_runtime_file", side_effect=lambda path, maximum: values[path]), \
                    mock.patch("codex_fresh_native_runtime.verify_runtime_files", return_value=(manifest, {})) as verifier:
                with self.assertRaises(ValueError):
                    fresh_tui.qualified_reader(Path("/public/pin"))(Path("/public/candidate"), Path("/public/receipt"))
                if changed != "manifest":
                    verifier.assert_not_called()

    def test_reader_failure_precedes_any_archive_install_daemon_or_provider_work(self):
        with mock.patch.dict(os.environ, {"OMUX_ISOLATED_VAULT_PROOF": "private-bus-private-xdg"}), \
                mock.patch.object(runtime_support, "fresh_runtime_bundle", side_effect=ValueError("refused")) as reader, \
                mock.patch.object(tui.support.pack, "read_bundle") as install_input, \
                mock.patch.object(tui.subprocess, "Popen") as process:
            with self.assertRaises(ValueError):
                tui.inside(*([Path("/public/unused")] * 5), runtime_reader=fresh_tui.qualified_reader(Path("/public/pin")))
            reader.assert_called_once()
            install_input.assert_not_called()
            process.assert_not_called()

    def test_runtime_reader_cannot_replace_live_runtime_selection(self):
        reader = mock.Mock()
        with mock.patch.dict(os.environ, {"OMUX_ISOLATED_VAULT_PROOF": "private-bus-private-xdg"}):
            with self.assertRaises(ValueError):
                tui.inside(*([Path("/public/unused")] * 5), live=mock.Mock(), runtime_reader=reader)
        reader.assert_not_called()

    def test_shared_ordinary_resume_still_refuses_rewritten_prefix_or_store_identity(self):
        before = (("row",), (1, 2), b"digest", b"original\n")
        for resumed in ((("row",), (1, 3), b"digest", b"original\ncheckpoint\n"),
                        (("row",), (1, 2), b"digest", b"rewritten\ncheckpoint\n")):
            with self.subTest(resumed=resumed), \
                    mock.patch.object(tui.native_resumed_checkpoint, "validate_paginated_checkpoint") as append:
                with self.assertRaises(ValueError):
                    tui.resumed_history(before, resumed, "thread")
                append.assert_not_called()


if __name__ == "__main__":
    unittest.main()
