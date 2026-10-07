"""Exact live admission cannot broaden ordinary/offline execution."""
import json
import os
from pathlib import Path
import tempfile
import time
import unittest
import guard_dependency_profile as profiles
import guard_owner_runtime_input as retained
import guard_codex_live_profile as live

class LiveAdmissionTests(unittest.TestCase):
    def test_exact_live_target_only(self):
        for label in live.LABELS:
            self.assertEqual(live.selected(["test", label]), {"PrivateNetwork": "no"})
        for args in ([], ["build", live.LABEL], ["test", "//..."],
                     ["test", live.LABEL, "//:docs_check"],
                     ["test", live.LABEL, live.ENROLLMENT_LABEL],
                     ["test", "//delivery:installed_legacy_native_tui_test"]):
            with self.subTest(arguments=args), self.assertRaises(ValueError):
                live.selected(args)

    def test_system_private_inputs_are_mandatory(self):
        live.finite(["test", live.LABEL], "system", "/private/input.json",
                    "/private/runtime", False)
        for manager, manifest, runtime, reuse, unrelated in (
                ("user", "/private/input.json", "/private/runtime", False, ()),
                ("system", None, "/private/runtime", False, ()),
                ("system", "/private/input.json", None, False, ()),
                ("system", "/private/input.json", "/private/runtime", True, ()),
                ("system", "/private/input.json", "/private/runtime", False, ("other",))):
            with self.subTest(manager=manager, reuse=reuse), self.assertRaises(ValueError):
                live.finite(["test", live.LABEL], manager, manifest, runtime, reuse, unrelated)

    def test_offline_network_and_retained_target_isolation(self):
        self.assertEqual(profiles.selected_profile("standard", ["test", retained.DIAGNOSTIC]),
                         {"PrivateNetwork": "yes"})
        with self.assertRaises(ValueError):
            retained.finite("standard", ["test", live.LABEL])
        retained.finite("codex-live", ["test", live.LABEL])
        with self.assertRaises(ValueError):
            profiles.selected_profile("codex-live", ["test", live.LABEL], site_inputs=True)

    def test_enrollment_inventory_excludes_codex_runtime_and_model(self):
        live.finite(["test", live.ENROLLMENT_LABEL], "system", "/private/input.json", None, False)
        with self.assertRaises(ValueError):
            live.finite(["test", live.ENROLLMENT_LABEL], "system", "/private/input.json",
                        "/private/runtime", False)
        good = {"schema_version": 1, "authorized_source_paths": ["/private/account-a/auth.json"]}
        self.assertEqual(live.schema(json.dumps(good), live.ENROLLMENT_LABEL), good)
        for value in (dict(good, model="small-model"),
                      dict(good, authorized_source_paths=good["authorized_source_paths"] * 2)):
            with self.assertRaises(ValueError):
                live.schema(json.dumps(value), live.ENROLLMENT_LABEL)
        with self.assertRaises(ValueError):
            retained.finite("codex-live", ["test", live.ENROLLMENT_LABEL])

    def test_schema_requires_exact_paths_and_explicit_model(self):
        good = {"schema_version": 1,
                "authorized_source_paths": ["/private/account-a/auth.json", "/private/account-b/auth.json"],
                "model": "small-model"}
        self.assertEqual(live.schema(json.dumps(good)), good)
        invalid = [
            dict(good, unknown="refuse"),
            dict(good, schema_version=True),
            dict(good, authorized_source_paths=good["authorized_source_paths"][:1]),
            dict(good, authorized_source_paths=[good["authorized_source_paths"][0]] * 2),
            dict(good, model=""),
            dict(good, model="model with whitespace"),
        ]
        for value in invalid:
            with self.subTest(fields=list(value)), self.assertRaises(ValueError):
                live.schema(json.dumps(value))

    def test_bind_selector_refuses_systemd_grammar_ambiguity(self):
        self.assertEqual(live.binding_selector("/private/input.json"), "/private/input.json")
        for value in ("/private/has:colon.json", "/private/has space.json", "/private/line\\n.json"):
            with self.subTest(selector=value), self.assertRaises(ValueError):
                live.binding_selector(value)

    def test_failure_evidence_never_retains_actual_bind_selectors(self):
        private_path = "/private/selected-account/auth.json"
        actual = {"BindReadOnlyPaths": private_path + ":" + live.DESTINATION,
                  "BindPaths": private_path + ":/unexpected", "PrivateNetwork": "no"}
        before = dict(actual)
        for verified in (False, True):
            projected = live.receipt_properties(actual, verified=verified)
            self.assertNotIn(private_path, repr(projected))
            self.assertEqual(projected["PrivateNetwork"], "no")
            self.assertEqual(actual, before)
            self.assertIsNot(projected, actual)
        self.assertEqual(live.receipt_properties(actual, verified=True)["BindPaths"], "none")

    def test_live_rejection_never_stringifies_private_oserror(self):
        class PrivateOSError(OSError):
            def __str__(self):
                raise AssertionError("private exception was stringified")
        error = PrivateOSError(2, "private predicate", "/private/selected-account/auth.json")
        self.assertEqual(live.rejection_category(error), "codex-live-admission-refused")
        self.assertEqual(live.rejection_category(ValueError("private-provider-content")),
                         "codex-live-admission-refused")

    def test_private_manifest_rejects_duplicate_fields(self):
        with self.assertRaises(ValueError):
            live.unique_object([("model", "first"), ("model", "second")])

    def test_private_directory_bind_and_named_custody(self):
        with tempfile.TemporaryDirectory(dir=os.environ['TEST_TMPDIR']) as temporary:
            root = Path(temporary)
            repository = root / 'repository'
            repository.mkdir(mode=0o700)
            source = root / 'source'
            source.mkdir(mode=0o700)
            credential = source / 'auth.json'
            credential.write_bytes(b'nonsecret model input')
            credential.chmod(0o600)
            directory = root / 'inputs'
            directory.mkdir(mode=0o700)
            manifest = directory / 'input.json'
            manifest.write_text(json.dumps({'schema_version':1,'authorized_source_paths':[str(credential)]}))
            manifest.chmod(0o600)
            admission = live.Admission(manifest, repository, time.monotonic_ns()+60*10**9,
                                       ['test', live.ENROLLMENT_LABEL])
            try:
                self.assertEqual(admission.binding(), str(directory)+':/omux-live-inputs')
                self.assertFalse(admission.recheck()['sourceContentReadByGuard'])
                extra = directory / 'unexpected'
                extra.write_bytes(b'unrelated')
                with self.assertRaises(ValueError):
                    admission.recheck()
                extra.unlink()
                directory.rename(root / 'retired-inputs')
                directory.mkdir(mode=0o700)
                (directory/'input.json').write_text('{}')
                (directory/'input.json').chmod(0o600)
                with self.assertRaises(ValueError):
                    admission.recheck()
            finally:
                admission.close()

    def test_manifest_directory_refuses_shared_or_redirected_namespace(self):
        with tempfile.TemporaryDirectory(dir=os.environ['TEST_TMPDIR']) as temporary:
            directory=Path(temporary)/'inputs'
            directory.mkdir(mode=0o700)
            manifest=directory/'input.json'
            manifest.write_text('{}')
            manifest.chmod(0o600)
            descriptor=live.open_manifest_directory(manifest)
            os.close(descriptor)
            directory.chmod(0o755)
            with self.assertRaises(ValueError):
                live.open_manifest_directory(manifest)
            directory.chmod(0o700)
            redirect=Path(temporary)/'redirect'
            redirect.symlink_to(directory,target_is_directory=True)
            with self.assertRaises(OSError):
                live.open_manifest_directory(redirect/'input.json')

if __name__ == "__main__":
    unittest.main()
