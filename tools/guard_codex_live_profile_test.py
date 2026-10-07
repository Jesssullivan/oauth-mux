"""Exact live admission cannot broaden ordinary/offline execution."""
import json
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

if __name__ == "__main__":
    unittest.main()
