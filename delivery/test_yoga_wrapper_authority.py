"""Captured-byte boundaries only; no filesystem, registered store or execution proof."""
import copy
from dataclasses import FrozenInstanceError
import json
import unittest
from unittest.mock import patch

import yoga_wrapper_authority as authority


def root(letter, name):
    return "/nix/store/" + letter * 32 + "-" + name


class WrapperTests(unittest.TestCase):
    def setUp(self):
        self.roots = {name: root(letter, name) for name, letter in zip(
            ("python", "systemd", "bazel", "native", "bootstrap", "zig", "jdk", "bash", "dbus", "keyring", "native_manifest", "bootstrap_manifest"),
            "abcdfghijklm")}
        r = self.roots
        self.tools = {"python": r["python"] + "/bin/python3", "systemd_run": r["systemd"] + "/bin/systemd-run",
            "systemctl": r["systemd"] + "/bin/systemctl", "bazel": r["bazel"] + "/bin/bazel", "closure": r["native"],
            "bootstrap_closure": r["bootstrap"], "zig_sdk": r["zig"], "java_home": r["jdk"]}
        self.native = {"system": "x86_64-linux", "packages": {"bash": {"out": r["bash"]}, "python": {"out": r["python"]},
            "bazel_jdk": {"out": r["jdk"]}, "dbus": {"out": r["dbus"]}, "gnome_keyring": {"out": r["keyring"]}},
            "tools": {"systemctl": self.tools["systemctl"], "dbus_run_session": r["dbus"] + "/bin/dbus-run-session",
                      "dbus_daemon": r["dbus"] + "/bin/dbus-daemon", "gnome_keyring_daemon": r["keyring"] + "/bin/gnome-keyring-daemon"}}
        self.native_bytes = json.dumps(self.native, sort_keys=True, indent=2).encode() + b"\n"
        self.registered_bytes = authority.canonical(self.native)
        self.native_path = "/srv/yoga-proof/repository/native.json"
        self.paths, self.wrappers, facts = {}, {}, {}
        interpreter = r["bash"] + "/bin/bash"
        for role, (key, _) in authority.ROLES.items():
            self.paths[role] = "/srv/yoga-proof/repository/tool_wrappers/" + key
            backend = self.native["tools"][key]
            self.wrappers[role] = ('#!' + interpreter + '\nset -eu\nexec \'' + backend + '\' "$@"\n').encode()
            facts[role] = {"sha256": authority.digest(self.wrappers[role]), "backend": backend,
                "backendRoot": authority.store_root(backend), "interpreter": interpreter, "abi": "omux-native-capability-wrapper-v1"}
        self.shas = {role: fact["sha256"] for role, fact in facts.items()}
        roots = sorted({authority.store_root(value) for value in self.tools.values()} | {r["dbus"], r["keyring"]})
        rows = [{"path": path, "narHash": "sha256:" + "a" * 64, "narSize": 200,
                 "references": sorted([r["native_manifest"], r["bash"]]) if path == r["native"]
                 else [r["bootstrap_manifest"]] if path == r["bootstrap"] else []} for path in sorted(r.values())]
        self.inventory = {"schemaVersion": 1, "system": "x86_64-linux", "mode": "local-sqlite-readonly-snapshot",
            "roots": roots, "paths": rows, "contentRehashed": False, "realized": False, "published": False,
            "provenance": {"rootsSha256": authority.digest(authority.canonical(roots)), "inputSha256": {
                "selection": "1" * 64, "native_manifest": authority.digest(self.native_bytes), "bootstrap_manifest": "2" * 64,
                **{"wrapper/" + role: sha for role, sha in self.shas.items()}}}}
        self.companion = {"schemaVersion": 1, "scope": "yoga-controller-registry-and-wrapper-v1", "selectionSha256": "1" * 64,
            "inventorySha256": "", "controllerTools": copy.deepcopy(self.tools),
            "nativeManifest": {"sha256": authority.digest(self.native_bytes), "registeredObject": r["native_manifest"],
                               "registeredManifestSha256": authority.digest(self.registered_bytes)},
            "bootstrapManifest": {"sha256": "2" * 64, "registeredObject": r["bootstrap_manifest"], "registeredManifestSha256": "3" * 64},
            "wrappers": facts, "rootCount": len(roots), "registeredPaths": len(rows), "registeredNarBytes": 200 * len(rows),
            "deadlineMonotonicNs": 1, "registrySnapshotVerified": True, "selectedInputBytesVerified": True,
            **{field: False for field in authority.FALSE_FIELDS}}
        self.reseal()

    def reseal(self):
        self.inventory_bytes = authority.canonical(self.inventory) + b"\n"
        self.inventory_sha = authority.digest(self.inventory_bytes)
        self.companion["inventorySha256"] = self.inventory_sha
        self.companion_bytes = authority.canonical(self.companion) + b"\n"
        self.companion_sha = authority.digest(self.companion_bytes)

    def validate(self, **changes):
        arguments = dict(companion_sha256=self.companion_sha, native_manifest_bytes=self.native_bytes,
            native_manifest_sha256=authority.digest(self.native_bytes), registered_native_manifest_bytes=self.registered_bytes,
            inventory_bytes=self.inventory_bytes, inventory_sha256=self.inventory_sha, native_manifest_path=self.native_path,
            wrapper_paths=self.paths, wrapper_bytes=self.wrappers, wrapper_sha256=self.shas, controller_tools=self.tools,
            deadline_ns=1200 * 10**9, now=lambda: 10**9)
        arguments.update(changes)
        return authority.validate(self.companion_bytes, **arguments)

    def refuses(self, operation=None, reason=None):
        with self.assertRaises(authority.WrapperRefusal) as refused:
            (operation or self.validate)()
        if reason is not None:
            self.assertEqual(refused.exception.reason, reason)
        self.assertIn(refused.exception.reason, authority.REASONS)

    def test_exact_three_role_bindings_preserve_wrappers_and_do_no_io(self):
        with patch("builtins.open", side_effect=AssertionError("unexpected filesystem IO")):
            result = self.validate()
        self.assertEqual(len(result.bindings), 3)
        for binding in result.bindings:
            self.assertEqual(binding.path, self.paths[binding.role])
            self.assertNotEqual(binding.path, binding.backend)
            self.assertEqual(binding.sha256, self.shas[binding.role])
        self.assertEqual(result.registered_native_manifest_sha256, authority.digest(self.registered_bytes))
        self.assertNotEqual(result.native_manifest_sha256, result.registered_native_manifest_sha256)
        self.assertFalse(hasattr(result, "executionAuthority"))
        with self.assertRaises(FrozenInstanceError):
            result.bindings[0].backend = "/bin/false"

    def test_independent_hash_refusals_cover_all_captured_authorities(self):
        for field in ("companion_sha256", "native_manifest_sha256", "inventory_sha256"):
            with self.subTest(field=field):
                self.refuses(lambda: self.validate(**{field: "0" * 64}), "digest_mismatch")
        self.refuses(lambda: self.validate(registered_native_manifest_bytes=self.registered_bytes + b" "), "digest_mismatch")
        for role in authority.ROLES:
            with self.subTest(role=role):
                shas = dict(self.shas); shas[role] = "0" * 64
                self.refuses(lambda: self.validate(wrapper_sha256=shas), "digest_mismatch")

    def test_forged_companion_sha_claim_is_not_independent_selection(self):
        self.companion["wrappers"]["dbus_session"]["sha256"] = "0" * 64; self.reseal()
        self.refuses(reason="digest_mismatch")

    def test_extra_unknown_companion_manifest_or_role_fields_refuse(self):
        original = copy.deepcopy(self.companion)
        mutations = [lambda: self.companion.update(extra=True),
                     lambda: self.companion["nativeManifest"].update(extra=True),
                     lambda: self.companion["wrappers"]["dbus_session"].update(extra=True),
                     lambda: self.companion["wrappers"].update(python=copy.deepcopy(self.companion["wrappers"]["dbus_session"]))]
        for mutate in mutations:
            with self.subTest(mutation=mutations.index(mutate)):
                self.companion = copy.deepcopy(original); mutate(); self.reseal(); self.refuses(reason="schema_invalid")

    def test_authority_promoting_flags_and_boolean_counts_refuse(self):
        original = copy.deepcopy(self.companion)
        for field in sorted(authority.FALSE_FIELDS) + ["rootCount", "registeredPaths", "registeredNarBytes", "schemaVersion"]:
            with self.subTest(field=field):
                self.companion = copy.deepcopy(original); self.companion[field] = True; self.reseal(); self.refuses()

    def test_duplicate_keys_nonfinite_and_wrong_json_shapes_refuse(self):
        for data in (b'{"a":1,"a":2}', b'{"a":NaN}', b'[]', b'null', b'\xff'):
            with self.subTest(data=data):
                self.companion_bytes = data; self.companion_sha = authority.digest(data); self.refuses()

    def test_registered_native_object_requires_direct_edge_not_reachability_only(self):
        r = self.roots
        for row in self.inventory["paths"]:
            if row["path"] == r["native"]:
                row["references"].remove(r["native_manifest"])
            if row["path"] == r["bootstrap"]:
                row["references"].append(r["native_manifest"]); row["references"].sort()
        self.reseal(); self.refuses(reason="closure_mismatch")

    def test_bootstrap_registered_object_requires_direct_edge(self):
        r = self.roots
        for row in self.inventory["paths"]:
            if row["path"] == r["bootstrap"]:
                row["references"].clear()
            if row["path"] == r["native"]:
                row["references"].append(r["bootstrap_manifest"]); row["references"].sort()
        self.reseal(); self.refuses(reason="closure_mismatch")

    def test_registered_manifest_semantics_cannot_be_substituted(self):
        registered = copy.deepcopy(self.native); registered["tools"]["dbus_daemon"] += "-substitute"
        self.registered_bytes = authority.canonical(registered)
        self.companion["nativeManifest"]["registeredManifestSha256"] = authority.digest(self.registered_bytes)
        self.reseal(); self.refuses(reason="manifest_mismatch")

    def test_provenance_selection_manifest_and_wrapper_bindings_refuse(self):
        original = copy.deepcopy(self.inventory)
        for field in self.inventory["provenance"]["inputSha256"]:
            with self.subTest(field=field):
                self.inventory = copy.deepcopy(original)
                self.inventory["provenance"]["inputSha256"][field] = "0" * 64
                self.reseal(); self.refuses()

    def test_changed_wrapper_with_coherent_hashes_still_requires_exact_abi(self):
        role = "dbus_session"
        self.wrappers[role] += b"echo extra\n"
        self.shas[role] = authority.digest(self.wrappers[role])
        self.companion["wrappers"][role]["sha256"] = self.shas[role]
        self.inventory["provenance"]["inputSha256"]["wrapper/" + role] = self.shas[role]
        self.reseal(); self.refuses(reason="wrapper_mismatch")

    def test_source_nominated_backend_or_interpreter_cannot_replace_manifest(self):
        original = copy.deepcopy(self.companion)
        for field, value in (("backend", self.tools["python"]), ("backendRoot", self.roots["python"]),
                             ("interpreter", self.tools["python"]), ("abi", "python-wrapper-v1")):
            with self.subTest(field=field):
                self.companion = copy.deepcopy(original)
                self.companion["wrappers"]["dbus_session"][field] = value
                self.reseal(); self.refuses()

    def test_wrapper_roles_paths_backend_substitution_and_traversal_refuse(self):
        for role in authority.ROLES:
            for path in (self.native["tools"][authority.ROLES[role][0]], "/srv/another/tool_wrappers/" + authority.ROLES[role][0],
                         "/srv/yoga-proof/repository/../tool_wrappers/" + authority.ROLES[role][0], "/etc/" + role):
                with self.subTest(role=role, path=path):
                    paths = dict(self.paths); paths[role] = path; self.refuses(lambda: self.validate(wrapper_paths=paths))
        paths = dict(self.paths); paths["chromium"] = "/srv/chromium"
        self.refuses(lambda: self.validate(wrapper_paths=paths), "input_invalid")

    def test_unreachable_interpreter_cannot_be_added_as_authority_root(self):
        for row in self.inventory["paths"]:
            if row["path"] == self.roots["native"]:
                row["references"].remove(self.roots["bash"])
        self.inventory["roots"].append(self.roots["bash"]); self.inventory["roots"].sort()
        self.inventory["provenance"]["rootsSha256"] = authority.digest(authority.canonical(self.inventory["roots"]))
        self.companion["rootCount"] += 1
        self.reseal(); self.refuses(reason="closure_mismatch")

    def test_unrelated_duplicate_missing_and_unsorted_inventory_rows_refuse(self):
        original = copy.deepcopy(self.inventory)
        for kind in ("unrelated", "duplicate", "missing", "unsorted", "bad_hash"):
            with self.subTest(kind=kind):
                self.inventory = copy.deepcopy(original)
                if kind == "unrelated":
                    self.inventory["paths"].append({"path": root("n", "extra"), "narHash": "sha256:" + "a" * 64, "narSize": 1, "references": []})
                elif kind == "duplicate": self.inventory["paths"].append(copy.deepcopy(self.inventory["paths"][0]))
                elif kind == "missing": self.inventory["paths"] = [row for row in self.inventory["paths"] if row["path"] != self.roots["bash"]]
                elif kind == "unsorted": self.inventory["paths"].reverse()
                else: self.inventory["paths"][0]["narHash"] = "sha256:invalid"
                self.reseal(); self.refuses()

    def test_inventory_counts_and_controller_tools_cannot_be_source_nominated(self):
        tools = dict(self.tools); tools["python"] = self.roots["python"] + "/bin/python-substitute"
        self.refuses(lambda: self.validate(controller_tools=tools), "closure_mismatch")
        self.companion["registeredNarBytes"] += 1; self.reseal(); self.refuses(reason="inventory_invalid")

    def test_missing_manifest_package_and_wrong_system_refuse_without_raw_exception(self):
        for mutate in (lambda native: native["packages"].pop("bash"), lambda native: native.update(system="aarch64-linux")):
            native = copy.deepcopy(self.native); mutate(native)
            data = authority.canonical(native)
            companion = copy.deepcopy(self.companion)
            companion["nativeManifest"].update(sha256=authority.digest(data), registeredManifestSha256=authority.digest(data))
            self.companion = companion
            self.inventory["provenance"]["inputSha256"]["native_manifest"] = authority.digest(data)
            self.reseal(); self.refuses(lambda: self.validate(native_manifest_bytes=data, native_manifest_sha256=authority.digest(data), registered_native_manifest_bytes=data))

    def test_original_deadline_and_final_expiry_refuse(self):
        for value in (True, 0, 10**9, 1202 * 10**9):
            with self.subTest(value=value):
                self.refuses(lambda: self.validate(deadline_ns=value), "deadline_exceeded")
        completed = [0]
        binding = authority.WrapperBinding
        def now():
            return 10**9 if completed[0] < len(authority.ROLES) else 1200 * 10**9
        def captured(*arguments):
            value = binding(*arguments)
            completed[0] += 1
            return value
        with patch.object(authority, "WrapperBinding", side_effect=captured):
            self.refuses(lambda: self.validate(now=now), "deadline_exceeded")

    def test_byte_and_graph_bounds_refuse(self):
        self.refuses(lambda: self.validate(native_manifest_bytes=b"x" * (authority.MAX_MANIFEST + 1),
            native_manifest_sha256=authority.digest(b"x" * (authority.MAX_MANIFEST + 1))), "byte_bound")
        with patch.object(authority, "MAX_ROWS", 1): self.refuses()
        with patch.object(authority, "MAX_REFS", 1): self.refuses(reason="byte_bound")
        with patch.object(authority, "MAX_NAR_BYTES", 1): self.refuses(reason="byte_bound")


if __name__ == "__main__":
    unittest.main()
