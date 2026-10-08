import base64
import hashlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from nar_descriptor import hash_descriptor
from native_flake_sources import ROLES, generate, locked_sources, validate_selection, verify


class NativeFlakeSourcesTest(unittest.TestCase):
    def fixture(self):
        lock = {"version": 7, "root": "project", "nodes": {
            "project": {"inputs": {"nixpkgs": "renamed-pkgs", "flake-utils": "renamed-utils"}},
            "renamed-utils": {"inputs": {"systems": "renamed-systems"}},
            "renamed-pkgs": {}, "renamed-systems": {}}}
        items, payloads = [], {}
        sources = {}
        for i, (role, node) in enumerate(zip(ROLES, ["renamed-pkgs", "renamed-utils", "renamed-systems"])):
            root = "/nix/store/" + "abc"[i] * 32 + "-source"
            sources[role] = root
            descriptor = {"schemaVersion": 1, "root": root, "nodes": [
                {"path": "", "type": "directory"},
                {"path": "data", "type": "regular", "size": 3, "executable": False},
                {"path": "inert", "type": "symlink", "target": "/never-open-target"}]}
            payload = bytes([ord("a") + i]) * 3
            hashed = hash_descriptor(descriptor, opener=lambda *_: io.BytesIO(payload))
            sri = "sha256-" + base64.b64encode(bytes.fromhex(hashed["narHash"][7:])).decode()
            lock["nodes"][node]["locked"] = {"narHash": sri, "rev": str(i + 1) * 40}
            label = "regular/" + str(i).zfill(8)
            payloads[label] = payload
            items.append({"role": role, "node": node, "revision": str(i + 1) * 40,
                          "narHash": hashed["narHash"], "descriptor": descriptor,
                          "regularInputs": {"data": label}})
        content = json.dumps(lock).encode()
        bundle = {"schemaVersion": 1, "kind": "locked-native-flake-source-descriptors",
                  "lockSha256": hashlib.sha256(content).hexdigest(), "sources": items}
        return content, bundle, payloads, sources

    def materialize(self, base, payloads):
        (base / "regular").mkdir()
        for label, payload in payloads.items():
            (base / label).write_bytes(payload)

    def test_all_three_declared_sources_and_inert_links(self):
        content, bundle, payloads, _ = self.fixture()
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            self.materialize(base, payloads)
            original = os.lstat
            def guard(path, *args, **kwargs):
                if str(path) == "/never-open-target":
                    self.fail("inert source link followed")
                return original(path, *args, **kwargs)
            with patch("os.lstat", guard):
                result = verify(content, json.dumps(bundle).encode(), base, [base])
            self.assertTrue(result["sourceNarVerified"])
            self.assertEqual(result["verifiedRegularInputs"], 3)
            self.assertFalse(result["buildSeedVerified"])
            self.assertFalse(result["executionAuthority"])
            self.assertFalse(result["linkTargetsFollowed"])

    def test_lock_roles_follow_edges_and_reject_indirection(self):
        content, _, _, _ = self.fixture()
        self.assertEqual(locked_sources(content)["systems"]["node"], "renamed-systems")
        lock = json.loads(content)
        lock["nodes"]["project"]["inputs"]["flake-utils"] = ["renamed-utils"]
        with self.assertRaises((ValueError, TypeError)):
            locked_sources(json.dumps(lock).encode())

    def test_exact_roles_and_labels_validated_before_any_bytes(self):
        content, bundle, _, _ = self.fixture()
        for mutation in ("missing", "duplicate", "extra-label", "shared-label"):
            changed = json.loads(json.dumps(bundle))
            if mutation == "missing":
                changed["sources"].pop()
            elif mutation == "duplicate":
                changed["sources"][1] = changed["sources"][0]
            elif mutation == "extra-label":
                changed["sources"][0]["regularInputs"]["inert"] = "regular/00000009"
            else:
                changed["sources"][1]["regularInputs"]["data"] = "regular/00000000"
            with patch("native_flake_sources.open_declared", side_effect=AssertionError("bytes opened")):
                with self.assertRaises(ValueError):
                    verify(content, json.dumps(changed).encode(), "/unused", ["/unused"])

    def test_self_consistent_metadata_cannot_change_locked_role(self):
        content, bundle, _, _ = self.fixture()
        bundle["sources"][0]["narHash"] = bundle["sources"][1]["narHash"]
        with patch("native_flake_sources.open_declared", side_effect=AssertionError("bytes opened")):
            with self.assertRaises(ValueError):
                verify(content, json.dumps(bundle).encode(), "/unused", ["/unused"])

    def test_same_size_changed_content_refused(self):
        content, bundle, payloads, _ = self.fixture()
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            self.materialize(base, payloads)
            (base / "regular/00000001").write_bytes(b"BAD")
            with self.assertRaisesRegex(ValueError, "nar-mismatch"):
                verify(content, json.dumps(bundle).encode(), base, [base])

    def test_undeclared_alias_refused_before_target_metadata(self):
        content, bundle, payloads, _ = self.fixture()
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            self.materialize(base, payloads)
            label = base / "regular/00000000"
            label.unlink()
            outside = base / "undeclared"
            label.symlink_to(outside)
            original = os.lstat
            def guard(path, *args, **kwargs):
                if Path(path) == outside:
                    self.fail("undeclared target metadata accessed")
                return original(path, *args, **kwargs)
            with patch("os.lstat", guard), self.assertRaisesRegex(ValueError, "undeclared-label-alias"):
                verify(content, json.dumps(bundle).encode(), base, [base])

    def test_original_deadline_not_reset_between_roles(self):
        content, bundle, _, _ = self.fixture()
        clock = [0]
        calls = []
        def first_role(descriptor, *, opener, deadline):
            calls.append(deadline)
            clock[0] = 601
            return {"narHash": bundle["sources"][0]["narHash"], "narSize": 320}
        with patch("native_flake_sources.time.monotonic", side_effect=lambda: clock[0]), \
                patch("native_flake_sources.hash_descriptor", side_effect=first_role):
            with self.assertRaisesRegex(ValueError, "deadline"):
                verify(content, json.dumps(bundle).encode(), "/unused", ["/unused"])
        self.assertEqual(calls, [600])

    def test_source_selection_is_exact_immutable_roots(self):
        _, _, _, sources = self.fixture()
        self.assertEqual(validate_selection(sources), sources)
        for value in ("/tmp/source", sources["nixpkgs"] + "/../source", "/nix/store/" + "0" * 32 + "-not-source-directory"):
            changed = dict(sources, systems=value)
            with self.assertRaises(ValueError):
                validate_selection(changed)
        with self.assertRaises(ValueError):
            validate_selection(dict(sources, systems=sources["nixpkgs"]))

    def test_generator_is_metadata_only_and_exports_all_regular_labels(self):
        content, bundle, _, sources = self.fixture()
        descriptions = {item["descriptor"]["root"]: item["descriptor"] for item in bundle["sources"]}
        with tempfile.TemporaryDirectory() as directory:
            with patch("native_flake_sources.os.lstat", return_value=os.stat(directory)), \
                    patch("native_flake_sources.describe", side_effect=lambda root: descriptions[root]), \
                    patch("native_flake_sources.hash_descriptor", side_effect=AssertionError("repository hashed bytes")):
                report = generate(content, sources, directory)
            self.assertEqual(len(report["regularInputs"]), 3)
            self.assertFalse(report["contentRehashed"])
            generated = json.loads((Path(directory) / "source-descriptors.json").read_text())
            self.assertEqual(generated, bundle)


if __name__ == "__main__":
    unittest.main()
