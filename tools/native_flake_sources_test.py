import base64
import hashlib
import io
import json
import os
from pathlib import Path
import tempfile
import time
import stat
import unittest
from unittest.mock import patch

from nar_descriptor import hash_descriptor
import nar_descriptor as nar
import native_flake_sources as source
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


    def test_metadata_wire_size_matches_actual_canonical_nar_without_payload_reads(self):
        descriptor = {"schemaVersion": 1, "root": "/logical", "nodes": [
            {"path": "", "type": "directory"},
            {"path": "sub", "type": "directory"},
            {"path": "inert", "type": "symlink", "target": "/never-open-target"},
            *[{"path": "sub/data"+str(size), "type": "regular", "size": size,
               "executable": size == 9} for size in (0, 1, 8, 9)]]}
        actual = hash_descriptor(descriptor,
            opener=lambda root, name: io.BytesIO(b"a"*int(name.removeprefix("sub/data"))))
        with patch.object(nar, "open_regular", side_effect=AssertionError("payload opened")):
            self.assertEqual(nar.serialized_size(descriptor, deadline=time.monotonic()+10),
                             actual["narSize"])
        oversized = {"schemaVersion": 1, "root": "/logical", "nodes": [
            {"path": "", "type": "regular", "size": nar.MAX_BYTES, "executable": False}]}
        with self.assertRaises(ValueError):
            nar.serialized_size(oversized, deadline=time.monotonic()+10)
        with self.assertRaises(ValueError):
            nar.serialized_size(descriptor, deadline=time.monotonic()-1)

    def test_fused_real_copy_matches_default_proof_and_exact_original_open_count(self):
        content, bundle, payloads, _ = self.fixture()
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            self.materialize(base, payloads)
            expected = verify(content, json.dumps(bundle).encode(), base, [base])
            copied = base/"copied"
            copied.mkdir()
            with patch.object(source, "open_declared", wraps=source.open_declared) as original, \
                 patch.object(source.os, "fsync", side_effect=AssertionError("disposable copy fsync")):
                actual = verify(content, json.dumps(bundle).encode(), base, [base],
                                copy_directory=copied)
            self.assertEqual(actual, expected)
            self.assertEqual(original.call_count, len(payloads))
            for item in bundle["sources"]:
                root = copied/item["role"]/"source"
                self.assertEqual((root/"data").read_bytes(), payloads[item["regularInputs"]["data"]])
                self.assertEqual(stat.S_IMODE(os.lstat(root/"data").st_mode), 0o444)
                self.assertEqual(os.readlink(root/"inert"), "/never-open-target")

    def test_fused_metadata_refusal_precedes_all_copy_and_payload_io(self):
        content, bundle, _, _ = self.fixture()
        bundle["sources"][1]["regularInputs"]["data"] = "regular/00000000"
        with tempfile.TemporaryDirectory() as directory:
            copied = Path(directory)
            with patch.object(source, "open_declared", side_effect=AssertionError("payload")), \
                 patch.object(source, "copy_skeleton", side_effect=AssertionError("copy")):
                with self.assertRaises(ValueError):
                    verify(content, json.dumps(bundle).encode(), "/unused", ["/unused"],
                           copy_directory=copied)
            self.assertEqual(list(copied.iterdir()), [])

    def test_fused_original_same_size_corruption_refuses_locked_nar(self):
        content, bundle, payloads, _ = self.fixture()
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            self.materialize(base, payloads)
            (base/"regular/00000000").write_bytes(b"BAD")
            copied = base/"copied"
            copied.mkdir()
            with self.assertRaisesRegex(ValueError, "native-source-nar-mismatch"):
                verify(content, json.dumps(bundle).encode(), base, [base], copy_directory=copied)

    def test_fused_copied_same_size_corruption_refuses_independent_readback(self):
        content, bundle, payloads, _ = self.fixture()
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            self.materialize(base, payloads)
            copied = base/"copied"
            copied.mkdir()
            describe = source.describe
            def changed(root):
                leaf = root/"data"
                os.chmod(leaf, 0o600)
                leaf.write_bytes(b"BAD")
                os.chmod(leaf, 0o444)
                return describe(root)
            with patch.object(source, "describe", side_effect=changed):
                with self.assertRaisesRegex(ValueError, "copy-nar-mismatch"):
                    verify(content, json.dumps(bundle).encode(), base, [base], copy_directory=copied)

    def test_fused_flush_failure_closes_actual_original_and_output_fds(self):
        class FailedFlush:
            def __init__(self, stream):
                self.stream = stream
            def __enter__(self):
                return self
            def __exit__(self, *args):
                self.stream.close()
            def write(self, data):
                return self.stream.write(data)
            def flush(self):
                raise OSError("modeled flush failure")
            def fileno(self):
                return self.stream.fileno()
        content, bundle, payloads, _ = self.fixture()
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            self.materialize(base, payloads)
            copied = base/"copied"
            copied.mkdir()
            opened, outputs = [], []
            opener, fdopen = source.open_declared, source.os.fdopen
            def original(*args):
                stream = opener(*args)
                opened.append(stream)
                return stream
            def output(fd, mode):
                stream = fdopen(fd, mode)
                if mode == "wb":
                    outputs.append(stream)
                    return FailedFlush(stream)
                return stream
            with patch.object(source, "open_declared", side_effect=original), \
                 patch.object(source.os, "fdopen", side_effect=output):
                with self.assertRaisesRegex(OSError, "flush failure"):
                    verify(content, json.dumps(bundle).encode(), base, [base], copy_directory=copied)
            self.assertTrue(opened and outputs)
            self.assertTrue(all(stream.closed for stream in opened+outputs))


    def test_fused_output_stream_construction_fault_closes_both_real_fds(self):
        content, bundle, payloads, _ = self.fixture()
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            self.materialize(base, payloads)
            copied = base/"copied"
            copied.mkdir()
            outputs, originals = [], []
            fdopen, opener = source.os.fdopen, source.open_declared
            def opened(*args):
                stream = opener(*args)
                originals.append(stream)
                return stream
            def failing(fd, mode):
                if mode == "wb":
                    outputs.append(fd)
                    raise OSError("modeled output constructor failure")
                return fdopen(fd, mode)
            with patch.object(source, "open_declared", side_effect=opened), \
                 patch.object(source.os, "fdopen", side_effect=failing):
                with self.assertRaisesRegex(OSError, "constructor failure"):
                    verify(content, json.dumps(bundle).encode(), base, [base], copy_directory=copied)
            self.assertTrue(outputs and originals)
            self.assertTrue(all(stream.closed for stream in originals))
            for fd in outputs:
                with self.assertRaises(OSError):
                    os.fstat(fd)


if __name__ == "__main__":
    unittest.main()
