"""Exact successor transformation units; isolated source is not native proof."""
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import codex_live_source as source
import codex_owner_status_persistence_source as successor


class PersistenceSourceTests(unittest.TestCase):
    def fixture(self):
        files = {name: ("100644", b"before-one\nbefore-two\n") for name in successor.ALLOWED}
        for name in successor.history.GRAPH:
            files[name] = ("100644", b"unchanged graph\n")
        files["retained.rs"] = ("100755", b"unchanged\n")
        raw = b"".join((f"diff --git a/{name} b/{name}\n--- a/{name}\n+++ b/{name}\n@@ -1,1 +1,2 @@\n-before-one\n+after-one\n+inserted\n@@ -2,1 +3,1 @@\n-before-two\n+after-two\n").encode()
            for name in sorted(successor.ALLOWED))
        preimages = {name: source.sha(files[name][1]) for name in successor.ALLOWED}
        return files, raw, preimages

    def selected(self, raw, preimages):
        return patch.multiple(successor, PATCH_SHA=source.sha(raw), PREIMAGES=preimages,
            AFTERIMAGES={name: source.sha(b"after-one\ninserted\nafter-two\n") for name in successor.ALLOWED},
            REVIEWED_NATIVE_SHA=source.sha(raw), NORMALIZED_NATIVE_SHA=source.sha(raw))

    def test_unique_file_cumulative_positions_produce_exact_scoped_bytes(self):
        files, raw, preimages = self.fixture()
        with self.selected(raw, preimages):
            result = successor.transform(files, raw)
        for name in successor.ALLOWED:
            self.assertEqual(result[name], ("100644", b"after-one\ninserted\nafter-two\n"))
        self.assertEqual(result["retained.rs"], files["retained.rs"])
        self.assertEqual(set(result), set(files))

    def test_digest_preimage_mode_and_missing_input_refuse(self):
        files, raw, preimages = self.fixture()
        name = sorted(successor.ALLOWED)[0]
        with self.selected(raw, preimages):
            with self.assertRaises(ValueError):
                successor.transform(files, raw + b"\n")
            for changed in (
                {**files, name: ("100644", b"different original\n")},
                {**files, name: ("100755", files[name][1])},
                {key: value for key, value in files.items() if key != name},
            ):
                with self.assertRaises(ValueError):
                    successor.transform(changed, raw)

    def test_rehashed_context_original_destination_and_overlap_drift_refuse(self):
        files, raw, preimages = self.fixture()
        for changed in (
            raw.replace(b"-before-one", b"-different", 1),
            raw.replace(b"@@ -1,1 +1,2 @@", b"@@ -2,1 +1,2 @@", 1),
            raw.replace(b"@@ -2,1 +3,1 @@", b"@@ -2,1 +2,1 @@", 1),
            raw.replace(b"@@ -2,1 +3,1 @@", b"@@ -1,1 +3,1 @@", 1),
        ):
            with self.selected(changed, preimages), self.assertRaises(ValueError):
                successor.transform(files, changed)

    def test_index_metadata_and_wrong_afterimage_pin_refuse(self):
        files, raw, preimages = self.fixture()
        first = raw.index(b"\n") + 1
        indexed = raw[:first] + b"index 0000000..1111111 100755\n" + raw[first:]
        with self.selected(indexed, preimages), self.assertRaises(ValueError):
            successor.transform(files, indexed)
        with self.selected(raw, preimages), patch.object(successor, "AFTERIMAGES", {name: "0" * 64 for name in successor.ALLOWED}), self.assertRaises(ValueError):
            successor.transform(files, raw)

    def test_repeated_file_section_unknown_path_and_incomplete_footprint_refuse(self):
        files, raw, preimages = self.fixture()
        name = sorted(successor.ALLOWED)[0]
        repeated = f"diff --git a/{name} b/{name}\n--- a/{name}\n+++ b/{name}\n@@ -1,1 +1,1 @@\n-before-one\n+another\n".encode()
        unknown = b"diff --git a/retained.rs b/retained.rs\n--- a/retained.rs\n+++ b/retained.rs\n@@ -1,1 +1,1 @@\n-unchanged\n+different\n"
        section = raw[:raw.index(b"diff --git ", 1)]
        for changed in (raw + repeated, raw + unknown, section):
            with self.selected(changed, preimages), self.assertRaises(ValueError):
                successor.transform(files, changed)

    def test_output_set_modes_graph_and_missing_scoped_change_refuse(self):
        files, raw, preimages = self.fixture()
        with self.selected(raw, preimages):
            result = successor.transform(files, raw)
        graph = successor.history.GRAPH[0]
        for changed in (
            {**result, "extra.rs": ("100644", b"extra\n")},
            {key: value for key, value in result.items() if key != "retained.rs"},
            {**result, "retained.rs": ("100644", files["retained.rs"][1])},
            {**result, graph: ("100644", b"changed graph\n")},
            {**result, sorted(successor.ALLOWED)[0]: files[sorted(successor.ALLOWED)[0]]},
        ):
            with self.assertRaises(ValueError):
                successor.validate_transition(files, changed)

    def cleanup(self, root):
        for folder, _, files in os.walk(root, followlinks=False):
            Path(folder).chmod(0o700)
            for name in files:
                path = Path(folder) / name
                if not path.is_symlink():
                    path.chmod(0o600)

    def test_sealed_output_receipt_has_fresh_inventory_and_no_native_qualifiers(self):
        files, raw, preimages = self.fixture()
        report = {"patch_sha256": ["isolated-parent"], "patches": [],
            "graph_files": {name: {"sha256": source.sha(files[name][1])} for name in successor.history.GRAPH}}
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            try:
                with self.selected(raw, preimages), patch.object(successor.parent, "load_verified_source", return_value=(report, files)), patch.object(successor.status, "read_patch", return_value=raw):
                    receipt = successor.produce(root / "successor", 60)
                self.assertEqual(receipt["inventory_sha256"], source.sha(source.canonical(receipt["source_inventory"])))
                self.assertEqual(receipt["graph_files"], report["graph_files"])
                for field in ("sdk_metadata_qualified", "schema_producer_qualified", "native_compile_passed", "native_support", "provider_evaluation", "live_handoff_proven"):
                    self.assertIs(receipt[field], False)
                with self.selected(raw, preimages):
                    source.verify_written(root / "successor/source", successor.transform(files, raw))
                self.assertEqual((root / "successor/source-receipt.json").stat().st_mode & 0o777, 0o444)
            finally:
                self.cleanup(root)

    def test_changed_parent_readback_prevents_receipt_publication(self):
        files, raw, preimages = self.fixture()
        report = {"patch_sha256": [], "patches": [], "graph_files": {}}
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            try:
                with self.selected(raw, preimages), patch.object(successor.parent, "load_verified_source", side_effect=[(report, files), ({**report, "changed": True}, files)]), patch.object(successor.status, "read_patch", return_value=raw), self.assertRaises(ValueError):
                    successor.produce(root / "successor", 60)
                self.assertFalse((root / "successor/source-receipt.json").exists())
            finally:
                self.cleanup(root)


if __name__ == "__main__":
    unittest.main()
