"""Four exact public N3 preimages plus one redacted fixture; no real N3 proof."""
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import codex_live_source as source
import codex_native_source_context_source as successor


class NativeContextSourceTests(unittest.TestCase):
    def setUp(self):
        # Fixture-only common.rs redaction. Production pins remain exact N3.
        common = "codex-rs/app-server-protocol/src/protocol/common.rs"
        scope = patch.multiple(successor,
            PREIMAGES={**successor.PREIMAGES, common: "5b716840ca97f0ce0f25aa14bbb9ba8c3956d05245b393c2e4e112030606cea9"},
            AFTERIMAGES={**successor.AFTERIMAGES, common: "4c14f5b2799ff656be5a5c8e7e0a2732b2231252e037052e65f1f2c16a847fef"})
        scope.start()
        self.addCleanup(scope.stop)

    def fixture(self):
        root = successor.ROOT / "integrations/codex-upstream/source-context-preimages"
        files = {name: ("100644", (root / name).read_bytes()) for name in successor.PREIMAGES}
        for name in successor.history.GRAPH:
            files[name] = ("100644", b"isolated unchanged graph\n")
        files["codex-rs/retained-fixture"] = ("100755", b"retained executable\n")
        files["codex-rs/retained-link"] = ("120000", b"retained-fixture")
        return files, successor.read_patch()

    def report(self):
        report = {"patch_sha256": successor.PARENT_PATCHES,
            "patches": [{"paths": [], "patch_sha256": pin} for pin in successor.PARENT_PATCHES],
            "kind": successor.parent.successor.KIND, "commit": source.COMMIT,
            "inventory_sha256": successor.parent.INVENTORY_SHA, "graph_files": {"fixture": "unchanged"}}
        for key in ("sdk_metadata_qualified", "schema_producer_qualified", "native_compile_passed",
                "native_support", "provider_evaluation", "live_handoff_proven"):
            report[key] = False
        return report

    def cleanup(self, root):
        for folder, _, names in os.walk(root, followlinks=False):
            Path(folder).chmod(0o700)
            for name in names:
                path = Path(folder) / name
                if not path.is_symlink():
                    path.chmod(0o600)

    def selected(self, raw):
        # Only structural negative tests repin the artifact, never production.
        return patch.multiple(successor, PATCH_SHA=source.sha(raw), PATCH_BYTES=len(raw))

    def test_four_exact_one_redacted_preimage_two_new_members_and_retained_inventory(self):
        files, raw = self.fixture()
        result = successor.transform(files, raw)
        self.assertEqual(set(result), set(files) | successor.ADDED)
        self.assertEqual(len(successor.ADDED), 2)
        for name, pin in successor.AFTERIMAGES.items():
            self.assertEqual(source.sha(result[name][1]), pin)
            self.assertEqual(result[name][0], "100644")
        for name in set(files) - set(successor.PREIMAGES):
            self.assertEqual(result[name], files[name])

    def test_wrong_preimage_mode_missing_input_or_existing_added_path_refuses(self):
        files, raw = self.fixture()
        name = sorted(successor.PREIMAGES)[0]
        variants = [dict(files), dict(files), dict(files), dict(files)]
        variants[0][name] = ("100644", files[name][1] + b"drift")
        variants[1][name] = ("100755", files[name][1])
        variants[2].pop(name)
        variants[3][sorted(successor.ADDED)[0]] = ("100644", b"already exists\n")
        for changed in variants:
            with self.subTest(changed=source.sha(source.canonical(successor.status.inventory(changed)))), self.assertRaises(ValueError):
                successor.transform(changed, raw)

    def test_digest_length_and_maximum_bound_refuse(self):
        files, raw = self.fixture()
        for changed in (raw + b"\n", raw[:-1], b"x" * (source.MAX_PATCH + 1)):
            with self.assertRaises(ValueError):
                successor.transform(files, changed)
        with self.selected(b"x" * (source.MAX_PATCH + 1)), self.assertRaises(ValueError):
            successor.frame_patch(b"x" * (source.MAX_PATCH + 1))

    def test_rehashed_duplicate_unknown_newfile_header_and_context_refuse(self):
        files, raw = self.fixture()
        first_end = raw.index(b"diff --git ", 1)
        added = sorted(successor.ADDED)[0].encode()
        marker = b"diff --git a/" + added + b" b/" + added + b"\nnew file mode 100644\n"
        variants = (raw + raw[:first_end],
            raw.replace(b"a/codex-rs/app-server/src/lib.rs", b"a/codex-rs/unknown.rs", 1),
            raw.replace(marker, marker.replace(b"100644", b"100755"), 1),
            raw.replace(b"--- /dev/null\n", b"--- a/" + added + b"\n", 1),
            raw.replace(b" mod owner_control;", b" mod wrong_context;", 1))
        for changed in variants:
            self.assertNotEqual(changed, raw)
            with self.selected(changed), self.assertRaises(ValueError):
                successor.transform(files, changed)

    def test_rehashed_hunk_position_and_wrong_afterimage_refuse(self):
        files, raw = self.fixture()
        start = raw.index(b"@@ -")
        end = raw.index(b"\n", start)
        header = raw[start:end]
        changed = raw[:start] + header.replace(b"+", b"+999", 1) + raw[end:]
        with self.selected(changed), self.assertRaises(ValueError):
            successor.transform(files, changed)
        bad = dict(successor.AFTERIMAGES)
        bad[sorted(bad)[0]] = "0" * 64
        with patch.object(successor, "AFTERIMAGES", bad), self.assertRaises(ValueError):
            successor.transform(files, raw)

    def test_inventory_modes_graph_and_unrelated_bytes_preserved(self):
        files, raw = self.fixture()
        result = successor.transform(files, raw)
        for changed in (
            {**result, "codex-rs/extra": ("100644", b"extra")},
            {name: value for name, value in result.items() if name not in successor.ADDED},
            {**result, "codex-rs/retained-fixture": ("100644", b"retained executable\n")},
            {**result, successor.history.GRAPH[0]: ("100644", b"changed graph")},
            {**result, "codex-rs/retained-link": ("120000", b"different-link")},
        ):
            with self.assertRaises(ValueError):
                successor.validate_transition(files, changed)

    def test_sealed_output_full_readback_and_false_qualification_fields(self):
        files, raw = self.fixture()
        report = self.report()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            try:
                with patch.object(successor.parent, "load_verified_source", return_value=(report, files)):
                    receipt = successor.produce(root / "successor", 60)
                result = successor.transform(files, raw)
                source.verify_written(root / "successor/source", result)
                self.assertEqual(receipt["source_inventory"], successor.status.inventory(result))
                self.assertEqual(receipt["tracked_files"], len(files) + 2)
                self.assertEqual(receipt["patch_sha256"], report["patch_sha256"] + [successor.PATCH_SHA])
                self.assertEqual((root / "successor/source-receipt.json").read_bytes(), source.encoded(receipt))
                self.assertEqual((root / "successor/source-receipt.json").stat().st_mode & 0o777, 0o444)
                for name in ("context_rotation_implemented", "daemon_context_acquisition_implemented",
                    "native_source_finalized", "sdk_metadata_qualified", "schema_producer_qualified",
                    "native_compile_passed", "native_support", "provider_evaluation", "live_handoff_proven"):
                    self.assertIs(receipt[name], False)
            finally:
                self.cleanup(root)
        self.assertIsNone(source.DEADLINE)

    def test_wrong_parent_lineage_flags_inventory_and_readback_refuse(self):
        files, _ = self.fixture()
        report = self.report()
        for wrong in ({**report, "patch_sha256": []}, {**report, "inventory_sha256": "0" * 64},
                {**report, "native_compile_passed": True}, {**report, "commit": "0" * 40},
                {**report, "kind": "old-fourth-source-alias"}):
            with tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                try:
                    with patch.object(successor.parent, "load_verified_source", return_value=(wrong, files)), self.assertRaises(ValueError):
                        successor.produce(root / "successor", 60)
                    self.assertFalse((root / "successor/source-receipt.json").exists())
                finally:
                    self.cleanup(root)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            try:
                with patch.object(successor.parent, "load_verified_source", side_effect=[(report, files), ({**report, "drift": True}, files)]), self.assertRaises(ValueError):
                    successor.produce(root / "successor", 60)
                self.assertFalse((root / "successor/source-receipt.json").exists())
            finally:
                self.cleanup(root)
        self.assertIsNone(source.DEADLINE)


if __name__ == "__main__":
    unittest.main()
