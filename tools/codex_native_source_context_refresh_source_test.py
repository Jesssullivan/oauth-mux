"""Exact three public refresh preimages; address-free fixture lineage only."""
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import codex_native_source_context_refresh_source as successor

source = successor.source


class RefreshSourceTests(unittest.TestCase):
    def fixture(self):
        root = successor.ROOT / "integrations/codex-upstream/refresh-preimages"
        files = {name: ("100644", (root / name).read_bytes()) for name in successor.PREIMAGES}
        for name in successor.seventh.history.GRAPH: files[name] = ("100644", b"isolated unchanged graph\n")
        files["codex-rs/fixture-executable"] = ("100755", b"inert fixture\n")
        files["codex-rs/fixture-link"] = ("120000", b"fixture-executable")
        inventory = successor.seventh.status.inventory(files)
        report = {"kind": successor.seventh.KIND, "status": "verified-seventh-native-context-source-uncompiled",
            "commit": source.COMMIT, "patch_sha256": successor.seventh.PARENT_PATCHES + [successor.seventh.PATCH_SHA],
            "source_inventory": inventory, "inventory_sha256": source.sha(source.canonical(inventory)),
            "tracked_files": len(files), "source_bytes": sum(len(v) for _, v in files.values()), "graph_files": {"fixture": "unchanged"},
            "context_rotation_implemented": False, **{name: False for name in successor.FLAGS}}
        report["patches"] = [{"patch_sha256": pin, "paths": []} for pin in report["patch_sha256"]]
        return files, report, successor.read_patch()

    def config(self, root, files, report):
        return {"schema_version": 1, "status": "actual-seventh-source-pinned", "root": str(root),
            "receipt_sha256": source.sha(source.encoded(report)), "receipt_bytes": len(source.encoded(report)),
            "inventory_sha256": report["inventory_sha256"], "source_members": len(files), "source_bytes": report["source_bytes"]}

    def sealed_parent(self, root, files, report):
        fd = source.write_source(root, files)
        os.close(fd)
        (root / "source-receipt.json").write_bytes(source.encoded(report))
        (root / "source-receipt.json").chmod(0o555)
        root.chmod(0o555)

    def cleanup(self, root):
        for folder, _, names in os.walk(root, followlinks=False):
            Path(folder).chmod(0o700)
            for name in names:
                path = Path(folder) / name
                if not path.is_symlink(): path.chmod(0o600)

    def selected(self, raw):
        return patch.multiple(successor, PATCH_SHA=source.sha(raw), PATCH_BYTES=len(raw))

    def test_unconfigured_input_refuses_before_any_parent_or_host_inventory(self):
        # An actual production binding must not change this negative model.
        # Feed explicit pending bytes through the real JSON/input validator.
        pending = b'{"schema_version":1,"status":"awaiting-actual-seventh-receipt","root":null,"receipt_sha256":null,"receipt_bytes":null,"inventory_sha256":null,"source_members":null,"source_bytes":null}\n'
        def declared(relative, maximum):
            self.assertEqual(relative, successor.INPUT)
            self.assertEqual(maximum, 8192)
            return pending
        with patch.object(successor, "declared", side_effect=declared), patch.object(successor, "load_seventh", side_effect=AssertionError("no parent read")):
            with tempfile.TemporaryDirectory() as temporary, self.assertRaises(ValueError):
                successor.produce(Path(temporary) / "output", 60)
        self.assertIsNone(source.DEADLINE)

    def test_exact_three_preimages_full_retained_inventory_and_afterimages(self):
        files, _, raw = self.fixture()
        result = successor.transform(files, raw)
        self.assertEqual(set(result), set(files))
        for name, pin in successor.AFTERIMAGES.items(): self.assertEqual(source.sha(result[name][1]), pin)
        for name in set(files) - set(successor.PREIMAGES): self.assertEqual(files[name], result[name])

    def test_rehashed_duplicate_context_position_mode_and_afterimage_refuse(self):
        files, _, raw = self.fixture()
        first_end = raw.index(b"diff --git ", 1)
        start = raw.index(b"@@ -"); end = raw.index(b"\n", start)
        changed_position = raw[:start] + raw[start:end].replace(b"+", b"+999", 1) + raw[end:]
        variants = (raw + raw[:first_end], changed_position,
            raw.replace(b"-struct SourceDeclaration", b"-struct WrongDeclaration", 1),
            raw.replace(b"--- a/codex-rs", b"index 123..456 100644\n--- a/codex-rs", 1))
        for changed in variants:
            self.assertNotEqual(raw, changed)
            with self.selected(changed), self.assertRaises(ValueError): successor.transform(files, changed)
        bad = dict(files); name = sorted(successor.PREIMAGES)[0]
        bad[name] = ("100755", bad[name][1])
        with self.assertRaises(ValueError): successor.transform(bad, raw)
        with patch.object(successor, "AFTERIMAGES", {**successor.AFTERIMAGES, name: "0" * 64}), self.assertRaises(ValueError): successor.transform(files, raw)

    def test_parent_lineage_modes_flags_and_unrelated_mutation_refuse(self):
        files, report, raw = self.fixture()
        config = self.config(Path("/synthetic-parent"), files, report)
        for bad in ({**report, "patch_sha256": []}, {**report, "kind": "old-source-alias"},
            {**report, "native_compile_passed": True}, {**report, "context_rotation_implemented": True},
            {**report, "tracked_files": len(files) + 1}, {**report, "source_inventory": {}}, {**report, "commit": "0" * 40}):
            with self.assertRaises(ValueError): successor.validate_parent(bad, files, config)
        result = successor.transform(files, raw)
        for bad in ({**result, "codex-rs/extra": ("100644", b"extra")},
            {**result, "codex-rs/fixture-link": ("120000", b"other")},
            {**result, successor.seventh.history.GRAPH[0]: ("100644", b"changed graph")}):
            with self.assertRaises(ValueError): successor.validate_transition(files, bad)

    def test_real_sealed_fixture_readback_and_producer_all_unqualified(self):
        files, report, raw = self.fixture()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            try:
                origin = root / "seventh"; self.sealed_parent(origin, files, report)
                config = self.config(origin, files, report)
                # Only fixture lineage reconstruction is substituted. Actual
                # descriptor/mode/tree/receipt/readback and patch code execute.
                with patch.object(successor, "reconstruct_seventh", return_value=(report, files)), patch.object(successor, "load_input", return_value=config):
                    receipt = successor.produce(root / "eighth", 60)
                self.assertEqual(receipt["patch_sha256"], report["patch_sha256"] + [successor.PATCH_SHA])
                source.verify_written(root / "eighth/source", successor.transform(files, raw))
                self.assertEqual((root / "eighth/source-receipt.json").read_bytes(), source.encoded(receipt))
                self.assertEqual((root / "eighth/source-receipt.json").stat().st_mode & 0o777, 0o444)
                for name in successor.FLAGS + ("context_rotation_runtime_qualified", "finite_kernel_shutdown_proven"):
                    self.assertIs(receipt[name], False)
            finally: self.cleanup(root)
        self.assertIsNone(source.DEADLINE)

    def test_changed_physical_parent_or_second_reconstruction_refuses_terminal_receipt(self):
        files, report, _ = self.fixture()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            try:
                origin = root / "seventh"; self.sealed_parent(origin, files, report)
                config = self.config(origin, files, report)
                victim = origin / "source/codex-rs/fixture-executable"
                victim.chmod(0o600); victim.write_bytes(b"drift"); victim.chmod(0o555)
                with patch.object(successor, "reconstruct_seventh", return_value=(report, files)), patch.object(successor, "load_input", return_value=config), self.assertRaises(ValueError):
                    successor.produce(root / "eighth", 60)
                self.assertFalse((root / "eighth/source-receipt.json").exists())
            finally: self.cleanup(root)
        self.assertIsNone(source.DEADLINE)

    def test_terminal_parent_reconstruction_or_input_fence_refuses_receipt(self):
        files, report, _ = self.fixture()
        for drift_parent in (False, True):
            with tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                try:
                    origin = root / "seventh"; self.sealed_parent(origin, files, report)
                    config = self.config(origin, files, report)
                    stages = [(report, files), (report, files), ({**report, "kind": "drift"}, files)] if drift_parent else [(report, files)] * 4
                    inputs = [config, config] if drift_parent else [config, {**config, "receipt_sha256": "0" * 64}]
                    with patch.object(successor, "reconstruct_seventh", side_effect=stages), patch.object(successor, "load_input", side_effect=inputs), self.assertRaises(ValueError):
                        successor.produce(root / "eighth", 60)
                    self.assertFalse((root / "eighth/source-receipt.json").exists())
                finally: self.cleanup(root)
        self.assertIsNone(source.DEADLINE)

    def test_expired_original_source_clock_refuses_before_parent_read(self):
        files, report, _ = self.fixture()
        config = self.config(Path("/synthetic-parent"), files, report)
        def expire():
            source.DEADLINE = successor.time.monotonic() - 1
            return config
        with tempfile.TemporaryDirectory() as temporary, patch.object(successor, "load_input", side_effect=expire), self.assertRaises(ValueError):
            successor.produce(Path(temporary) / "eighth", 60)
        self.assertIsNone(source.DEADLINE)


if __name__ == "__main__": unittest.main()
