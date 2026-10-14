"""Real N3 reconstruction/read helpers on bounded temporary source, never SDK IO."""
from contextlib import ExitStack, contextmanager
import copy
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import codex_live_source as source
import codex_owner_status_persistence_source as successor
import codex_owner_status_persistence_source_test as fixture
import codex_owner_status_persistence_binding as binding


class PersistenceBindingTests(unittest.TestCase):
    @contextmanager
    def isolated(self):
        # Parent origin and finite test pins are substituted. N1's independent
        # binding suite covers its ancestry; the real strict sixth transform,
        # exact receipt reconstruction, sealed full read and anchors run here.
        helper = fixture.PersistenceSourceTests()
        files, raw, preimages = helper.fixture()
        files["retained/link.rs"] = ("120000", b"../retained.rs")
        parent = {"patch_sha256": ["isolated-parent"], "patches": [],
            "graph_files": {name: {"sha256": source.sha(files[name][1])} for name in successor.history.GRAPH}}
        with tempfile.TemporaryDirectory() as temporary, ExitStack() as stack:
            stack.enter_context(helper.selected(raw, preimages))
            stack.enter_context(patch.object(source, "DEADLINE", None))
            stack.enter_context(patch.object(successor.parent, "load_verified_source", return_value=(parent, files)))
            stack.enter_context(patch.object(successor.status, "read_patch", return_value=raw))
            result = successor.transform(files, raw)
            document = successor.expected_receipt(parent, result)
            encoded = source.encoded(document)
            root = Path(temporary) / "owned-source"
            stack.enter_context(patch.multiple(binding, ROOT=root,
                RECEIPT_SHA=source.sha(encoded), RECEIPT_BYTES=len(encoded),
                INVENTORY_SHA=document["inventory_sha256"], SOURCE_MEMBERS=len(result),
                SOURCE_BYTES=sum(len(value) for _, value in result.values())))
            descriptor = source.write_source(root, result)
            os.close(descriptor)
            (root / "source-receipt.json").write_bytes(encoded)
            (root / "source-receipt.json").chmod(0o555)
            root.chmod(0o555)
            try:
                yield root, parent, files, raw, result, document
            finally:
                helper.cleanup(Path(temporary))

    def rewrite(self, root, document):
        path = root / "source-receipt.json"
        path.chmod(0o600)
        path.write_bytes(source.encoded(document))
        path.chmod(0o555)

    def test_exact_source_binding_is_distinct_and_all_qualifications_false(self):
        with self.isolated():
            report = binding.bind()
            self.assertEqual(report["kind"], "omux-owner-status-persistence-metadata-binding-v1")
            self.assertEqual(report["metadata_input"]["kind"], "omux-owner-status-persistence-metadata-input-v1")
            self.assertNotIn("export_root", report["metadata_input"])
            self.assertTrue(report["source_reconstructed_and_fully_read"])
            for field in ("sdk_materials_revalidated", "sdk_metadata_qualified", "schema_producer_qualified",
                "native_source_finalized", "native_compile_passed", "native_support", "provider_evaluation", "live_handoff_proven"):
                self.assertIs(report[field], False)

    def test_receipt_bytes_mode_symlink_and_root_mode_refuse(self):
        for change in ("byte", "mode", "symlink", "root-mode"):
            with self.subTest(change=change), self.isolated() as (root, *_):
                path = root / "source-receipt.json"
                if change == "byte":
                    path.chmod(0o600)
                    path.write_bytes(path.read_bytes() + b"\n")
                    path.chmod(0o555)
                elif change == "mode":
                    path.chmod(0o444)
                elif change == "root-mode":
                    root.chmod(0o700)
                else:
                    root.chmod(0o700)
                    path.rename(root / "original.json")
                    path.symlink_to("original.json")
                    root.chmod(0o555)
                with self.assertRaises((ValueError, OSError)):
                    binding.bind()

    def test_rehashed_receipt_lineage_inventory_graph_and_claim_drift_refuse(self):
        changes = (("kind", "omux-owner-status-source-v1"), ("source_inventory", {}),
            ("inventory_sha256", "0" * 64), ("patch_sha256", []), ("patches", []),
            ("persistence_preimages", {}), ("persistence_afterimages", {}), ("graph_files", {}),
            ("parent_source_root", "/different"), ("parent_source_receipt_sha256", "0" * 64),
            ("reviewed_native_patch_sha256", "0" * 64), ("normalized_native_patch_sha256", "0" * 64),
            ("sdk_metadata_qualified", True), ("native_support", True), ("native_source_finalized", True))
        for field, value in changes:
            with self.subTest(field=field), self.isolated() as (root, _, _, _, _, document):
                changed = copy.deepcopy(document)
                changed[field] = value
                self.rewrite(root, changed)
                encoded = source.encoded(changed)
                with patch.multiple(binding, RECEIPT_SHA=source.sha(encoded), RECEIPT_BYTES=len(encoded)), self.assertRaises(ValueError):
                    binding.bind()

    def test_inventory_counts_parent_preimage_and_each_patch_digest_refuse(self):
        for field in ("INVENTORY_SHA", "SOURCE_MEMBERS", "SOURCE_BYTES"):
            with self.subTest(field=field), self.isolated():
                with patch.object(binding, field, "0" * 64 if field.endswith("SHA") else 0), self.assertRaises(ValueError):
                    binding.bind()
        with self.isolated() as (_, parent, files, *_):
            changed = dict(files)
            changed[sorted(successor.ALLOWED)[0]] = ("100644", b"changed preimage\n")
            with patch.object(successor.parent, "load_verified_source", return_value=(parent, changed)), self.assertRaises(ValueError):
                binding.bind()
        for name in (successor.REVIEWED_NATIVE_NAME, successor.NORMALIZED_NATIVE_NAME, successor.PATCH_NAME):
            with self.subTest(name=name), self.isolated() as (_, _, _, raw, *_):
                with patch.object(successor.status, "read_patch", side_effect=lambda requested: raw + b"\n" if requested == name else raw), self.assertRaises(ValueError):
                    binding.bind()

    def test_source_byte_mode_missing_extra_and_symlink_drift_refuse(self):
        for change in ("byte", "mode", "missing", "extra", "symlink"):
            with self.subTest(change=change), self.isolated() as (root, *_):
                path = root / "source/retained.rs"
                if change == "byte":
                    path.chmod(0o600)
                    path.write_bytes(b"different native bytes\n")
                    path.chmod(0o555)
                elif change == "mode":
                    path.chmod(0o444)
                elif change == "symlink":
                    link = root / "source/retained/link.rs"
                    link.parent.chmod(0o700)
                    link.unlink()
                    link.symlink_to("../different.rs")
                    link.parent.chmod(0o555)
                else:
                    path.parent.chmod(0o700)
                    if change == "missing":
                        path.unlink()
                    else:
                        extra = path.parent / "extra.rs"
                        extra.write_bytes(b"extra\n")
                        extra.chmod(0o555)
                    path.parent.chmod(0o555)
                with self.assertRaises((ValueError, OSError)):
                    binding.bind()

    def test_changed_parent_readback_refuses(self):
        with self.isolated() as (_, parent, files, *_):
            with patch.object(successor.parent, "load_verified_source", side_effect=[(parent, files), ({**parent, "changed": True}, files)]), self.assertRaises(ValueError):
                binding.bind()

    def test_identical_named_root_replacement_refuses_held_anchor(self):
        with self.isolated() as (root, _, _, _, result, document):
            original = source.verify_written
            replaced = False
            def replace_after_read(path, files):
                nonlocal replaced
                original(path, files)
                if replaced:
                    return
                replaced = True
                root.rename(root.with_name("held-original"))
                descriptor = source.write_source(root, result)
                os.close(descriptor)
                (root / "source-receipt.json").write_bytes(source.encoded(document))
                (root / "source-receipt.json").chmod(0o555)
                root.chmod(0o555)
            with patch.object(source, "verify_written", side_effect=replace_after_read), self.assertRaises(ValueError):
                binding.bind()


if __name__ == "__main__":
    unittest.main()
