"""Real binding helpers on isolated source-unit data; no N1 or SDK access."""
from contextlib import ExitStack, contextmanager
import copy
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import codex_live_source as source
import codex_live_source_test as parent_fixture
import codex_owner_status_binding as binding
import codex_owner_status_source as status


class OwnerStatusBindingTests(unittest.TestCase):
    @contextmanager
    def isolated(self):
        # Only source origin and test pins are substituted. Real fourth/fifth
        # transformations, receipt parser, sealed IO and anchored bind execute.
        with tempfile.TemporaryDirectory() as temporary, ExitStack() as stack:
            parent = parent_fixture.ProtocolHistorySourceTests().fixture()
            for name in status.ALLOWED:
                parent[name] = ("100644", ("before " + name + "\n").encode())
            parent["retained/link.rs"] = ("120000", b"source.rs")
            raw = b"".join((f"--- a/{name}\n+++ b/{name}\n@@ -1 +1 @@\n-before {name}\n+after {name}\n").encode()
                for name in sorted(status.ALLOWED))
            stack.enter_context(patch.multiple(status, PATCH_SHA=source.sha(raw),
                PREIMAGES={name: source.sha(parent[name][1]) for name in status.ALLOWED}))
            stack.enter_context(patch.object(source, "DEADLINE", None))
            fourth = binding.history.transform(parent, binding.history.PATCH_BYTES)
            fifth = status.transform(fourth, raw)
            root = Path(temporary) / "owned-source"
            stack.enter_context(patch.multiple(binding, ROOT=root,
                INVENTORY_SHA=source.sha(source.canonical(status.inventory(fifth))),
                FOURTH_INVENTORY_SHA=source.sha(source.canonical(status.inventory(fourth))),
                SOURCE_MEMBERS=len(fifth), SOURCE_BYTES=sum(len(value) for _, value in fifth.values())))
            parent_report = {"patches": [{"patch_sha256": pin, "paths": []} for pin in binding.history.PARENT_PATCHES]}
            document = binding.expected_receipt(parent_report, fourth, fifth)
            encoded = source.encoded(document)
            stack.enter_context(patch.multiple(binding, RECEIPT_SHA=source.sha(encoded), RECEIPT_BYTES=len(encoded)))
            stack.enter_context(patch.object(binding.history, "load_parent", return_value=(parent, parent_report)))
            def read_patch(name):
                return binding.history.PATCH_BYTES if name == binding.history.PATCH_NAME else raw
            stack.enter_context(patch.object(status, "read_patch", side_effect=read_patch))
            descriptor = source.write_source(root, fifth)
            os.close(descriptor)
            (root / "source-receipt.json").write_bytes(encoded)
            (root / "source-receipt.json").chmod(0o555)
            root.chmod(0o555)
            try:
                yield root, parent, parent_report, fourth, fifth, document, raw
            finally:
                # Only the owned temporary fixture is made removable.
                for folder, _, files in os.walk(temporary, followlinks=False):
                    Path(folder).chmod(0o700)
                    for name in files:
                        path = Path(folder) / name
                        if not path.is_symlink():
                            path.chmod(0o600)

    def replace_receipt(self, root, document):
        path = root / "source-receipt.json"
        path.chmod(0o600)
        path.write_bytes(source.encoded(document))
        path.chmod(0o555)

    def test_real_binding_emits_only_source_truth_with_all_sdk_native_qualifiers_false(self):
        with self.isolated():
            report = binding.bind()
            self.assertTrue(report["source_reconstructed_and_fully_read"])
            for name in ("sdk_materials_revalidated", "sdk_metadata_qualified", "schema_producer_qualified",
                "native_source_finalized", "native_compile_passed", "native_support", "provider_evaluation", "live_handoff_proven"):
                self.assertIs(report[name], False)

    def test_changed_receipt_bytes_modes_and_symlink_refuse(self):
        for change in ("byte", "mode", "symlink"):
            with self.subTest(change=change), self.isolated() as (root, *_):
                path = root / "source-receipt.json"
                if change == "byte":
                    path.chmod(0o600)
                    path.write_bytes(path.read_bytes() + b"\n")
                    path.chmod(0o555)
                elif change == "mode":
                    path.chmod(0o444)
                else:
                    root.chmod(0o700)
                    path.rename(root / "receipt-original.json")
                    path.symlink_to("receipt-original.json")
                    root.chmod(0o555)
                with self.assertRaises((ValueError, OSError)):
                    binding.load_actual()

    def test_rehashed_receipt_inventory_patch_and_false_claims_still_refuse_reconstruction(self):
        for field, value in (("inventory_sha256", "0" * 64), ("fourth_source_inventory_sha256", "0" * 64),
            ("source_inventory", {}), ("fourth_source_inventory", {}), ("graph_files", {}),
            ("patch_sha256", []), ("sdk_metadata_qualified", True), ("native_source_finalized", True), ("native_support", True)):
            with self.subTest(field=field), self.isolated() as (root, _, _, _, _, document, _):
                changed = copy.deepcopy(document)
                changed[field] = value
                self.replace_receipt(root, changed)
                encoded = source.encoded(changed)
                with patch.multiple(binding, RECEIPT_SHA=source.sha(encoded), RECEIPT_BYTES=len(encoded)), self.assertRaises(ValueError):
                    binding.bind()

    def test_actual_inventory_count_byte_and_reconstructed_preimage_refuse(self):
        for pin in ("INVENTORY_SHA", "FOURTH_INVENTORY_SHA", "SOURCE_MEMBERS", "SOURCE_BYTES"):
            with self.subTest(pin=pin), self.isolated() as (_, _, parent_report, fourth, fifth, _, _):
                value = "0" * 64 if pin.endswith("SHA") else 0
                with patch.object(binding, pin, value), self.assertRaises(ValueError):
                    binding.expected_receipt(parent_report, fourth, fifth)
        with self.isolated() as (_, parent, parent_report, *_):
            changed = dict(parent)
            name = sorted(status.ALLOWED)[0]
            changed[name] = ("100644", b"changed original\n")
            with patch.object(binding.history, "load_parent", return_value=(changed, parent_report)), self.assertRaises(ValueError):
                binding.bind()

    def test_changed_source_byte_mode_missing_extra_and_symlink_refuse_full_read(self):
        for change in ("byte", "mode", "missing", "extra", "symlink"):
            with self.subTest(change=change), self.isolated() as (root, *_):
                path = root / "source/retained/source.rs"
                if change == "byte":
                    path.chmod(0o600)
                    path.write_bytes(b"changed native bytes\n")
                    path.chmod(0o555)
                elif change == "mode":
                    path.chmod(0o444)
                else:
                    path.parent.chmod(0o700)
                    if change == "missing":
                        path.unlink()
                    elif change == "extra":
                        (path.parent / "extra.rs").write_bytes(b"extra\n")
                        (path.parent / "extra.rs").chmod(0o555)
                    else:
                        link = path.parent / "link.rs"
                        link.unlink()
                        link.symlink_to("different.rs")
                    path.parent.chmod(0o555)
                with self.assertRaises((ValueError, OSError)):
                    binding.bind()

    def test_named_root_replacement_after_full_read_refuses_original_anchor(self):
        with self.isolated() as (root, _, _, _, fifth, document, _):
            original = source.verify_written
            replaced = False
            def replace_after_read(path, files):
                nonlocal replaced
                original(path, files)
                if replaced:
                    return
                replaced = True
                old = root.with_name("original-held-source")
                root.rename(old)
                descriptor = source.write_source(root, fifth)
                os.close(descriptor)
                (root / "source-receipt.json").write_bytes(source.encoded(document))
                (root / "source-receipt.json").chmod(0o555)
                root.chmod(0o555)
            with patch.object(source, "verify_written", side_effect=replace_after_read), self.assertRaises(ValueError):
                binding.bind()


if __name__ == "__main__":
    unittest.main()
