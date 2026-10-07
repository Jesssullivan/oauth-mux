"""Modeled acquired-source contracts; no actual HM evaluation or acquisition."""
import base64
import hashlib
import json
import os
from pathlib import Path
import shutil
import tempfile
import time
import unittest
from unittest.mock import patch

import home_manager_acquired_inputs as acquired
import home_manager_inputs
import nar_descriptor
from nar_descriptor import describe, hash_descriptor


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def sha(value):
    return hashlib.sha256(value).hexdigest()


class AcquiredPairTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.base = Path(self.temporary.name).resolve()
        self.roots = {}
        self.pins = {}
        self.inventory = {"schemaVersion": 1, "sources": {}}
        self.lock = {"root": "root", "nodes": {"root": {"inputs": {
            "home-manager": "hm", "nixpkgs": "np"}}}}
        self.receipt = {"schemaVersion": 1, "kind": "omux-home-manager-acquired-pair", "sources": {}}
        for name, node in (("home-manager", "hm"), ("nixpkgs", "np")):
            root = self.base / name
            root.mkdir()
            (root / "lib").mkdir()
            (root / "default.nix").write_bytes(b"{ system }: { fixture = system; }\n")
            (root / "lib/helper.nix").write_bytes(name.encode() + b"\n")
            (root / "executable").write_bytes(b"synthetic executable metadata\n")
            (root / "executable").chmod(0o555)
            # This target is intentionally absent and never consulted.
            (root / "inert-link").symlink_to("/unavailable-modeled-external-target")
            descriptor = describe(root)
            nar = hash_descriptor(descriptor)
            sri = "sha256-" + base64.b64encode(bytes.fromhex(nar["narHash"][7:])).decode()
            revision = home_manager_inputs.PINS[name][0]
            self.pins[name] = (revision, sri)
            self.roots[name] = str(root)
            self.inventory["sources"][name] = {"nodes": descriptor["nodes"]}
            self.lock["nodes"][node] = {"locked": {"rev": revision, "narHash": sri}}
            owner, repository = acquired.REPOSITORIES[name]
            self.receipt["sources"][name] = {"revision": revision, "narHash": sri,
                "narSize": nar["narSize"],
                "url": f"https://github.com/{owner}/{repository}/archive/{revision}.tar.gz"}
            for path in (root / "default.nix", root / "lib/helper.nix"):
                path.chmod(0o444)
            (root / "lib").chmod(0o555)
            root.chmod(0o555)
        self.lock["nodes"]["hm"]["inputs"] = {"nixpkgs": ["nixpkgs"]}

    def tearDown(self):
        # Restore only our fixture directories; never resolve inert targets.
        for directory, _, _ in os.walk(self.base, followlinks=False):
            os.chmod(directory, 0o700)
        self.temporary.cleanup()

    def arguments(self):
        lock = encoded(self.lock)
        inventory = encoded(self.inventory)
        receipt = {**self.receipt, "lockSha256": sha(lock), "inventorySha256": sha(inventory)}
        receipt_bytes = encoded(receipt)
        return [lock, receipt_bytes, sha(receipt_bytes), inventory, dict(self.roots)]

    def verify(self, **kwargs):
        # Tiny fixture hashes substitute only inside these modeled tests. The
        # production function has no pin override or verifier injection option.
        with patch.dict(home_manager_inputs.PINS, self.pins, clear=True):
            return acquired.verify_acquired_pair(*self.arguments(), **kwargs)

    def test_complete_actual_byte_readback_is_not_evaluation_or_acquisition_authority(self):
        original = os.readlink
        def readlink(path, *args, **kwargs):
            self.assertNotEqual(path, "/unavailable-modeled-external-target")
            return original(path, *args, **kwargs)
        with patch("home_manager_acquired_inputs.os.readlink", side_effect=readlink):
            result = self.verify()
        self.assertTrue(result["contentRehashed"])
        self.assertTrue(result["completeInventoryMatched"])
        self.assertFalse(result["executionAuthority"])
        self.assertFalse(result["evaluationAuthority"])
        self.assertFalse(result["acquisitionActionsVerified"])
        self.assertFalse(result["linkTargetsFollowed"])
        self.assertEqual(result["activation"], "unproved")
        self.assertEqual(set(result["sources"]), set(acquired.NAMES))

    def test_repeated_scan_of_same_directory_descriptor_keeps_complete_inventory(self):
        deadline = time.monotonic() + 30
        root = acquired.open_root(self.roots["home-manager"], deadline)
        try:
            first = acquired.scan(root, deadline)
            second = acquired.scan(root, deadline)
        finally:
            os.close(root)
        self.assertGreater(len(first[0]), 1)
        self.assertEqual(first, second)
        self.assertEqual({node["path"] for node in first[0]},
                         {"", "default.nix", "lib", "lib/helper.nix",
                          "executable", "inert-link"})

    def test_nar_library_import_preserves_declared_logical_sibling_namespace(self):
        expected = Path(acquired.__file__).absolute().parent.parent / "tools"
        self.assertEqual(Path(nar_descriptor.__file__).absolute().parent, expected)
        self.assertIs(acquired.serialize, nar_descriptor.serialize)

    def test_nested_pending_names_reserve_global_entry_and_metadata_budgets(self):
        root = self.base / "fanout"
        directories = [root, root / "a", root / "b", root / "c",
                       root / "a/aa", root / "a/ab", root / "a/ac"]
        for directory in directories:
            directory.mkdir()
        for directory in directories:
            directory.chmod(0o555)
        deadline = time.monotonic() + 30
        descriptor = acquired.open_root(str(root), deadline)
        original = os.scandir
        calls = []
        def traced(directory):
            calls.append(os.fstat(directory).st_ino)
            return original(directory)
        try:
            with patch("home_manager_acquired_inputs.MAX_NODES", 6), \
                    patch("home_manager_acquired_inputs.os.scandir", side_effect=traced), \
                    self.assertRaisesRegex(ValueError, "acquired-tree-entry-bound"):
                acquired.scan(descriptor, deadline)
            # Root's b/c are still pending when collecting a's children. The
            # discovery budget must refuse before entering any aa/ab/ac subtree.
            self.assertEqual(len(calls), 2)
            calls.clear()
            with patch("home_manager_acquired_inputs.MAX_INVENTORY_BYTES", 650), \
                    patch("home_manager_acquired_inputs.os.scandir", side_effect=traced), \
                    self.assertRaisesRegex(ValueError, "acquired-tree-metadata-bound"):
                acquired.scan(descriptor, deadline)
            self.assertEqual(len(calls), 2)
        finally:
            os.close(descriptor)

    def test_synthetic_hashes_never_qualify_fixed_production_pins(self):
        with self.assertRaisesRegex(ValueError, "acquired-paired-lock-invalid"):
            acquired.verify_acquired_pair(*self.arguments())

    def test_receipt_and_inventory_bytes_need_their_independent_bindings(self):
        arguments = self.arguments()
        arguments[2] = "0" * 64
        with patch.dict(home_manager_inputs.PINS, self.pins, clear=True), self.assertRaisesRegex(ValueError, "acquired-receipt-binding"):
            acquired.verify_acquired_pair(*arguments)
        arguments = self.arguments()
        arguments[3] += b" "
        with patch.dict(home_manager_inputs.PINS, self.pins, clear=True), self.assertRaisesRegex(ValueError, "acquired-inventory-binding"):
            acquired.verify_acquired_pair(*arguments)

    def test_duplicate_metadata_and_follow_changes_are_refused(self):
        arguments = self.arguments()
        arguments[1] = b'{"schemaVersion":1,"schemaVersion":1}'
        arguments[2] = sha(arguments[1])
        with patch.dict(home_manager_inputs.PINS, self.pins, clear=True), self.assertRaisesRegex(ValueError, "acquired-duplicate-json-key"):
            acquired.verify_acquired_pair(*arguments)
        self.lock["nodes"]["hm"]["inputs"]["nixpkgs"] = ["another-source"]
        with self.assertRaisesRegex(ValueError, "acquired-paired-lock-invalid"):
            self.verify()

    def test_receipt_cannot_add_roots_or_substitute_archive_url(self):
        self.receipt["sources"]["home-manager"]["url"] = "https://invalid.example/unpinned.tar.gz"
        with self.assertRaisesRegex(ValueError, "acquired-source-lock-binding"):
            self.verify()
        del self.receipt["sources"]["home-manager"]["url"]
        self.receipt["sources"]["other-source"] = {}
        with self.assertRaisesRegex(ValueError, "acquired-metadata-fields"):
            self.verify()

    def test_same_sized_changed_bytes_cannot_pass_receipt_or_inventory_labels(self):
        file = Path(self.roots["home-manager"]) / "default.nix"
        original = file.read_bytes()
        file.chmod(0o644)
        file.write_bytes(b"x" * len(original))
        file.chmod(0o444)
        with self.assertRaisesRegex(ValueError, "acquired-source-nar-mismatch"):
            self.verify()

    def test_actual_extra_node_is_not_hidden_by_declared_inventory(self):
        root = Path(self.roots["home-manager"])
        root.chmod(0o755)
        (root / "extra").write_bytes(b"unlisted")
        (root / "extra").chmod(0o444)
        root.chmod(0o555)
        with self.assertRaisesRegex(ValueError, "acquired-complete-inventory-mismatch"):
            self.verify()

    def test_missing_node_and_executable_mode_changes_are_refused(self):
        root = Path(self.roots["home-manager"])
        executable = root / "executable"
        executable.chmod(0o444)
        with self.assertRaisesRegex(ValueError, "acquired-complete-inventory-mismatch"):
            self.verify()
        executable.chmod(0o555)
        root.chmod(0o755)
        executable.unlink()
        root.chmod(0o555)
        with self.assertRaisesRegex(ValueError, "acquired-complete-inventory-mismatch"):
            self.verify()

    def test_link_target_metadata_cannot_change_without_changing_proof(self):
        root = Path(self.roots["home-manager"])
        root.chmod(0o755)
        (root / "inert-link").unlink()
        (root / "inert-link").symlink_to("/different-unavailable-target")
        root.chmod(0o555)
        with self.assertRaisesRegex(ValueError, "acquired-complete-inventory-mismatch"):
            self.verify()

    def test_physical_root_alias_and_writable_tree_are_refused(self):
        alias = self.base / "alias"
        alias.symlink_to(self.roots["home-manager"], target_is_directory=True)
        self.roots["home-manager"] = str(alias)
        with self.assertRaises((OSError, ValueError)):
            self.verify()
        self.roots["home-manager"] = str(self.base / "home-manager")
        (self.base / "home-manager/lib").chmod(0o755)
        with self.assertRaisesRegex(ValueError, "acquired-tree-node-writable"):
            self.verify()

    def test_special_file_is_refused_without_blocking_read(self):
        root = Path(self.roots["home-manager"])
        root.chmod(0o755)
        os.mkfifo(root / "fifo", 0o444)
        root.chmod(0o555)
        with self.assertRaisesRegex(ValueError, "acquired-tree-special-file"):
            self.verify()

    def test_descriptor_parent_traversal_and_small_budgets_are_refused(self):
        self.inventory["sources"]["home-manager"]["nodes"].append({"path": "../escape", "type": "directory"})
        with self.assertRaisesRegex(ValueError, "acquired-invalid-nar-inventory"):
            self.verify()
        self.inventory["sources"]["home-manager"]["nodes"].pop()
        with patch("home_manager_acquired_inputs.MAX_NODES", 2), self.assertRaisesRegex(ValueError, "acquired-inventory-entry-bound"):
            self.verify()
        with self.assertRaisesRegex(ValueError, "acquired-deadline-bound"):
            self.verify(deadline_seconds=0)

    def test_identical_byte_rewrite_after_hash_does_not_erase_snapshot_race(self):
        original = acquired.serialize
        def changed(*args, **kwargs):
            result = original(*args, **kwargs)
            file = Path(self.roots["home-manager"]) / "default.nix"
            payload = file.read_bytes()
            file.chmod(0o644)
            file.write_bytes(payload)
            file.chmod(0o444)
            return result
        with patch("home_manager_acquired_inputs.serialize", side_effect=changed), self.assertRaisesRegex(ValueError, "acquired-tree-changed-during-hash"):
            self.verify()

    def test_selected_root_replacement_is_not_hidden_by_pinned_old_descriptor(self):
        original = acquired.serialize
        replaced = False
        def changed(*args, **kwargs):
            nonlocal replaced
            result = original(*args, **kwargs)
            if not replaced:
                root = Path(self.roots["home-manager"])
                backup = self.base / "old-root"
                root.rename(backup)
                shutil.copytree(backup, root, symlinks=True)
                replaced = True
            return result
        with patch("home_manager_acquired_inputs.serialize", side_effect=changed), self.assertRaisesRegex(ValueError, "acquired-(tree-changed-during-hash|selected-root-replaced)"):
            self.verify()

    def test_first_source_cannot_change_while_second_source_is_hashed(self):
        original = acquired.serialize
        calls = 0
        def changed(*args, **kwargs):
            nonlocal calls
            result = original(*args, **kwargs)
            calls += 1
            if calls == 2:
                file = Path(self.roots["home-manager"]) / "default.nix"
                payload = file.read_bytes()
                file.chmod(0o644)
                file.write_bytes(payload)
                file.chmod(0o444)
            return result
        with patch("home_manager_acquired_inputs.serialize", side_effect=changed), self.assertRaisesRegex(ValueError, "acquired-pair-changed-during-verification"):
            self.verify()


if __name__ == "__main__":
    unittest.main()
