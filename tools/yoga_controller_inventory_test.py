"""Actual SQLite/private-file boundaries with modeled immutable store objects.

No Nix executable, backend, daemon, store write, browser or network runs. The
temporary metadata anchor replaces only physical /srv custody, and synthetic
store witnesses/manifest readers represent immutable data, not a live proof.
"""
import copy
from contextlib import closing
import json
import os
from pathlib import Path
import sqlite3
import stat
import tempfile
import time
import unittest
from unittest.mock import patch

import yoga_controller_inventory as producer
from cached_nix_inventory import snapshot_inventory


def root(letter, name):
    return "/nix/store/" + letter * 32 + "-" + name


class InventoryTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.directory.chmod(0o700)
        self.native_path = self.directory / "native.json"
        self.bootstrap_path = self.directory / "bootstrap.json"
        self.picked = self.directory / "selection.json"
        self.output = self.directory / "evidence"
        self.deadline = time.monotonic_ns() + 900 * 10**9
        self.roots = {name: root(letter, name) for name, letter in
                      (("python", "a"), ("systemd", "b"), ("bazel", "c"), ("native", "d"),
                       ("bootstrap", "e"), ("zig", "f"), ("jdk", "g"), ("bash", "h"),
                       ("dbus", "i"), ("keyring", "j"), ("native_manifest", "k"), ("bootstrap_manifest", "l"))}
        r = self.roots
        tools = {"python": r["python"] + "/bin/python3", "systemd_run": r["systemd"] + "/bin/systemd-run",
                 "systemctl": r["systemd"] + "/bin/systemctl", "bazel": r["bazel"] + "/bin/bazel",
                 "closure": r["native"], "bootstrap_closure": r["bootstrap"], "zig_sdk": r["zig"], "java_home": r["jdk"]}
        self.native = {"system": "x86_64-linux", "packages": {"bash": {"out": r["bash"]}, "bazel_jdk": {"out": r["jdk"]},
                       "dbus": {"out": r["dbus"]}, "gnome_keyring": {"out": r["keyring"]}},
                       "tools": {"systemctl": tools["systemctl"], "dbus_run_session": r["dbus"] + "/bin/dbus-run-session",
                                 "dbus_daemon": r["dbus"] + "/bin/dbus-daemon", "gnome_keyring_daemon": r["keyring"] + "/bin/gnome-keyring-daemon"}}
        self.bootstrap = {"system": "x86_64-linux", "packages": {"python": {"out": r["python"]}}, "tools": {}}
        self.native_path.write_bytes(producer.canonical(self.native)); self.bootstrap_path.write_bytes(producer.canonical(self.bootstrap))
        self.wrapper_paths = {}
        wrappers = self.directory / "tool_wrappers"; wrappers.mkdir(mode=0o700)
        for name, (key, _) in producer.WRAPPERS.items():
            path = wrappers / key
            path.write_bytes(('#!' + r["bash"] + '/bin/bash\nset -eu\nexec \'' + self.native["tools"][key] + '\' "$@"\n').encode())
            path.chmod(0o555); self.wrapper_paths[name] = str(path)
        self.selection = {"schemaVersion": 1, "scope": "yoga-controller-inventory-selection-v1", "controllerTools": tools,
                          "nativeManifestSha256": producer.digest(self.native_path.read_bytes()),
                          "bootstrapManifestSha256": producer.digest(self.bootstrap_path.read_bytes()),
                          "wrapperSha256": {name: producer.digest(Path(path).read_bytes()) for name, path in self.wrapper_paths.items()}}
        self.write_selection()
        self.database = self.directory / "registry.sqlite"
        with closing(sqlite3.connect(self.database)) as connection, connection:
            connection.execute("CREATE TABLE ValidPaths(id INTEGER PRIMARY KEY,path TEXT,hash TEXT,narSize INTEGER)")
            connection.execute("CREATE TABLE Refs(referrer INTEGER,reference INTEGER)")
            for index, path in enumerate(sorted(r.values()), 1):
                connection.execute("INSERT INTO ValidPaths VALUES(?,?,?,?)", (index, path, "sha256:" + "a" * 64, 200))
            references = {r["native"]: [r[key] for key in ("native_manifest", "python", "systemd", "jdk", "bash", "dbus", "keyring")],
                          r["bootstrap"]: [r[key] for key in ("bootstrap_manifest", "python", "bash")], r["bazel"]: [r["jdk"]]}
            ids = dict(connection.execute("SELECT path,id FROM ValidPaths"))
            for source, targets in references.items():
                for target in targets:
                    connection.execute("INSERT INTO Refs VALUES(?,?)", (ids[source], ids[target]))
        self.physical = producer.physical
        self.open_parent = producer.custody.open_parent
        def physical(path):
            candidate = Path(path)
            if candidate.is_relative_to(self.directory):
                require = producer.require
                require(str(candidate) == path and ".." not in candidate.parts, "selection_invalid")
            else:
                self.physical(path)
        def parent(path, uid, deadline, now):
            candidate = Path(path)
            if not candidate.is_relative_to(self.directory):
                return self.open_parent(path, uid, deadline, now)
            producer.budget(deadline)
            descriptor = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                for part in candidate.relative_to(self.directory).parts[:-1]:
                    child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
                    os.close(descriptor); descriptor = child
                return descriptor
            except BaseException:
                os.close(descriptor); raise
        for patcher in (patch.object(producer, "physical", side_effect=physical),
                        patch.object(producer.custody, "open_parent", side_effect=parent)):
            patcher.start(); self.addCleanup(patcher.stop)
        # Only the output selector's /srv prefix is modeled; actual parent/file
        # metadata, exclusive writes, inode drift and owned cleanup remain real.
        self.output_patcher = patch.object(producer, "output_selector", side_effect=physical)
        self.output_patcher.start(); self.addCleanup(self.output_patcher.stop)

    def write_selection(self):
        self.picked.write_bytes(producer.canonical(self.selection))
        self.selection_sha = producer.digest(self.picked.read_bytes())

    def snapshot(self, database, roots, *, exists):
        self.assertEqual(database, producer.DATABASE)
        return snapshot_inventory(str(self.database), roots, exists=exists)

    def observe(self, path, deadline):
        producer.budget(deadline)
        self.assertIn(path, self.roots.values())
        return ((1, path, 0o40555, 0, 0, 1, 0, 1, 1), None)

    def binding(self, selected_root, expected, rows, captures, deadline):
        name = "native_manifest" if selected_root == self.roots["native"] else "bootstrap_manifest"
        target = self.roots[name]
        self.assertIn(target, rows[selected_root]["references"])
        observed = self.native if name == "native_manifest" else self.bootstrap
        producer.require(expected == observed, "manifest_mismatch")
        return {"registeredObject": target, "registeredManifestSha256": producer.digest(producer.canonical(observed))}

    def produce(self, **changes):
        arguments = dict(selection_path=str(self.picked), selection_sha256=self.selection_sha,
                         native_manifest=str(self.native_path), bootstrap_manifest=str(self.bootstrap_path),
                         wrapper_paths=self.wrapper_paths, output=str(self.output), deadline_ns=self.deadline,
                         snapshotter=self.snapshot, observer=self.observe)
        arguments.update(changes)
        with patch.object(producer, "registered_manifest", side_effect=self.binding):
            return producer.produce_inventory(**arguments)

    def test_real_sqlite_closed_inventory_and_private_wrapper_companion(self):
        result = self.produce()
        data = (self.output / "controller-inventory.json").read_bytes()
        receipt_bytes = (self.output / "controller-evidence.json").read_bytes()
        value, receipt = json.loads(data), json.loads(receipt_bytes)
        self.assertEqual(producer.parse_inventory(data, result["inventorySha256"]), value["paths"])
        self.assertEqual(result["receiptSha256"], producer.digest(receipt_bytes))
        self.assertEqual(receipt["registeredPaths"], 12)
        self.assertEqual(receipt["rootCount"], 9)
        self.assertNotIn(self.roots["bash"], value["roots"])
        self.assertIn(self.roots["bash"], {row["path"] for row in value["paths"]})
        for name, facts in receipt["wrappers"].items():
            self.assertEqual(facts["sha256"], self.selection["wrapperSha256"][name])
            self.assertEqual(facts["backendRoot"], producer.store_root(facts["backend"]))
        for key in ("contentRehashed", "executionAuthority", "destinationRegistrationVerified", "wrapperExecuted", "backendExecuted", "realized"):
            self.assertIs(receipt[key], False)
        self.assertEqual(stat.S_IMODE(self.output.stat().st_mode), 0o700)
        self.assertTrue(all(stat.S_IMODE(path.stat().st_mode) == 0o600 for path in self.output.iterdir()))
        self.assertNotIn(str(self.directory), json.dumps(result))

    def test_independent_selection_manifest_and_wrapper_hashes_refuse(self):
        with self.assertRaisesRegex(producer.InventoryError, "digest_mismatch"):
            self.produce(selection_sha256="0" * 64)
        for key in ("nativeManifestSha256", "bootstrapManifestSha256"):
            original = self.selection[key]; self.selection[key] = "0" * 64; self.write_selection()
            with self.assertRaisesRegex(producer.InventoryError, "digest_mismatch"):
                self.produce()
            self.selection[key] = original
        self.selection["wrapperSha256"]["keyring"] = "0" * 64; self.write_selection()
        with self.assertRaisesRegex(producer.InventoryError, "digest_mismatch"):
            self.produce()
        self.assertFalse(self.output.exists())

    def test_unknown_role_extra_field_and_boolean_schema_refuse(self):
        original = copy.deepcopy(self.selection)
        for mutate in (lambda value: value.update(extra=True), lambda value: value.update(schemaVersion=True),
                       lambda value: value["controllerTools"].update(extra=root("m", "extra"))):
            self.selection = copy.deepcopy(original); mutate(self.selection); self.write_selection()
            with self.assertRaisesRegex(producer.InventoryError, "selection_invalid"):
                self.produce()
        self.assertFalse(self.output.exists())

    def test_absent_independent_selector_digest_refuses_before_read(self):
        with patch.object(producer, "Capture") as capture:
            with self.assertRaisesRegex(producer.InventoryError, "selection_invalid"):
                self.produce(selection_sha256=None)
            capture.assert_not_called()

    def test_physical_selector_admits_registered_file_roots_but_no_parent_escape(self):
        self.physical(self.roots["native_manifest"])
        self.physical(self.roots["bootstrap_manifest"])
        for path in ("/nix/store/manifest", "/nix/store/../manifest", "/etc/manifest", self.roots["native_manifest"] + "/../elsewhere"):
            with self.assertRaisesRegex(producer.InventoryError, "selection_invalid"):
                self.physical(path)

    def test_hash_selected_wrapper_with_extra_shell_command_is_not_abi(self):
        path = Path(self.wrapper_paths["dbus_session"])
        path.chmod(0o600); path.write_bytes(path.read_bytes() + b"echo unwanted\n"); path.chmod(0o555)
        self.selection["wrapperSha256"]["dbus_session"] = producer.digest(path.read_bytes()); self.write_selection()
        with self.assertRaisesRegex(producer.InventoryError, "wrapper_mismatch"):
            self.produce()
        self.assertFalse(self.output.exists())

    def test_missing_registry_root_and_reference_are_not_filled_from_files(self):
        with closing(sqlite3.connect(self.database)) as connection, connection:
            connection.execute("DELETE FROM ValidPaths WHERE path=?", (self.roots["jdk"],))
        with self.assertRaises(ValueError):
            self.produce()
        self.assertFalse(self.output.exists())

    def test_unrelated_rows_are_rejected_instead_of_authority_roots(self):
        def unrelated(database, roots, *, exists):
            rows = self.snapshot(database, roots, exists=exists)
            return sorted(rows + [{"path": root("m", "unrelated"), "narHash": "sha256:" + "a" * 64, "narSize": 100, "references": []}], key=lambda row: row["path"])
        with self.assertRaisesRegex(producer.InventoryError, "registry_invalid"):
            self.produce(snapshotter=unrelated)
        self.assertFalse(self.output.exists())

    def test_wrapper_interpreter_must_be_reachable_without_adding_root(self):
        with closing(sqlite3.connect(self.database)) as connection, connection:
            identifier = connection.execute("SELECT id FROM ValidPaths WHERE path=?", (self.roots["bash"],)).fetchone()[0]
            connection.execute("DELETE FROM Refs WHERE reference=?", (identifier,))
        with self.assertRaisesRegex(producer.InventoryError, "registry_invalid"):
            self.produce()
        self.assertFalse(self.output.exists())

    def test_registry_drift_between_transactions_refuses_publication(self):
        calls = 0
        def drift(database, roots, *, exists):
            nonlocal calls
            calls += 1
            if calls == 2:
                with closing(sqlite3.connect(self.database)) as connection, connection:
                    connection.execute("UPDATE ValidPaths SET narSize=201 WHERE path=?", (self.roots["python"],))
            return self.snapshot(database, roots, exists=exists)
        with self.assertRaisesRegex(producer.InventoryError, "registry_changed"):
            self.produce(snapshotter=drift)
        self.assertFalse(self.output.exists())

    def test_earlier_selected_file_replacement_during_snapshot_is_refused(self):
        replaced = False
        def replace(database, roots, *, exists):
            nonlocal replaced
            if not replaced:
                replaced = True
                self.picked.rename(self.directory / "old-selection")
                self.picked.write_bytes((self.directory / "old-selection").read_bytes())
            return self.snapshot(database, roots, exists=exists)
        with self.assertRaisesRegex(producer.InventoryError, "input_changed"):
            self.produce(snapshotter=replace)
        self.assertFalse(self.output.exists())

    def test_fifo_and_alias_are_rejected_before_collection(self):
        fifo = self.directory / "fifo"; os.mkfifo(fifo, 0o600)
        alias = self.directory / "alias"; alias.symlink_to(self.picked)
        for path in (fifo, alias):
            with patch.object(producer.os, "read") as reader:
                with self.assertRaises((ValueError, OSError)):
                    producer.Capture(str(path), self.selection_sha, producer.MAX_SELECTION, self.deadline)
                reader.assert_not_called()

    def test_file_fstat_failure_closes_both_allocated_descriptors(self):
        actual_open, actual_stat = os.open, os.fstat
        allocated = []
        def opened(*args, **kwargs):
            descriptor = actual_open(*args, **kwargs)
            allocated.append(descriptor)
            return descriptor
        def metadata(descriptor):
            info = actual_stat(descriptor)
            if stat.S_ISREG(info.st_mode):
                raise OSError("fixed injected fstat failure")
            return info
        with patch.object(producer.os, "open", side_effect=opened), patch.object(producer.os, "fstat", side_effect=metadata):
            with self.assertRaises(OSError):
                producer.Capture(str(self.picked), self.selection_sha, producer.MAX_SELECTION, self.deadline)
        self.assertEqual(len(allocated), 2)
        for descriptor in allocated:
            with self.assertRaises(OSError):
                actual_stat(descriptor)

    def test_original_deadline_and_snapshot_reserve_refuse_before_output(self):
        for deadline in (True, 0, time.monotonic_ns() - 1, time.monotonic_ns() + 60 * 10**9):
            with self.assertRaisesRegex(producer.InventoryError, "deadline_exceeded"):
                self.produce(deadline_ns=deadline)
        self.assertFalse(self.output.exists())

    def test_path_reference_and_byte_caps_refuse(self):
        rows = self.snapshot(producer.DATABASE, [self.roots["native"]], exists=lambda _: True)
        roots = [self.roots["native"]]
        for name, ceiling in (("MAX_PATHS", 1), ("MAX_REFS", 1), ("MAX_BYTES", 1)):
            with patch.object(producer, name, ceiling), self.assertRaises(producer.InventoryError):
                producer.inventory(rows, roots, {})
        duplicate = rows + [rows[-1]]
        with self.assertRaises(producer.InventoryError):
            producer.inventory(duplicate, roots, {})

    def test_registered_manifest_refuses_host_relative_and_undeclared_targets(self):
        info = os.stat_result((stat.S_IFLNK | 0o777, 10, 1, 1, 0, 0, 20, 0, 0, 0))
        directory_fd = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY)
        try:
            for target in ("/etc/environment", "../manifest", root("m", "undeclared")):
                with patch.object(producer.custody, "open_parent", side_effect=lambda *args: os.dup(directory_fd)), \
                     patch.object(producer.os, "stat", return_value=info), patch.object(producer.os, "readlink", return_value=target), \
                     patch.object(producer, "Capture") as reader:
                    with self.assertRaisesRegex(producer.InventoryError, "manifest_mismatch"):
                        producer.registered_manifest(self.roots["native"], self.native,
                            {self.roots["native"]: {"references": []}}, [], self.deadline)
                    reader.assert_not_called()
        finally:
            os.close(directory_fd)

    def test_existing_output_is_never_adopted_or_removed(self):
        self.output.mkdir(mode=0o700); marker = self.output / "foreign"; marker.write_bytes(b"keep")
        with self.assertRaises(FileExistsError):
            self.produce()
        self.assertEqual(marker.read_bytes(), b"keep")

    def test_second_evidence_write_failure_removes_owned_pair_only(self):
        unrelated = self.directory / "unrelated"; unrelated.mkdir(); (unrelated / "keep").write_bytes(b"keep")
        real_write = producer.Output.write
        def fail(output, name, data):
            if name == "controller-evidence.json":
                raise OSError("fixed injected failure")
            return real_write(output, name, data)
        with patch.object(producer.Output, "write", side_effect=fail, autospec=True), self.assertRaises(OSError):
            self.produce()
        self.assertFalse(self.output.exists()); self.assertEqual((unrelated / "keep").read_bytes(), b"keep")

    def test_foreign_output_replacement_is_preserved_on_failed_join(self):
        calls = 0
        def replace(database, roots, *, exists):
            nonlocal calls
            calls += 1
            if calls == 3:
                path = self.output / "controller-inventory.json"
                path.rename(self.output / "retained-original")
                path.write_bytes(b"foreign")
            return self.snapshot(database, roots, exists=exists)
        with self.assertRaisesRegex(producer.InventoryError, "cleanup_incomplete"):
            self.produce(snapshotter=replace)
        self.assertEqual((self.output / "controller-inventory.json").read_bytes(), b"foreign")

    def test_unknown_output_entry_preserves_foreign_data_and_refuses_cleanup(self):
        calls = 0
        def insert(database, roots, *, exists):
            nonlocal calls
            calls += 1
            if calls == 3:
                (self.output / "foreign").write_bytes(b"keep")
            return self.snapshot(database, roots, exists=exists)
        with self.assertRaisesRegex(producer.InventoryError, "cleanup_incomplete"):
            self.produce(snapshotter=insert)
        self.assertEqual((self.output / "foreign").read_bytes(), b"keep")

    def test_foreign_entry_added_during_output_rehash_refuses_final_layout(self):
        real_capture = producer.Capture
        output = self.output
        class Capture(real_capture):
            def __init__(self, path, *args, **kwargs):
                super().__init__(path, *args, **kwargs)
                if Path(path) == output / "controller-evidence.json":
                    (output / "foreign").write_bytes(b"keep")
        with patch.object(producer, "Capture", Capture), self.assertRaisesRegex(producer.InventoryError, "cleanup_incomplete"):
            self.produce()
        self.assertEqual((self.output / "foreign").read_bytes(), b"keep")

    def test_cli_seconds_bounds_refuse_without_producer_and_one_original_deadline(self):
        arguments = ["producer"]
        for flag in ("selection", "selection-sha256", "native-manifest", "bootstrap-manifest",
                     "dbus-session", "dbus-daemon", "keyring", "output"):
            arguments.extend(["--" + flag, "fixed-declared-input"])
        for value in ("0", "601", "not-an-integer"):
            with patch.object(producer.sys, "argv", arguments + ["--seconds", value]), \
                 patch.object(producer, "produce_inventory") as called:
                with self.assertRaisesRegex(producer.InventoryError, "selection_invalid"):
                    producer.main()
                called.assert_not_called()
        for seconds in (None, "600"):
            argv = arguments if seconds is None else arguments + ["--seconds", seconds]
            with patch.object(producer.sys, "argv", argv), patch.object(producer.time, "monotonic_ns", return_value=1234567) as now, \
                 patch.dict(producer.os.environ, {"OMUX_EXECUTION_GUARD": "/srv/guard-fixture"}, clear=True), \
                 patch.object(producer, "produce_inventory", return_value={"scope": "modeled-cli-call"}) as called, patch("builtins.print"):
                self.assertEqual(producer.main(), 0)
                self.assertEqual(now.call_count, 2)
                self.assertEqual(called.call_args.args[-1], 1234567 + int(seconds or "120") * 10**9)

    def test_cli_requires_guarded_declared_output_context_and_forwards_exact_default(self):
        arguments = ["producer"]
        for flag in ("selection", "selection-sha256", "native-manifest", "bootstrap-manifest", "dbus-session", "dbus-daemon", "keyring"):
            arguments.extend(["--" + flag, "fixed-declared-input"])
        for environment in ({}, {"OMUX_EXECUTION_GUARD": "/srv/guard-fixture"}):
            with patch.object(producer.sys, "argv", arguments), patch.dict(producer.os.environ, environment, clear=True), \
                 patch.object(producer, "produce_inventory") as called:
                with self.assertRaisesRegex(producer.InventoryError, "selection_invalid"):
                    producer.main()
                called.assert_not_called()
        environment = {"OMUX_EXECUTION_GUARD": "/srv/guard-fixture", "TEST_UNDECLARED_OUTPUTS_DIR": str(self.directory)}
        with patch.object(producer.sys, "argv", arguments), patch.dict(producer.os.environ, environment, clear=True), \
             patch.object(producer, "produce_inventory", return_value={"scope": "modeled-cli-call"}) as called, patch("builtins.print"):
            self.assertEqual(producer.main(), 0)
            self.assertEqual(called.call_args.args[-2], str(self.directory.resolve() / "yoga-controller-inputs"))


if __name__ == "__main__":
    unittest.main()
