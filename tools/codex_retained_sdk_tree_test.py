"""Real tiny-FS retained logical/physical proof models; UNRUN proposal."""
from contextlib import ExitStack
import copy
import os
from pathlib import Path
import stat
import tempfile
import time
import unittest
from unittest.mock import patch

import codex_native_sdk_carrier as core
import codex_retained_sdk_tree as tree


class RetainedTreeFactsTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=os.environ["TEST_TMPDIR"])
        self.root = Path(self.tmp.name)
        self.tree = self.root / "tree"
        self.tree.mkdir(mode=0o700)
        self.logical = {}
        for role in ("sdk", "jdk"):
            (self.tree / role).mkdir(mode=0o700)
            self.logical[(role, "")] = {"kind": "directory", "mode": 0o555}
        for role, name, raw, mode in (("sdk", "plain", b"public metadata", 0o444),
                ("sdk", "executable", b"public executable content", 0o555),
                ("jdk", "receipt", b"public recipe", 0o400)):
            path = self.tree / role / name
            path.write_bytes(raw)
            path.chmod(mode)
            self.logical[(role, name)] = {"kind": "file", "mode": mode,
                "size": len(raw), "sha256": core.sha(raw)}
        os.symlink("/nix/store/inert-public-link", self.tree / "jdk" / "literal")
        self.logical[("jdk", "literal")] = {"kind": "symlink",
            "target": "/nix/store/inert-public-link"}
        for role in ("sdk", "jdk"): (self.tree / role).chmod(0o555)
        self.tree.chmod(0o555)
        self.until = time.monotonic() + 20
        self.clock = core.Clock(self.until)
        with self.roots() as roots:
            observed, self.created, self.nars = core._scan_nar(roots, self.logical, self.clock)
            self.assertEqual(observed, self.logical)
        # Model Bazel's closed all-regular0555 retention transformation only;
        # an actual declared retained-output gate remains separately required.
        for (role, name), row in self.logical.items():
            if row["kind"] == "file": (self.tree / role / name).chmod(0o555)
        self.document = {"schema_version": 1, "kind": tree.INVENTORY_KIND,
            "carrier": {"receipt_sha256": "1" * 64, "manifest_sha256": "2" * 64,
                "payload_sha256": "3" * 64, "origin_receipt_sha256": "4" * 64},
            "nars": self.nars,
            "entries": [{"role": role, "path": name, **row}
                for (role, name), row in sorted(self.logical.items())]}
        self.raw = core.encoded(self.document)

    def tearDown(self):
        for directory, children, files in os.walk(self.root, followlinks=False):
            Path(directory).chmod(0o700)
        self.tmp.cleanup()

    def roots(self):
        stack = ExitStack()
        try:
            roots = {role: stack.enter_context(core.Root(self.tree / role, self.clock))
                for role in ("sdk", "jdk")}
            class Owner:
                def __enter__(self): return roots
                def __exit__(self, *error): return stack.__exit__(*error)
            return Owner()
        except BaseException:
            stack.close()
            raise

    def parsed(self, document=None):
        raw = self.raw if document is None else core.encoded(document)
        return tree.parse_inventory(raw, core.sha(raw), self.clock)

    def test_complete_real_retained_tree_preserves_logical_nar_and_all_byte_sha(self):
        logical, expected_nars, lineage = self.parsed()
        with self.roots() as roots:
            witnesses, nars = tree.scan_retained_tree(roots, logical, tree.PHYSICAL_POLICY, self.clock)
            self.assertEqual(nars, expected_nars)
            self.assertEqual(core.decode(nars), self.nars)
            self.assertEqual(set(witnesses), set(self.logical))
            for (role, name), row in logical.items():
                if row["kind"] == "file":
                    self.assertEqual(stat.S_IMODE(witnesses[(role, name)][4]), 0o555)
                    self.assertEqual(core.sha((self.tree / role / name).read_bytes()), row["sha256"])
            self.assertFalse(core.decode(nars)["jdk"]["linkTargetsFollowed"])
            self.assertEqual(self.clock.deadline, self.until)

    def test_logical_executable_bit_is_not_inherited_from_physical0555(self):
        logical, expected, unused = self.parsed()
        with self.roots() as roots:
            unused, actual = tree.scan_retained_tree(roots, logical, tree.PHYSICAL_POLICY, self.clock)
        changed = {key: dict(row) for key, row in logical.items()}
        changed[("sdk", "plain")]["mode"] = 0o555
        with self.roots() as roots:
            unused, changed_nars = tree.scan_retained_tree(roots, changed, tree.PHYSICAL_POLICY, self.clock)
        self.assertEqual(actual, expected)
        self.assertNotEqual(core.decode(changed_nars)["sdk"], core.decode(expected)["sdk"])

    def test_closed_schema_duplicates_missing_roles_and_mixed_payload_rows_refuse(self):
        for change in ("duplicate", "missing-role", "extra-field", "offset", "wrong-kind", "bad-parent"):
            with self.subTest(change=change):
                value = copy.deepcopy(self.document)
                if change == "duplicate": value["entries"].append(value["entries"][-1])
                elif change == "missing-role": value["entries"] = [row for row in value["entries"] if row["role"] != "jdk"]
                elif change == "extra-field": value["authority"] = True
                elif change == "offset": value["entries"][-1]["offset"] = 0
                elif change == "wrong-kind": value["kind"] = core.SCRATCH_EXTRACTED
                else: value["entries"][-1]["path"] = "absent/child"
                with self.assertRaises(ValueError): self.parsed(value)

    def test_changed_selected_pin_and_writable_or_wrong_retention_policy_refuse(self):
        with self.assertRaises(ValueError): tree.parse_inventory(self.raw, "0" * 64, self.clock)
        logical, unused, lineage = self.parsed()
        with self.roots() as roots:
            with self.assertRaises(ValueError): tree.scan_retained_tree(roots, logical, "arbitrary", self.clock)
        leaf = self.tree / "sdk" / "plain"
        for mode in (0o444, 0o644, 0o777):
            with self.subTest(mode=mode):
                leaf.chmod(mode)
                with self.roots() as roots:
                    with self.assertRaises(ValueError): tree.scan_retained_tree(roots, logical, tree.PHYSICAL_POLICY, self.clock)
                leaf.chmod(0o555)

    def test_extra_member_symlink_and_hardlink_alias_refuse_current_namespace(self):
        logical, unused, lineage = self.parsed()
        directory = self.tree / "sdk"
        for kind in ("extra", "symlink", "hardlink"):
            with self.subTest(kind=kind):
                directory.chmod(0o700)
                target = directory / "foreign"
                if kind == "extra": target.write_bytes(b"extra public byte")
                elif kind == "symlink": os.symlink("plain", target)
                else: os.link(directory / "plain", target)
                directory.chmod(0o555)
                with self.roots() as roots:
                    with self.assertRaises(ValueError): tree.scan_retained_tree(roots, logical, tree.PHYSICAL_POLICY, self.clock)
                directory.chmod(0o700); target.unlink(); directory.chmod(0o555)

    def test_actual_content_change_before_stream_and_original_clock_during_read_refuse(self):
        logical, unused, lineage = self.parsed()
        leaf = self.tree / "sdk" / "plain"
        raw = leaf.read_bytes()
        leaf.chmod(0o700); leaf.write_bytes(b"X" * len(raw)); leaf.chmod(0o555)
        with self.roots() as roots:
            with self.assertRaises(ValueError): tree.scan_retained_tree(roots, logical, tree.PHYSICAL_POLICY, self.clock)
        leaf.chmod(0o700); leaf.write_bytes(raw); leaf.chmod(0o555)
        real_read, expired = os.read, [False]
        def read(fd, count):
            block = real_read(fd, count)
            if block: expired[0] = True
            return block
        def now(): return self.until + 1 if expired[0] else self.until - 1
        with self.roots() as roots:
            with patch.object(core.os, "read", side_effect=read), patch.object(core.time, "monotonic", side_effect=now):
                with self.assertRaises(ValueError): tree.scan_retained_tree(roots, logical, tree.PHYSICAL_POLICY, self.clock)
        self.assertTrue(expired[0])
        self.assertEqual(self.clock.deadline, self.until)




    def test_real_owned_sealed_tree_relocation_keeps_inode_descendants_and_full_nar(self):
        import codex_native_retained_sdk_tree_producer as producer
        import codex_retained_sdk_tree_inputs as admission
        parent_path = self.root / "published"
        parent_path.mkdir(mode=0o700)
        stage = core.Root(self.root, self.clock, sealed=False, owned=True)
        parent = admission._Directory(parent_path, self.clock)
        fd = None
        actual_chmod, actual_rename = os.fchmod, os.rename
        changes, moved = [], []
        try:
            logical, unused_nars, unused_lineage = self.parsed()
            with self.roots() as roots:
                before_members, before_nars = tree.scan_retained_tree(roots, logical, tree.PHYSICAL_POLICY, self.clock)
            fd = os.open("tree", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=stage.fd)
            expected = core.identity(os.fstat(fd), True)
            self.assertEqual(stat.S_IMODE(expected[4]), 0o555)
            def chmod(selected, mode):
                self.assertEqual(selected, fd)
                changes.append((selected, mode))
                return actual_chmod(selected, mode)
            def rename(source, target, **kwargs):
                self.assertEqual((source, target), ("tree", "tree"))
                self.assertEqual((kwargs["src_dir_fd"], kwargs["dst_dir_fd"]), (stage.fd, parent.fd))
                self.assertEqual(stat.S_IMODE(os.fstat(fd).st_mode), 0o700)
                self.assertEqual(core.identity(os.fstat(fd), True), core.identity(
                    os.stat(source, dir_fd=stage.fd, follow_symlinks=False), True))
                result = actual_rename(source, target, **kwargs)
                moved.append(core.identity(os.stat(target, dir_fd=parent.fd, follow_symlinks=False), True))
                return result
            with patch.object(os, "fchmod", chmod), patch.object(os, "rename", rename):
                self.assertEqual(producer._relocate_owned_tree(stage, parent, fd, expected, self.clock), expected)
            self.assertEqual(changes, [(fd, 0o700), (fd, 0o555)])
            self.assertEqual(len(moved), 1)
            self.assertEqual(moved[0][:4], expected[:4])
            self.assertEqual(stat.S_IMODE(moved[0][4]), 0o700)
            self.assertFalse(self.tree.exists())
            self.tree = parent_path / "tree"
            with core.Root(self.tree, self.clock) as published:
                self.assertEqual(core.identity(os.fstat(published.fd), True), expected)
            with self.roots() as roots:
                after_members, after_nars = tree.scan_retained_tree(roots, logical, tree.PHYSICAL_POLICY, self.clock)
            self.assertEqual(after_members, before_members)
            self.assertEqual(after_nars, before_nars)
            self.assertEqual(self.clock.deadline, self.until)
        finally:
            if fd is not None: os.close(fd)
            parent.close(); stage.close()


class RetainedTreeProducerModels(unittest.TestCase):
    def test_actual_durable_tiny_carrier_normalized_tree_semantics_and_two_current_full_scans(self):
        import codex_native_retained_sdk_tree_producer as producer
        from codex_retained_sdk_tree_fixture import TinyCarrier
        with TinyCarrier() as tiny:
            path = tiny.root / "retained-current-tree"
            logical, nars, extracted = tiny.durable_tree(path)
            self.assertEqual(extracted["kind"], core.EXTRACTED)
            self.assertTrue(extracted["extracted_inventory_rechecked"])
            self.assertFalse(extracted["original_inodes_reused"])
            tiny.normalize(path)
            clock = core.Clock(time.monotonic() + 60)
            owner = producer._TreeScan(path, logical, clock)
            fds = [fd for root in (owner.root, *owner.roots.values()) for _, fd, _ in root.chain]
            try:
                self.assertEqual(core.decode(owner.nars), nars)
                first = owner.semantics()
                self.assertEqual(owner.semantics(), first)
                owner.final(); owner.fence()
                self.assertEqual(core.decode(first)["registry_inventory_sha256"],
                    core.decode(tiny.model.original)["registry_metadata"]["inventory_sha256"])
                self.assertEqual(len(owner.witnesses), len(logical))
            finally: owner.close()
            for fd in fds:
                with self.assertRaises(OSError): os.fstat(fd)

    def test_real_current_final_scan_detects_changed_file_and_same_byte_new_inode(self):
        import codex_native_retained_sdk_tree_producer as producer
        from codex_retained_sdk_tree_fixture import TinyCarrier
        for fault in ("bytes", "same-byte-inode"):
            with self.subTest(fault=fault), TinyCarrier() as tiny:
                path = tiny.root / "retained-race"
                logical, unused, extracted = tiny.durable_tree(path)
                tiny.normalize(path)
                owner = producer._TreeScan(path, logical, core.Clock(time.monotonic() + 60))
                leaf = path / "sdk/repositories/public+/tool"
                raw = leaf.read_bytes()
                try:
                    if fault == "bytes":
                        leaf.chmod(0o700); leaf.write_bytes(b"X" * len(raw)); leaf.chmod(0o555)
                    else:
                        parent = leaf.parent; parent.chmod(0o700)
                        backup = parent / "held-old-tool"
                        leaf.rename(backup)
                        leaf.write_bytes(raw); leaf.chmod(0o555)
                        # The retired original remains singly named; no nlink0
                        # custody refusal masks the actual named-identity join.
                        self.assertEqual(backup.stat().st_nlink, 1)
                        self.assertNotEqual(backup.stat().st_ino, leaf.stat().st_ino)
                        backup.rename(tiny.root / "held-old-tool")
                        parent.chmod(0o555)
                    with self.assertRaises(ValueError): owner.final()
                finally: owner.close()

    def test_actual_public_input_hash_refuses_private_mode_and_preserves_read_cleanup_first_cause(self):
        import codex_native_retained_sdk_tree_producer as producer
        with tempfile.TemporaryDirectory(dir=os.environ["TEST_TMPDIR"]) as temporary:
            path = Path(temporary) / "public"
            raw = b"synthetic public declared code"
            path.write_bytes(raw); path.chmod(0o444)
            owner = producer.PublicInput(path, core.Clock(time.monotonic() + 60))
            selected = owner.fd
            try: self.assertEqual(owner.digest(), (core.sha(raw), len(raw)))
            finally: owner.close()
            with self.assertRaises(OSError): os.fstat(selected)
            path.chmod(0o600)
            with self.assertRaises(ValueError): producer.PublicInput(path, core.Clock(time.monotonic() + 60))
            path.chmod(0o444)
            body, cleanup = MemoryError("synthetic read refusal"), OSError("synthetic close result")
            real_open, real_close = os.open, os.close
            opened, closed = [], []
            def acquire(*args, **kwargs):
                fd = real_open(*args, **kwargs); opened.append(fd); return fd
            def retire(fd):
                closed.append(fd); real_close(fd)
                if len(closed) == 1: raise cleanup
            with patch.object(os, "open", acquire), patch.object(os, "close", retire), \
                    patch.object(os, "read", side_effect=body):
                with self.assertRaises(MemoryError) as caught:
                    with producer.PublicInput(path, core.Clock(time.monotonic() + 60)) as held: held.digest()
            self.assertIs(caught.exception, body)
            self.assertIs(caught.exception.__cause__, cleanup)
            self.assertEqual(set(opened), set(closed))
            self.assertEqual(len(closed), len(set(closed)))
            for fd in opened:
                with self.assertRaises(OSError): os.fstat(fd)

    def test_actual_metadata_writer_is_exclusive_durable_and_preserves_first_write_cause(self):
        import codex_native_retained_sdk_tree_producer as producer
        import codex_retained_sdk_tree_inputs as admission
        with tempfile.TemporaryDirectory(dir=os.environ["TEST_TMPDIR"]) as temporary:
            parent = admission._Directory(Path(temporary), core.Clock(time.monotonic() + 60))
            try:
                raw = b"synthetic canonical public receipt"
                witness = producer._write_leaf(parent, "receipt.json", raw, parent.clock)
                path = Path(temporary) / "receipt.json"
                self.assertEqual(path.read_bytes(), raw)
                self.assertEqual(core.identity(path.stat()), witness)
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o444)
                with self.assertRaises(FileExistsError): producer._write_leaf(parent, "receipt.json", b"replay", parent.clock)
                self.assertEqual(path.read_bytes(), raw)
                body, cleanup = MemoryError("synthetic write refusal"), OSError("synthetic successful close error")
                real_close, closed = os.close, []
                def retire(fd): closed.append(fd); real_close(fd); raise cleanup
                with patch.object(os, "write", side_effect=body), patch.object(os, "close", retire):
                    with self.assertRaises(MemoryError) as caught:
                        producer._write_leaf(parent, "failed.json", raw, parent.clock)
                self.assertIs(caught.exception, body)
                self.assertIs(caught.exception.__cause__, cleanup)
                self.assertEqual(len(closed), 1)
                with self.assertRaises(OSError): os.fstat(closed[0])
            finally: parent.close()

    def test_closed_action_descriptor_requires_complete_disjoint_declared_input_roles(self):
        import codex_native_retained_sdk_tree_producer as producer
        clock = core.Clock(time.monotonic() + 60)
        value = {"schema_version": 1, "kind": producer.ACTION_KIND,
            "code": [{"logical_path": "_main/tools/code.py", "execution_path": "tools/code.py"}],
            "tools": [{"logical_path": "python/bin/python", "execution_path": "external/python/bin/python"}],
            "proofs": [{"logical_path": "proof/receipt", "execution_path": "external/proof/receipt"}],
            "carrier": [{"name": name, "logical_path": "carrier/" + name,
                "execution_path": "external/carrier/" + name} for name in core.FILES]}
        self.assertEqual(producer._descriptor(core.encoded(value), clock), value)
        for fault in ("collision", "missing-proof", "missing-carrier", "extra", "bad-path", "missing-logical"):
            changed = copy.deepcopy(value)
            if fault == "collision": changed["proofs"][0]["logical_path"] = changed["code"][0]["logical_path"]
            elif fault == "missing-proof": changed["proofs"] = []
            elif fault == "missing-carrier": changed["carrier"].pop()
            elif fault == "extra": changed["success"] = True
            elif fault == "bad-path": changed["tools"][0]["logical_path"] = "../outside"
            else: del changed["carrier"][0]["logical_path"]
            with self.subTest(fault=fault), self.assertRaises(ValueError): producer._descriptor(core.encoded(changed), clock)

    def test_actual_qualifier_rejects_same_byte_code_swap_after_last_full_tree_proof_without_marker(self):
        import io
        from contextlib import redirect_stdout
        import codex_native_retained_sdk_tree_producer as producer
        from codex_retained_sdk_tree_fixture import TinyCarrier
        from codex_retained_sdk_tree_admission_fixture import DeclaredTreeFixture
        with TinyCarrier() as tiny, DeclaredTreeFixture(tiny) as fixture:
            producer.materialize(fixture.materialize_args())
            tiny.normalize(fixture.output / "tree")
            actual_final = producer._TreeScan.final
            def after_tree(owner):
                actual_final(owner)
                code = Path(fixture.descriptor["code"][0]["execution_path"])
                raw = code.read_bytes(); original = fixture.root / "original-code"
                code.rename(original); code.write_bytes(raw); code.chmod(0o444)
                self.assertEqual(original.stat().st_nlink, 1)
                self.assertEqual(original.read_bytes(), code.read_bytes())
                self.assertNotEqual(original.stat().st_ino, code.stat().st_ino)
            with patch.dict(os.environ, {"TEST_UNDECLARED_OUTPUTS_DIR": str(fixture.qualifier_output)}), \
                    patch.object(producer._TreeScan, "final", after_tree), redirect_stdout(io.StringIO()) as stdout:
                with self.assertRaisesRegex(ValueError, "final-declared-input-physical-fence"):
                    producer.qualify(fixture.qualifier_args())
            self.assertEqual(stdout.getvalue(), "")

    def test_actual_qualifier_terminal_close_expiry_attempts_all_fd_drains_and_emits_no_marker(self):
        import io
        from contextlib import redirect_stdout
        import codex_native_retained_sdk_tree_producer as producer
        from codex_retained_sdk_tree_fixture import TinyCarrier
        from codex_retained_sdk_tree_admission_fixture import DeclaredTreeFixture
        with TinyCarrier() as tiny, DeclaredTreeFixture(tiny) as fixture:
            producer.materialize(fixture.materialize_args())
            tiny.normalize(fixture.output / "tree")
            actual_drain, actual_clock = producer._drain, time.monotonic
            actual_open, actual_dup, actual_close = os.open, os.dup, os.close
            cutoff = (fixture.entry + 1170 * 10**9) / 10**9
            expired, live, acquired, retired = [False], set(), [], []
            def acquire(*args, **kwargs):
                fd = actual_open(*args, **kwargs)
                self.assertNotIn(fd, live); live.add(fd); acquired.append(fd); return fd
            def duplicate(fd):
                result = actual_dup(fd)
                self.assertNotIn(result, live); live.add(result); acquired.append(result); return result
            def close(fd):
                self.assertIn(fd, live); live.remove(fd); retired.append(fd); actual_close(fd)
            def drain(*args, **kwargs):
                result = actual_drain(*args, **kwargs)
                expired[0] = True
                return result
            with patch.dict(os.environ, {"TEST_UNDECLARED_OUTPUTS_DIR": str(fixture.qualifier_output)}), \
                    patch.object(os, "open", acquire), patch.object(os, "dup", duplicate), patch.object(os, "close", close), \
                    patch.object(producer, "_drain", drain), \
                    patch.object(time, "monotonic", side_effect=lambda: cutoff if expired[0] else actual_clock()), \
                    redirect_stdout(io.StringIO()) as stdout:
                with self.assertRaisesRegex(ValueError, "deadline"):
                    producer.qualify(fixture.qualifier_args())
            self.assertTrue(expired[0]); self.assertTrue(acquired)
            self.assertEqual(live, set()); self.assertEqual(len(acquired), len(retired))
            self.assertEqual(stdout.getvalue(), "")


    def test_real_owned_relocation_faults_reseal_original_root_and_preserve_first_cause(self):
        import codex_native_retained_sdk_tree_producer as producer
        import codex_retained_sdk_tree_inputs as admission
        for fault in ("source-name-swap", "chmod-after-effect", "cutoff-after-writable", "reseal-after-effect", "rename-collision", "rename-cleanup-fault"):
            with self.subTest(fault=fault), tempfile.TemporaryDirectory(dir=os.environ["TEST_TMPDIR"]) as temporary:
                root = Path(temporary)
                staged, destination = root / "stage", root / "destination"
                staged.mkdir(mode=0o700); destination.mkdir(mode=0o700)
                source = staged / "tree"; source.mkdir(mode=0o700)
                leaf = source / "public"; leaf.write_bytes(b"synthetic retained public bytes"); leaf.chmod(0o444)
                source.chmod(0o555)
                clock = core.Clock(time.monotonic() + 20)
                original_until = clock.deadline
                stage = core.Root(staged, clock, sealed=False, owned=True)
                parent = admission._Directory(destination, clock)
                fd = None
                actual_chmod, actual_rename, actual_time = os.fchmod, os.rename, time.monotonic
                expired, renamed, collision, reseal_faulted = [False], [], [], [False]
                reseal = OSError("synthetic reseal after-effect refusal")
                body, cleanup = MemoryError("synthetic permission transition refusal"), OSError("synthetic reseal after-effect refusal")
                try:
                    fd = os.open("tree", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=stage.fd)
                    expected = core.identity(os.fstat(fd), True)
                    leaf_witness = core.identity(leaf.stat())
                    if fault == "source-name-swap":
                        source.rename(staged / "held-tree")
                        source.mkdir(mode=0o555)
                        self.assertNotEqual(source.stat().st_ino, expected[1])
                    def chmod(selected, mode):
                        self.assertEqual(selected, fd)
                        result = actual_chmod(selected, mode)
                        if mode == 0o700 and fault == "chmod-after-effect": raise body
                        if mode == 0o700 and fault == "cutoff-after-writable": expired[0] = True
                        if mode == 0o555 and fault == "reseal-after-effect" and not reseal_faulted[0]:
                            reseal_faulted[0] = True
                            raise reseal
                        if mode == 0o555 and fault == "rename-cleanup-fault": raise cleanup
                        return result
                    def rename(source_name, target, **kwargs):
                        renamed.append((source_name, target))
                        self.assertEqual(stat.S_IMODE(os.fstat(fd).st_mode), 0o700)
                        if fault in ("rename-collision", "rename-cleanup-fault"):
                            foreign = destination / "tree"
                            foreign.mkdir(mode=0o700)
                            (foreign / "keep").write_bytes(b"synthetic foreign output remains")
                        try: return actual_rename(source_name, target, **kwargs)
                        except OSError as error: collision.append(error); raise
                    with patch.object(os, "fchmod", chmod), patch.object(os, "rename", rename), \
                            patch.object(core.time, "monotonic", side_effect=lambda: original_until if expired[0] else actual_time()):
                        if fault == "source-name-swap":
                            with self.assertRaisesRegex(ValueError, "owned-sealed-relocation-root"):
                                producer._relocate_owned_tree(stage, parent, fd, expected, clock)
                        elif fault == "chmod-after-effect":
                            with self.assertRaises(MemoryError) as caught:
                                producer._relocate_owned_tree(stage, parent, fd, expected, clock)
                            self.assertIs(caught.exception, body)
                        elif fault == "cutoff-after-writable":
                            with self.assertRaisesRegex(ValueError, "deadline"):
                                producer._relocate_owned_tree(stage, parent, fd, expected, clock)
                        elif fault == "reseal-after-effect":
                            with self.assertRaises(OSError) as caught:
                                producer._relocate_owned_tree(stage, parent, fd, expected, clock)
                            self.assertIs(caught.exception, reseal)
                            self.assertTrue(reseal_faulted[0])
                            self.assertFalse(source.exists())
                        else:
                            with self.assertRaises(OSError) as caught:
                                producer._relocate_owned_tree(stage, parent, fd, expected, clock)
                            self.assertEqual(len(collision), 1)
                            self.assertIs(caught.exception, collision[0])
                            if fault == "rename-cleanup-fault": self.assertIs(caught.exception.__cause__, cleanup)
                            self.assertEqual((destination / "tree" / "keep").read_bytes(), b"synthetic foreign output remains")
                    self.assertEqual(core.identity(os.fstat(fd), True), expected)
                    original_path = (staged / "held-tree" if fault == "source-name-swap" else
                        destination / "tree" if fault == "reseal-after-effect" else source)
                    self.assertEqual(core.identity((original_path / "public").stat()), leaf_witness)
                    self.assertEqual(clock.deadline, original_until)
                    if fault not in ("rename-collision", "rename-cleanup-fault", "reseal-after-effect"):
                        self.assertEqual(renamed, [])
                        self.assertFalse((destination / "tree").exists())
                    self.assertFalse((destination / "receipt.json").exists())
                finally:
                    if fd is not None: os.close(fd)
                    parent.close(); stage.close()


if __name__ == "__main__": unittest.main()
