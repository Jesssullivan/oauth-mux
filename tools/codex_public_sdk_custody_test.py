"""Real tiny-FS/FD models and explicit negative kernel-metadata stimuli.

No mount, namespace, OS-service or provider changes. Injected RO observations
are negative-model setup, never evidence that a real foreign mount is readonly.
The declared SDK action remains the real complete readonly-namespace gate.
"""
from contextlib import ExitStack
import ctypes
import errno
import os
from pathlib import Path
import stat
import tempfile
import time
import unittest
from unittest.mock import patch

import codex_native_sdk_carrier as core
import codex_public_sdk_custody as public
import codex_retained_sdk_tree_inputs as admission


class PublicSdkCustodyModels(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.temporary = self.stack.enter_context(tempfile.TemporaryDirectory(dir=os.environ["TEST_TMPDIR"]))
        self.path = Path(self.temporary)
        self.leaf = self.path / "public-input"
        self.leaf.write_bytes(b"synthetic declared public SDK input\n")
        self.leaf.chmod(0o444)
        entry = time.monotonic_ns()
        self.context = {"MODE": admission.PROFILE, "ENTRY_NS": str(entry),
            "DEADLINE_NS": str(entry + 1200 * 10**9),
            "EPOCH": "/srv/fast-local/jess/state/codex/omux-integrated-execution-20261005/22222222-2222-2222-2222-222222222222",
            "SOURCE_COMMIT": "a" * 40, "GRAPH_SHA256": "b" * 64,
            "BOOT_ID": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"}
        environment = {"OMUX_NATIVE_SDK_TREE_" + name: value for name, value in self.context.items()}
        environment["OMUX_NATIVE_SDK_TREE_CURRENT_BOOT_ID"] = self.context["BOOT_ID"]
        self.stack.enter_context(patch.dict(os.environ, environment))
        self.clock = core.Clock((entry + 1170 * 10**9) / 10**9)
        self.clock.until_ns = entry + 1170 * 10**9
        self.domain = public.materializer_domain(self.context, self.clock)
        self.stack.callback(self.domain.close)
        self.domain.confirm(core.encoded({"schema_version": 1,
            "kind": "omux-sdk-tree-current-clock-domain-v1", "clock": "linux-CLOCK_MONOTONIC",
            "boot_id": self.context["BOOT_ID"]}))

    def test_real_kernel_mount_id_and_flags_join_independent_current_open(self):
        fd = os.open(self.leaf, os.O_RDONLY | os.O_NOFOLLOW)
        named = os.open(self.leaf, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            held, mount = public._snapshot(fd, self.clock)
            current, current_mount = public._snapshot(named, self.clock)
            self.assertNotEqual(fd, named)
            self.assertEqual(held, current)
            self.assertEqual(len(held), 9)
            self.assertEqual(mount, current_mount)
            self.assertGreater(mount[0], 0)
            self.assertEqual(mount[1:], (os.fstatvfs(fd).f_fsid, os.fstatvfs(fd).f_flag))
            self.assertEqual(ctypes.sizeof(public._Statx), 256)
            self.assertEqual(public._Statx.mnt_id.offset, 144)
        finally: public.drain(fds=(fd, named))

    def test_real_owned_writable_namespace_and_complete_pinned_public_leaf(self):
        owner = public.Leaf(self.leaf, self.domain, 4096, core.sha(self.leaf.read_bytes()))
        try:
            self.assertEqual(owner.raw, b"synthetic declared public SDK input\n")
            self.assertEqual(owner.read(), owner.raw)
            self.assertEqual(owner.witness, core.identity(self.leaf.stat()))
            owner.check()
        finally: owner.close()

    def test_foreign_writable_refuses_with_real_kernel_flags_and_no_permission_argument(self):
        # No supplied RO bool/record can enter a constructor. The kernel call
        # remains real; the process-UID seam is negative fixture stimulus only.
        if self.leaf.stat().st_uid != 0 and not os.statvfs(self.path).f_flag & os.ST_RDONLY:
            with patch.object(os, "getuid", return_value=self.leaf.stat().st_uid + 1):
                with self.assertRaisesRegex(ValueError, "foreign-writable"):
                    public.Directory(self.path, self.domain)
        with self.assertRaises(TypeError): public.Directory(self.path, self.domain, readonly=True)

    def test_same_inode_current_named_writable_mount_refuses_while_old_held_remains_RO(self):
        actual_mount = public._mount
        # This injection describes the required counterexample; it does not
        # mount/remount anything or turn model output into kernel RO evidence.
        def model_ro(fd):
            mount, filesystem, flags = actual_mount(fd)
            return mount, filesystem, flags | os.ST_RDONLY
        with patch.object(public, "_mount", side_effect=model_ro):
            owner = public.Directory(self.path, self.domain)
            held_fds = {row[1] for row in owner.chain}
            observed = []
            def rebound(fd):
                mount, filesystem, flags = actual_mount(fd)
                observed.append((fd, core.identity(os.fstat(fd))))
                return mount, filesystem, (flags | os.ST_RDONLY) if fd in held_fds else flags & ~os.ST_RDONLY
            try:
                original = [core.identity(os.fstat(fd)) for fd in held_fds]
                with patch.object(public, "_mount", side_effect=rebound):
                    with self.assertRaisesRegex(ValueError, "current-mount-and-ancestor|foreign-writable"):
                        owner.check()
                self.assertTrue(any(fd not in held_fds for fd, witness in observed))
                self.assertTrue(any(fd in held_fds for fd, witness in observed))
                self.assertEqual(original, [core.identity(os.fstat(fd)) for fd in held_fds])
            finally: owner.close()

    def test_same_inode_readonly_rebind_with_different_kernel_mount_id_refuses(self):
        actual_mount = public._mount
        owner = public.Directory(self.path, self.domain)
        held = {row[1] for row in owner.chain}
        def rebound(fd):
            mount, filesystem, flags = actual_mount(fd)
            return mount if fd in held else mount + 1000000, filesystem, flags
        try:
            with patch.object(public, "_mount", side_effect=rebound):
                with self.assertRaisesRegex(ValueError, "current-mount-and-ancestor"):
                    owner.check()
        finally: owner.close()

    def test_readonly_to_writable_between_kernel_observation_regions_refuses(self):
        fd = os.open(self.leaf, os.O_RDONLY | os.O_NOFOLLOW)
        actual_mount = public._mount
        calls = [0]
        def transition(held):
            calls[0] += 1
            mount, filesystem, flags = actual_mount(held)
            return mount, filesystem, (flags | os.ST_RDONLY) if calls[0] == 1 else flags & ~os.ST_RDONLY
        try:
            with patch.object(public, "_mount", side_effect=transition):
                with self.assertRaisesRegex(ValueError, "kernel-observation-race"):
                    public._snapshot(fd, self.clock)
        finally: os.close(fd)

    def test_real_readonly_declared_input_uses_actual_RO_witness_when_available(self):
        # This exact declared source is a real action input. A processwrapper
        # namespace may expose a writable mount; that branch proves refusal,
        # not successful foreign RO admission. No skipped positive is counted.
        source = Path(__file__).resolve(strict=True)
        fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            witness, mount = public._snapshot(fd, self.clock)
            foreign = list(witness); foreign[2] = max(1, os.getuid() + 1)
            if mount[2] & os.ST_RDONLY:
                public._policy(foreign, mount)
            else:
                with self.assertRaisesRegex(ValueError, "foreign-writable"):
                    public._policy(foreign, mount)
        finally: os.close(fd)

    def test_statx_unsupported_mask_and_syscall_failures_refuse_and_drain_partial_opens(self):
        actual_open, actual_close = os.open, os.close
        for fault in ("unsupported", "syscall"):
            live, opened = set(), []
            class Call:
                def __call__(self, fd, path, flags, mask, output):
                    if fault == "syscall": ctypes.set_errno(errno.EPERM); return -1
                    output._obj.mask = 0
                    return 0
            class Library: statx = Call()
            def acquire(*args, **kwargs):
                fd = actual_open(*args, **kwargs); live.add(fd); opened.append(fd); return fd
            def retire(fd):
                self.assertIn(fd, live); live.remove(fd); actual_close(fd)
            with self.subTest(fault=fault), patch.object(os, "open", side_effect=acquire), \
                    patch.object(os, "close", side_effect=retire), patch.object(public.ctypes, "CDLL", return_value=Library()):
                with self.assertRaises((OSError, ValueError)): public.Directory(self.path, self.domain)
            self.assertTrue(opened)
            self.assertEqual(live, set())

    def test_partial_named_open_and_snapshot_fault_attempt_every_descriptor_close(self):
        actual_open, actual_close, actual_snapshot = os.open, os.close, public._snapshot
        live, opened = set(), []
        body = MemoryError("synthetic post-open snapshot refusal")
        calls = [0]
        def acquire(*args, **kwargs):
            fd = actual_open(*args, **kwargs); live.add(fd); opened.append(fd); return fd
        def retire(fd):
            self.assertIn(fd, live); live.remove(fd); actual_close(fd)
        def snapshot(fd, clock):
            calls[0] += 1
            if calls[0] == 3: raise body
            return actual_snapshot(fd, clock)
        with patch.object(os, "open", side_effect=acquire), patch.object(os, "close", side_effect=retire), \
                patch.object(public, "_snapshot", side_effect=snapshot):
            with self.assertRaises(MemoryError) as caught: public.Directory(self.path, self.domain)
        self.assertIs(caught.exception, body)
        self.assertGreaterEqual(len(opened), 3)
        self.assertEqual(live, set())

    def test_ambiguous_close_is_not_retried_after_fd_number_reuse_and_all_other_fds_drain(self):
        owner = public.Directory(self.path, self.domain)
        owned = {row[1] for row in owner.chain}
        actual_close, actual_open = os.close, os.open
        canary, attempted = [], []
        cleanup = OSError("synthetic after-effect close error")
        def retire(fd):
            attempted.append(fd); actual_close(fd)
            if len(attempted) == 1:
                replacement = actual_open(self.leaf, os.O_RDONLY)
                canary.append(replacement)
                self.assertEqual(replacement, fd)
                raise cleanup
        try:
            with patch.object(os, "close", side_effect=retire):
                with self.assertRaises(OSError) as caught: owner.close()
            self.assertIs(caught.exception, cleanup)
            self.assertEqual(set(attempted), owned)
            self.assertEqual(len(attempted), len(owned))
            self.assertEqual(owner.chain, [])
            self.assertEqual(core.identity(os.fstat(canary[0])), core.identity(self.leaf.stat()))
        finally:
            for fd in canary: actual_close(fd)

    def test_leaf_body_failure_keeps_first_cause_and_drains_current_named_and_held_owners(self):
        actual_open, actual_close, actual_read = os.open, os.close, os.read
        live, closed = set(), []
        body, cleanup = MemoryError("synthetic bounded read failure"), OSError("synthetic close after effect")
        armed = [False]
        def acquire(*args, **kwargs):
            fd = actual_open(*args, **kwargs); live.add(fd); return fd
        def retire(fd):
            self.assertIn(fd, live); live.remove(fd); closed.append(fd); actual_close(fd)
            if armed[0]: armed[0] = False; raise cleanup
        def read(fd, size): armed[0] = True; raise body
        with patch.object(os, "open", side_effect=acquire), patch.object(os, "close", side_effect=retire), \
                patch.object(os, "read", side_effect=read):
            with self.assertRaises(MemoryError) as caught: public.Leaf(self.leaf, self.domain, 4096)
        self.assertIs(caught.exception, body)
        self.assertIs(caught.exception.__cause__, cleanup)
        self.assertTrue(closed)
        self.assertEqual(live, set())

    def test_current_named_close_fault_keeps_reused_canary_and_drains_all_partial_owners(self):
        actual_open, actual_close = os.open, os.close
        live, canary, closed = set(), [], []
        cleanup = OSError("synthetic current-name close after effect")
        armed = [True]
        def acquire(*args, **kwargs):
            fd = actual_open(*args, **kwargs); live.add(fd); return fd
        def retire(fd):
            self.assertIn(fd, live); live.remove(fd); closed.append(fd); actual_close(fd)
            if armed[0]:
                armed[0] = False
                replacement = actual_open(self.leaf, os.O_RDONLY)
                self.assertEqual(replacement, fd)
                canary.append(replacement)
                raise cleanup
        try:
            with patch.object(os, "open", side_effect=acquire), patch.object(os, "close", side_effect=retire):
                with self.assertRaises(OSError) as caught: public.Leaf(self.leaf, self.domain, 4096)
            self.assertIs(caught.exception, cleanup)
            self.assertEqual(live, set())
            self.assertTrue(closed)
            self.assertEqual(core.identity(os.fstat(canary[0])), core.identity(self.leaf.stat()))
        finally:
            for fd in canary: actual_close(fd)

    def test_prior_cause_and_multiple_non_OS_close_faults_keep_primary_and_drain_every_slot(self):
        actual_close = os.close
        for prior in (None, OSError("synthetic earliest existing cause")):
            body = MemoryError("synthetic primary body")
            body.__cause__ = prior
            first, second = KeyboardInterrupt("synthetic first close fault"), MemoryError("synthetic second close fault")
            slots = (public.FdSlot(), public.FdSlot())
            for slot in slots: slot.fd = os.open(self.leaf, os.O_RDONLY)
            owned = {slot.fd for slot in slots}
            attempted = []
            def retire(fd):
                attempted.append(fd); actual_close(fd)
                raise first if len(attempted) == 1 else second
            with self.subTest(existing_cause=prior is not None), patch.object(os, "close", side_effect=retire):
                with self.assertRaises(MemoryError) as caught: public.drain(owners=slots, body=body)
            self.assertIs(caught.exception, body)
            self.assertIs(caught.exception.__cause__, first if prior is None else prior)
            self.assertEqual(set(attempted), owned)
            self.assertEqual(len(attempted), 2)
            self.assertTrue(all(slot.fd is None for slot in slots))
            for fd in owned:
                with self.assertRaises(OSError): os.fstat(fd)

    def test_public_writer_cache_postinsert_fault_drains_pending_dup_and_every_parent(self):
        base = self.path / "codex_native_retained_sdk_tree_materialized/sdk-tree-public"
        base.mkdir(parents=True, mode=0o700)
        stage = base / ".sdk-tree-creation-private"; stage.mkdir(mode=0o700)
        self.domain.bind_output(base)
        output = core.PublicOutput(stage / "tree", self.clock, self.domain)
        output.mkdir("sdk")
        handles = core._PublicParentHandles(output.root)
        body = MemoryError("synthetic after-insert cache refusal")
        prior = OSError("synthetic prior cause")
        body.__cause__ = prior
        class AfterInsert(dict):
            def __setitem__(self, name, value): super().__setitem__(name, value); raise body
        handles.entries = AfterInsert()
        live = set()
        actual_open, actual_dup, actual_close = os.open, os.dup, os.close
        def acquire(*args, **kwargs):
            fd = actual_open(*args, **kwargs); live.add(fd); return fd
        def duplicate(fd):
            result = actual_dup(fd); live.add(result); return result
        def retire(fd):
            self.assertIn(fd, live); live.remove(fd); actual_close(fd)
        try:
            with patch.object(os, "open", side_effect=acquire), patch.object(os, "dup", side_effect=duplicate), \
                    patch.object(os, "close", side_effect=retire):
                with self.assertRaises(MemoryError) as caught:
                    with handles: handles.parent("sdk/file")
            self.assertIs(caught.exception, body)
            self.assertIs(caught.exception.__cause__, prior)
            self.assertEqual(live, set())
            self.assertIsNone(handles.pending)
            self.assertEqual(handles.entries, {})
        finally:
            handles.close(); output.close()

    def test_public_root_postinsert_and_stack_enrollment_faults_close_owned_ancestry(self):
        import codex_native_retained_sdk_tree_producer as producer
        base = self.path / "codex_native_retained_sdk_tree_materialized/sdk-tree-public"
        root = base / "tree/sdk"; root.mkdir(parents=True, mode=0o700); root.chmod(0o555)
        self.domain.bind_output(base)
        body = MemoryError("synthetic post-enrollment root failure")
        class AfterInsert(dict):
            def __setitem__(self, name, owner): super().__setitem__(name, owner); raise body
        roots = AfterInsert(sdk=None)
        with self.assertRaises(MemoryError) as caught:
            producer._keep_root(roots, "sdk", root, self.clock, self.domain)
        self.assertIs(caught.exception, body)
        self.assertIsNone(roots["sdk"].ancestry)
        self.assertEqual(roots["sdk"].chain, [])
        # The stack-fault route likewise retains a local owner before a
        # fallible callback allocation, including an after-insert refusal.
        carrier_path = self.path / "sdk-private/sdk-carrier"
        self.domain.bind_carrier(carrier_path, "a" * 64)
        held = core.PublicHeldCarrier(carrier_path, "a" * 64, self.clock.deadline, self.domain)
        class Stack:
            def enter_context(self, owner): self.owner = owner; raise body
        stack = Stack()
        with self.assertRaises(MemoryError): core._sdk_enter_root(stack, held, root, self.clock)
        self.assertIsNone(stack.owner.ancestry)
        self.assertEqual(stack.owner.chain, [])
        held.close()

    def test_default_private_directory_and_root_still_refuse_foreign_RO_ancestry(self):
        actual_mount = public._mount
        def model_ro(fd):
            mount, filesystem, flags = actual_mount(fd)
            return mount, filesystem, flags | os.ST_RDONLY
        if self.path.stat().st_uid == 0: return
        with patch.object(os, "getuid", return_value=self.path.stat().st_uid + 1), \
                patch.object(public, "_mount", side_effect=model_ro):
            owner = public.Directory(self.path, self.domain)
            owner.close()
            with self.assertRaises(ValueError): admission._Directory(self.path, self.clock)
            with self.assertRaises(ValueError): core.Root(self.path, self.clock, sealed=False)
            with self.assertRaisesRegex(ValueError, "owned-writer-endpoint"):
                public.WriterDirectory(self.path, self.domain)

    def test_private_proof600_cannot_join_control_or_unbound_public_proof_reader(self):
        private = self.path / "synthetic-private-proof"
        private.write_bytes(b"synthetic original proof, no secrets")
        private.chmod(0o600)
        with self.assertRaises(ValueError): public.Leaf(private, self.domain, 4096)
        with self.assertRaisesRegex(ValueError, "only-five-declared-original-proofs"):
            public.Leaf(private, self.domain, 4096, core.sha(private.read_bytes()), "proof")

    def test_bound_original_proof600_foreign_owner_refuses_even_with_model_RO_ancestors(self):
        import codex_native_carrier_metadata as metadata
        rows = {}
        epoch = self.path / "11111111-1111-1111-1111-111111111111"
        report = epoch / "output-base/execroot/_main/bazel-out/k8-fastbuild/testlogs/tools/codex_native_sdk_carrier_seal_producer/test.outputs/sdk-private/native-sdk-carrier-producer.json"
        paths = {"outer_receipt": epoch / "receipt.json", "test_evidence": epoch / "test-evidence.json",
            "test_log": epoch / "test-evidence" / ("a" * 64 + ".evidence"),
            "test_xml": epoch / "test-evidence" / ("b" * 64 + ".evidence"), "program_report": report}
        for role, alias in metadata.PROOF_ALIASES.items():
            path = paths[role]; path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            path.write_bytes(b"synthetic original evidence only"); path.chmod(0o600)
            rows[role] = {"path": str(path), "sha256": core.sha(path.read_bytes()), "alias": alias}
        self.domain.bind_proofs({"kind": metadata.PROOF_KIND, "proofs": rows})
        selected = rows["outer_receipt"]
        if self.path.stat().st_uid == 0: return
        actual_mount = public._mount
        def model_ro(fd):
            mount, filesystem, flags = actual_mount(fd)
            return mount, filesystem, flags | os.ST_RDONLY
        with patch.object(os, "getuid", return_value=self.path.stat().st_uid + 1), \
                patch.object(public, "_mount", side_effect=model_ro):
            with self.assertRaisesRegex(ValueError, "original-proof-process-owner"):
                public.Leaf(selected["path"], self.domain, 4096, selected["sha256"], "proof")

    def test_alias_replacement_same_bytes_and_changed_parent_refuse_current_owner(self):
        alias = self.path / "alias"; alias.symlink_to(self.leaf)
        owner = public.Leaf(alias, self.domain, 4096, core.sha(self.leaf.read_bytes()))
        try:
            alias.rename(self.path / "preserved-alias")
            alias.symlink_to(self.leaf)
            with self.assertRaises(ValueError): owner.check()
        finally: owner.close()

    def test_wrong_type_role_phase_context_and_original_clock_mutations_refuse(self):
        with self.assertRaises(TypeError): public.materializer_domain(self.context, self.clock, readonly=True)
        with self.assertRaises(ValueError): public.Domain(object(), self.context, self.clock, "arbitrary")
        with self.assertRaises(ValueError): public.Directory(self.path, object())
        with self.assertRaises(ValueError): core.PublicRoot(self.path, self.clock, self.domain)
        changed = self.clock.until_ns
        self.clock.until_ns += 1
        try:
            with self.assertRaises(ValueError): self.domain.check()
        finally: self.clock.until_ns = changed
        with patch.dict(os.environ, {"OMUX_NATIVE_SDK_TREE_SOURCE_COMMIT": "c" * 40}):
            with self.assertRaises(ValueError): self.domain.check()
        with patch.object(os, "getpid", return_value=self.domain.pid + 1):
            with self.assertRaises(ValueError): self.domain.check()
        with patch.object(public.threading, "get_ident", return_value=self.domain.thread + 1):
            with self.assertRaises(ValueError): self.domain.check()
        with patch.object(core.time, "monotonic", return_value=self.clock.deadline):
            with self.assertRaises(ValueError): self.domain.check()

    def test_exact_types_exclude_subclass_and_duck_carrier_or_NAR_roots(self):
        import codex_retained_sdk_tree as tree
        class Fake:
            owned = False
            clock = self.clock
        with self.assertRaises(ValueError): core._FreshNarParents(Fake(), self.clock)
        with self.assertRaises(ValueError): core._carrier_clock(Fake(), self.path, "a" * 64, self.clock.deadline)
        class WrongDirectory(public.Directory): pass
        with self.assertRaises(ValueError): WrongDirectory(self.path, self.domain)
        # Even the exact public root class cannot enter default retained proof.
        root = object.__new__(core.PublicRoot)
        root.clock, root.owned, root.domain = self.clock, False, self.domain
        roots = {"sdk": root, "jdk": root}
        with self.assertRaisesRegex(ValueError, "exact-current-roots"):
            tree.scan_retained_tree(roots, {}, tree.PHYSICAL_POLICY, self.clock)
        with self.assertRaisesRegex(ValueError, "exact-public-qualification-roots"):
            tree.scan_public_sdk_tree(roots, {}, tree.PHYSICAL_POLICY, self.clock, self.domain)

    def test_public_proof_stack_drains_multiple_faults_and_preserves_existing_first_cause(self):
        visited = []
        primary = ValueError("original proof failure")
        prior = LookupError("earliest original cause")
        primary.__cause__ = prior
        def fail(label, error):
            visited.append(label)
            raise error
        with self.assertRaises(ValueError) as caught:
            with core._PublicProofExitStack() as stack:
                stack.callback(fail, "first-registered", MemoryError("later close"))
                stack.callback(fail, "last-registered", KeyboardInterrupt("first close"))
                raise primary
        self.assertIs(caught.exception, primary)
        self.assertIs(caught.exception.__cause__, prior)
        self.assertEqual(visited, ["last-registered", "first-registered"])
        self.assertIs(type(core._sdk_proof_stack(None)), core._ProofExitStack)

    def test_actual_complete_materialize_and_qualify_use_public_variants_and_preserve_default_reader(self):
        import codex_native_retained_sdk_tree_producer as producer
        from codex_retained_sdk_tree_fixture import TinyCarrier
        from codex_retained_sdk_tree_admission_fixture import DeclaredTreeFixture
        with TinyCarrier() as tiny, DeclaredTreeFixture(tiny) as fixture:
            producer.materialize(fixture.materialize_args())
            tiny.normalize(fixture.output / "tree")
            with patch.dict(os.environ, {"TEST_UNDECLARED_OUTPUTS_DIR": str(fixture.qualifier_output)}):
                producer.qualify(fixture.qualifier_args())
            self.assertEqual((fixture.qualifier_output / "sdk-tree-public/receipt.json").read_bytes(),
                             (fixture.output / "receipt.json").read_bytes())
            default = admission.admit_carrier(fixture.runfiles, fixture.rows, fixture.context, fixture.domain_raw)
            try: self.assertIs(type(default), admission.CreatorCarrierInputs)
            finally: default.close()


if __name__ == "__main__": unittest.main()
