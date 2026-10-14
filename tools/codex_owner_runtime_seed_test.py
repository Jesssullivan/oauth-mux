"""Real public-file seed/copy models, not native or consumer qualification."""
from contextlib import ExitStack, redirect_stdout
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import shutil
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import codex_owner_runtime_seed as subject
import codex_owner_runtime_input as runtime


class SeedTests(unittest.TestCase):
    def setUp(self):
        self.owner = ExitStack()
        self.addCleanup(self.owner.close)
        self.scratch = self.owner.enter_context(tempfile.TemporaryDirectory(dir=os.environ.get("TEST_TMPDIR")))
        self.root = Path(self.scratch)
        self.root.chmod(0o700)
        self.source = self.root / "original-public.tar.gz"
        self.source.write_bytes(b"synthetic public runtime byte copy" * 37)
        self.source.chmod(0o644)
        meta = self.root / "integrations/codex-owner-runtime"
        meta.mkdir(parents=True, mode=0o700)
        self.manifest = meta / "runtime-manifest.json"
        self.receipt = meta / "runtime-receipt.json"
        self.manifest.write_bytes(b'{"synthetic_public_manifest":1}\n')
        self.receipt.write_bytes(b'{"synthetic_public_receipt":1}\n')
        self.outputs = self.root / "outputs"
        self.outputs.mkdir(mode=0o700)
        self.owner.enter_context(patch.multiple(runtime,
            ARCHIVE_SHA=hashlib.sha256(self.source.read_bytes()).hexdigest(),
            ARCHIVE_BYTES=self.source.stat().st_size,
            MANIFEST_SHA=hashlib.sha256(self.manifest.read_bytes()).hexdigest(),
            EXPECTED_RECEIPT=self.receipt.read_bytes()))
        self.owner.enter_context(patch.multiple(subject, SOURCE_PATH=self.source,
            RECEIPT_SHA=hashlib.sha256(self.receipt.read_bytes()).hexdigest()))
        self.descriptor = self.root / "source-role.json"
        self.descriptor.write_text(json.dumps(subject.source_role()))

    def admission(self):
        entry = time.monotonic_ns()
        admission = subject.Admission(self.root, entry, entry + 20 * 10**9)
        self.owner.callback(admission.close)
        return admission

    def copy(self, admission):
        return subject.copy_seed(admission, self.source, self.descriptor,
                                 self.manifest, self.receipt, self.outputs)

    def test_real_complete_copy_has_no_consumer_authority_and_source_is_unchanged(self):
        before = runtime.identity(self.source.stat())
        original = self.source.read_bytes()
        admission = self.admission()
        with patch.object(runtime, "copy_retained", wraps=runtime.copy_retained) as writer:
            result = self.copy(admission)
        writer.assert_called_once()
        leaf = self.outputs / runtime.ARCHIVE_SHA
        copied = leaf / runtime.NAME
        self.assertEqual(copied.read_bytes(), original)
        self.assertEqual(copied.stat().st_mode & 0o777, 0o400)
        self.assertEqual(leaf.stat().st_mode & 0o777, 0o700)
        self.assertEqual(set(leaf.iterdir()), {copied})
        self.assertEqual(runtime.identity(self.source.stat()), before)
        self.assertEqual(self.source.stat().st_mode & 0o777, 0o644)
        self.assertTrue((self.outputs / "codex-owner-runtime-input-receipt.json").is_file())
        self.assertFalse(result["nativeSupport"])
        self.assertFalse(admission.facts()["consumer_admitted"])
        self.assertFalse(admission.facts()["source_qualified"])

    def test_closed_role_refuses_missing_extra_bool_duplicate_and_foreign_path_before_copy(self):
        valid = subject.source_role()
        variants = [{k: v for k, v in valid.items() if k != "source_path"},
                    dict(valid, extra="unrelated"), dict(valid, schema_version=True),
                    dict(valid, native_support=0), dict(valid, source_path=str(self.root / "foreign")),
                    dict(valid, archive_sha256="0" * 64)]
        admission = self.admission()
        for value in variants:
            with self.subTest(value=value):
                self.descriptor.write_text(json.dumps(value))
                with self.assertRaisesRegex(ValueError, "runtime-seed-role"):
                    self.copy(admission)
                self.assertEqual(list(self.outputs.iterdir()), [])
        with self.assertRaisesRegex(ValueError, "duplicate-role"):
            subject.role(b'{"schema_version":1,"schema_version":1}')

    def test_wrong_source_hash_refuses_before_any_output(self):
        self.source.write_bytes(b"x" * runtime.ARCHIVE_BYTES)
        with self.assertRaisesRegex(ValueError, "retained-input-identity"):
            self.admission()
        self.assertEqual(list(self.outputs.iterdir()), [])

    def test_real_source_group_write_hardlink_and_symlink_refuse_without_changing_source(self):
        original = self.source.read_bytes()
        self.source.chmod(0o664)
        with self.assertRaisesRegex(ValueError, "custody"):
            self.admission()
        self.source.chmod(0o644)
        alias = self.root / "link"
        os.link(self.source, alias)
        with self.assertRaisesRegex(ValueError, "custody"):
            self.admission()
        alias.unlink()
        saved = self.root / "saved"
        self.source.rename(saved)
        self.source.symlink_to(saved)
        with self.assertRaises(OSError):
            self.admission()
        self.source.unlink()
        saved.rename(self.source)
        self.assertEqual(self.source.read_bytes(), original)
        self.assertEqual(list(self.outputs.iterdir()), [])

    def test_same_bytes_new_source_inode_is_refused_by_held_named_join(self):
        admission = self.admission()
        replacement = self.root / "replacement"
        replacement.write_bytes(self.source.read_bytes())
        replacement.chmod(0o644)
        backup = self.source.with_name(self.source.name + ".displaced")
        self.source.rename(backup)
        replacement.replace(self.source)
        self.assertEqual(os.fstat(admission.source.fd).st_nlink, 1)
        self.assertEqual(backup.stat().st_ino, os.fstat(admission.source.fd).st_ino)
        self.assertNotEqual(self.source.stat().st_ino, backup.stat().st_ino)
        with patch.object(runtime, "copy_retained", wraps=runtime.copy_retained) as writer:
            with self.assertRaisesRegex(ValueError, "input-changed"):
                self.copy(admission)
            writer.assert_not_called()
        self.assertEqual(list(self.outputs.iterdir()), [])

    def test_equal_content_replaced_source_parent_is_refused_by_real_ancestor_fence(self):
        admission = self.admission()
        content = self.source.read_bytes()
        manifest = self.manifest.read_bytes()
        receipt = self.receipt.read_bytes()
        descriptor = self.descriptor.read_bytes()
        prior = self.root.with_name(self.root.name + "-prior")
        self.root.rename(prior)
        self.addCleanup(shutil.rmtree, prior)
        self.root.mkdir(mode=0o700)
        self.source.write_bytes(content)
        self.source.chmod(0o644)
        self.manifest.parent.mkdir(parents=True, mode=0o700)
        self.manifest.write_bytes(manifest)
        self.receipt.write_bytes(receipt)
        self.descriptor.write_bytes(descriptor)
        self.outputs.mkdir(mode=0o700)
        with self.assertRaisesRegex(ValueError, "ancestor-changed"):
            self.copy(admission)
        self.assertEqual(list(self.outputs.iterdir()), [])

    def test_actual_mid_copy_source_mutation_refuses_and_existing_writer_cleans_partial_output(self):
        admission = self.admission()
        actual = runtime.stream_digest
        def mutate(fd, deadline, *, output=None):
            result = actual(fd, deadline, output=output)
            if output is not None:
                self.source.write_bytes(b"z" * runtime.ARCHIVE_BYTES)
            return result
        with patch.object(runtime, "stream_digest", side_effect=mutate), \
                self.assertRaisesRegex(ValueError, "retained-source-changed-after-copy"):
            self.copy(admission)
        self.assertEqual(list(self.outputs.iterdir()), [])

    def test_actual_metadata_inode_replacement_refuses_before_writer(self):
        admission = self.admission()
        replacement = self.root / "replacement"
        replacement.write_bytes(self.manifest.read_bytes())
        backup = self.manifest.with_name(self.manifest.name + ".displaced")
        self.manifest.rename(backup)
        replacement.replace(self.manifest)
        self.assertEqual(os.fstat(admission.manifest.fd).st_nlink, 1)
        self.assertEqual(backup.stat().st_ino, os.fstat(admission.manifest.fd).st_ino)
        self.assertNotEqual(self.manifest.stat().st_ino, backup.stat().st_ino)
        with patch.object(runtime, "copy_retained", wraps=runtime.copy_retained) as writer:
            with self.assertRaisesRegex(ValueError, "input-changed"):
                self.copy(admission)
            writer.assert_not_called()
        self.assertEqual(list(self.outputs.iterdir()), [])

    def test_exclusive_output_does_not_overwrite_previous_bytes(self):
        admission = self.admission()
        leaf = self.outputs / runtime.ARCHIVE_SHA
        leaf.mkdir()
        sentinel = leaf / "prior"
        sentinel.write_bytes(b"preserve previous public artifact")
        with self.assertRaises(FileExistsError):
            self.copy(admission)
        self.assertEqual(sentinel.read_bytes(), b"preserve previous public artifact")

    def test_real_fsyncs_cover_regular_payload_and_receipt_plus_output_directories(self):
        admission = self.admission()
        actual = os.fsync
        seen = []
        def observe(fd):
            actual(fd)
            seen.append(os.fstat(fd).st_mode)
        with patch.object(runtime.os, "fsync", side_effect=observe):
            self.copy(admission)
        self.assertGreaterEqual(sum(stat.S_ISREG(mode) for mode in seen), 2)
        self.assertGreaterEqual(sum(stat.S_ISDIR(mode) for mode in seen), 3)

    def test_actual_fsync_failure_preserves_first_error_and_no_partial_copy(self):
        admission = self.admission()
        primary = OSError("synthetic-public-fsync-failure")
        original = self.source.read_bytes()
        with patch.object(runtime.os, "fsync", side_effect=primary), self.assertRaises(OSError) as raised:
            self.copy(admission)
        self.assertIs(raised.exception, primary)
        self.assertEqual(list(self.outputs.iterdir()), [])
        self.assertEqual(self.source.read_bytes(), original)

    def test_original_expired_cutoff_refuses_without_live_authority_or_clock_reset(self):
        entry = time.monotonic_ns() - 2 * 10**9
        with self.assertRaisesRegex(ValueError, "deadline"):
            subject.Admission(self.root, entry, entry + 10**9)
        self.assertEqual(list(self.outputs.iterdir()), [])
        admission = self.admission()
        cutoff = admission.deadline_ns
        with patch.object(runtime.time, "monotonic_ns", return_value=cutoff):
            with self.assertRaisesRegex(ValueError, "deadline"):
                self.copy(admission)
        self.assertEqual(admission.deadline_ns, cutoff)
        self.assertEqual(list(self.outputs.iterdir()), [])

    def test_constructor_real_fd_cleanup_failure_does_not_replace_primary_input_error(self):
        self.source.write_bytes(b"q" * runtime.ARCHIVE_BYTES)
        before = len(os.listdir("/proc/self/fd"))
        actual = os.close
        first = True
        def close(fd):
            nonlocal first
            actual(fd)
            if first:
                first = False
                raise OSError("synthetic-public-close-failure")
        with patch.object(subject.os, "close", side_effect=close), \
                self.assertRaisesRegex(ValueError, "retained-input-identity") as raised:
            self.admission()
        self.assertIn("runtime-seed-cleanup-refused", raised.exception.__notes__)
        self.assertEqual(len(os.listdir("/proc/self/fd")), before)

    def test_exact_seed_cohort_cannot_dispatch_consumers_flags_cache_or_provider_roles(self):
        self.assertTrue(subject.selected("standard", subject.ARGUMENTS))
        for arguments in (["test", subject.LABEL], ["run", subject.LABEL],
                ["test", subject.LABEL, "//delivery:installed_retained_ordinary_native_tui_test"],
                subject.ARGUMENTS + ["--test_arg=unrelated"]):
            with self.subTest(arguments=arguments), self.assertRaises(ValueError):
                subject.selected("standard", arguments)
        self.assertFalse(subject.selected("standard", ["test", subject.MODEL]))
        with self.assertRaises(ValueError):
            subject.selected("codex-live", subject.ARGUMENTS)
        args = SimpleNamespace(profile="standard", manager="system", source_commit="a" * 40,
                               source_dirty="false", reuse_owned_cache=False)
        self.assertTrue(subject.request(args, subject.ARGUMENTS))
        args.reuse_owned_cache = True
        with self.assertRaises(ValueError):
            subject.request(args, subject.ARGUMENTS)

    def test_guard_command_context_is_fixed_and_carries_original_budget_without_authority(self):
        run = Path("/synthetic-public-run/12345678-1234-1234-1234-123456789abc")
        command = ["bazel", *subject.ARGUMENTS]
        result = subject.augment(command, run, 1, 2, "a" * 40, "b" * 64, self.root)
        self.assertEqual(result[-2:], subject.ARGUMENTS[-2:])
        self.assertIn("--test_env=OMUX_EXECUTION_GUARD=" + str(run), result)
        self.assertIn("--test_env=" + subject.PREFIX + "ENTRY_NS=1", result)
        self.assertIn("--test_env=" + subject.PREFIX + "DEADLINE_NS=2", result)
        with self.assertRaises(ValueError):
            subject.augment(command, run, 1, 2, "a" * 40, "invalid", self.root)


    def registration_faults(self, action, registrations, *, cleanup_fault=False):
        actual_callback = ExitStack.callback
        actual_close = os.close
        for after in (False, True):
            for index in range(1, registrations + 1):
                with self.subTest(after_insert=after, registration=index, cleanup_fault=cleanup_fault):
                    before = len(os.listdir("/proc/self/fd"))
                    primary = MemoryError("synthetic-public-registration-failure")
                    calls = 0
                    closed = 0
                    def register(owner, *args, **kwargs):
                        nonlocal calls
                        calls += 1
                        if calls == index and not after:
                            raise primary
                        result = actual_callback(owner, *args, **kwargs)
                        if calls == index and after:
                            raise primary
                        return result
                    def close(fd):
                        nonlocal closed
                        actual_close(fd)
                        closed += 1
                        if cleanup_fault and closed == 1:
                            raise OSError("synthetic-public-close-after-release")
                    with patch.object(ExitStack, "callback", new=register), \
                            patch.object(subject.os, "close", side_effect=close), \
                            self.assertRaises(MemoryError) as raised:
                        action()
                    self.assertIs(raised.exception, primary)
                    self.assertEqual(calls, index)
                    self.assertEqual(len(os.listdir("/proc/self/fd")), before)
                    self.assertEqual(list(self.outputs.iterdir()), [])

    def test_all_input_owner_registrations_before_and_after_insert_drain_real_fds(self):
        paths = (self.source, self.manifest, self.receipt)
        registrations = 1 + sum(len(path.parts) + 1 for path in paths)
        def acquire():
            owner = ExitStack()
            entry = time.monotonic_ns()
            try:
                subject.admit_owned(owner, self.root, entry, entry + 20 * 10**9)
            except BaseException as primary:
                subject.close_failure(owner, primary)
                raise
            owner.close()
        self.registration_faults(acquire, registrations)
        self.registration_faults(acquire, registrations, cleanup_fault=True)
        self.assertEqual(self.source.stat().st_mode & 0o777, 0o644)

    def test_role_owner_registration_faults_do_not_enter_writer_or_leak_real_fds(self):
        admission = self.admission()
        with patch.object(runtime, "copy_retained", wraps=runtime.copy_retained) as writer:
            self.registration_faults(lambda: self.copy(admission), len(self.descriptor.parts) + 1)
            self.registration_faults(lambda: self.copy(admission), len(self.descriptor.parts) + 1,
                                     cleanup_fault=True)
            writer.assert_not_called()
        admission.recheck()

    def test_cleanup_diagnostic_allocation_cannot_replace_original_failure(self):
        class Primary(MemoryError):
            def add_note(self, note):
                raise MemoryError("synthetic-note-allocation")
        primary = Primary("synthetic-body-failure")
        class Owner:
            def close(self):
                raise OSError("synthetic-cleanup-failure")
        subject.close_failure(Owner(), primary)
        self.assertEqual(str(primary), "synthetic-body-failure")

    def test_actual_final_graph_source_and_metadata_swaps_are_refused_while_owners_live(self):
        for selected in (self.source, self.manifest, self.receipt):
            with self.subTest(selected=selected.name):
                admission = self.admission()
                expected = ("synthetic-graph", 3)
                def graph():
                    replacement = self.root / "replacement"
                    replacement.write_bytes(selected.read_bytes())
                    replacement.chmod(selected.stat().st_mode & 0o777)
                    backup = selected.with_name(selected.name + ".displaced")
                    selected.rename(backup)
                    replacement.replace(selected)
                    held = (admission.source if selected == self.source else
                            admission.manifest if selected == self.manifest else admission.receipt)
                    self.assertEqual(os.fstat(held.fd).st_nlink, 1)
                    self.assertEqual(backup.stat().st_ino, os.fstat(held.fd).st_ino)
                    self.assertNotEqual(selected.stat().st_ino, backup.stat().st_ino)
                    return expected
                with self.assertRaisesRegex(ValueError, "input-changed"):
                    subject.finish(admission, graph, expected)
                self.assertFalse(admission.owner._exit_callbacks)
                self.assertEqual(admission.deadline_ns, admission.facts()["original_seed_deadline_monotonic_ns"])
        self.assertEqual(list(self.outputs.iterdir()), [])

    def test_actual_main_close_expiry_refuses_without_success_marker_or_clock_reset(self):
        admission = self.admission()
        cutoff = admission.deadline_ns
        clock = time.monotonic_ns()
        actual_close = admission.close
        def close():
            nonlocal clock
            actual_close()
            clock = cutoff
        values = {"EPOCH": "12345678-1234-1234-1234-123456789abc",
                  "ENTRY_NS": str(admission.entry_ns), "DEADLINE_NS": str(cutoff),
                  "SOURCE": "a" * 40, "GRAPH": "b" * 64, "SOURCE_ROOT": str(self.root)}
        environment = {subject.PREFIX + name: value for name, value in values.items()}
        environment.update(OMUX_EXECUTION_GUARD="/synthetic-public-run/" + values["EPOCH"],
                           TEST_UNDECLARED_OUTPUTS_DIR=str(self.outputs))
        arguments = ["seed", "--archive", str(self.source), "--role", str(self.descriptor),
                     "--manifest", str(self.manifest), "--receipt", str(self.receipt)]
        output = io.StringIO()
        with patch.dict(os.environ, environment), patch.object(subject.sys, "argv", arguments), \
                patch.object(subject, "Admission", return_value=admission), \
                patch.object(admission, "close", side_effect=close), \
                patch.object(runtime.time, "monotonic_ns", side_effect=lambda: clock), \
                redirect_stdout(output), self.assertRaisesRegex(ValueError, "deadline"):
            subject.main()
        self.assertNotIn("OMUX_CODEX_OWNER_RUNTIME_PUBLIC_SEED_OK", output.getvalue())
        self.assertEqual(admission.deadline_ns, cutoff)
        self.assertEqual(self.source.stat().st_mode & 0o777, 0o644)

    def retention_fixture(self):
        import execution_guard as guard
        state = self.root / "retention-state"
        state.mkdir(mode=0o700)
        run = state / "12345678-1234-1234-1234-123456789abc"
        run.mkdir(mode=0o700)
        output_base = run / "output-base"
        output_base.mkdir(mode=0o700)
        relative = Path("execroot/_main/bazel-out/k8-fastbuild/testlogs/tools/codex_owner_runtime_input_seed/test.outputs")
        products = output_base / relative
        products.mkdir(parents=True, mode=0o700)
        runtime.copy_retained(self.source, self.manifest, self.receipt, products,
                              time.monotonic_ns() + 20 * 10**9)
        retirement = guard.RunRetirement(state, run)
        self.owner.callback(retirement.close)
        fd_slot = subject.register_fd(self.owner)
        fd_slot.fd = os.open(output_base, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        manifest = {"results": [{"target": subject.LABEL, "state": "observed",
                    "configuration": "k8-fastbuild", "files": [
                        {"source": "test.log", "state": "copied", "bytes": 1}]}]}
        # This is a tiny real writer output, not the real archive: only the
        # bounded fixed path digest is substituted for the physical model.
        members = ("codex-owner-runtime-input-receipt.json", runtime.ARCHIVE_SHA + "/" + runtime.NAME)
        self.owner.enter_context(patch.dict(guard.RETAINED_OUTPUT_PRODUCTS, {subject.LABEL: members}))
        self.owner.enter_context(patch.dict(guard.RETAINED_OUTPUT_ALTERNATIVES, {subject.LABEL: (members,)}))
        return guard, retirement, fd_slot.fd, manifest, products, relative

    def test_actual_retention_accepts_top_level_receipt_and_nested_leaf_with_full_root_join(self):
        guard, retirement, directory, manifest, products, _ = self.retention_fixture()
        self.assertTrue(retirement.producer_ready(directory, subject.LABEL, manifest))
        self.assertEqual(set((products / runtime.ARCHIVE_SHA).iterdir()),
                         {products / runtime.ARCHIVE_SHA / runtime.NAME})
        self.assertEqual((products / runtime.ARCHIVE_SHA / runtime.NAME).stat().st_mode & 0o777, 0o400)

    def test_actual_retention_receipt_replacement_during_fsync_refuses_held_named_leaf(self):
        guard, retirement, directory, manifest, products, _ = self.retention_fixture()
        receipt = products / "codex-owner-runtime-input-receipt.json"
        original_inode = receipt.stat().st_ino
        actual = os.fsync
        mutated = False
        def fsync(fd):
            nonlocal mutated
            actual(fd)
            if not mutated and os.fstat(fd).st_ino == original_inode:
                mutated = True
                replacement = products / "replacement"
                replacement.write_bytes(receipt.read_bytes())
                replacement.chmod(receipt.stat().st_mode & 0o777)
                replacement.replace(receipt)
        with patch.object(guard.os, "fsync", side_effect=fsync):
            self.assertFalse(retirement.producer_ready(directory, subject.LABEL, manifest))
        self.assertTrue(mutated)
        self.assertNotEqual(receipt.stat().st_ino, original_inode)

    def test_actual_retention_final_named_outputs_root_replacement_refuses(self):
        guard, retirement, directory, manifest, products, _ = self.retention_fixture()
        actual = os.stat
        named_root_reads = 0
        changed = False
        def stat_selected(path, *args, **kwargs):
            nonlocal named_root_reads, changed
            if path == "test.outputs" and kwargs.get("dir_fd") is not None:
                named_root_reads += 1
                if named_root_reads == 3:
                    prior = products.with_name("prior-outputs")
                    products.rename(prior)
                    products.mkdir(mode=0o700)
                    changed = True
            return actual(path, *args, **kwargs)
        with patch.object(guard.os, "stat", side_effect=stat_selected):
            self.assertFalse(retirement.producer_ready(directory, subject.LABEL, manifest))
        self.assertTrue(changed)
        self.assertEqual(named_root_reads, 3)

    def test_all_retention_variant_registration_faults_drain_real_fds_before_and_after_insert(self):
        guard, retirement, directory, manifest, products, relative = self.retention_fixture()
        actual_callback = ExitStack.callback
        count = 0
        def observe(owner, *args, **kwargs):
            nonlocal count
            count += 1
            return actual_callback(owner, *args, **kwargs)
        with patch.object(ExitStack, "callback", new=observe):
            self.assertTrue(retirement.producer_ready(directory, subject.LABEL, manifest))
        self.assertGreater(count, len(relative.parts))
        actual_close = os.close
        for cleanup_fault in (False, True):
            for after in (False, True):
                for index in range(1, count + 1):
                    with self.subTest(after_insert=after, registration=index, cleanup_fault=cleanup_fault):
                        before = len(os.listdir("/proc/self/fd"))
                        primary = MemoryError("synthetic-retention-registration-failure")
                        calls = 0
                        closed = 0
                        failed = False
                        def register(owner, *args, **kwargs):
                            nonlocal calls, failed
                            calls += 1
                            if calls == index and not after:
                                failed = True
                                raise primary
                            result = actual_callback(owner, *args, **kwargs)
                            if calls == index and after:
                                failed = True
                                raise primary
                            return result
                        def close(fd):
                            nonlocal closed
                            actual_close(fd)
                            if failed:
                                closed += 1
                            if cleanup_fault and failed and closed == 1:
                                raise OSError("synthetic-retention-close-after-release")
                        with patch.object(ExitStack, "callback", new=register), \
                                patch.object(guard.os, "close", side_effect=close), \
                                self.assertRaises(MemoryError) as raised:
                            retirement.producer_ready(directory, subject.LABEL, manifest)
                        self.assertIs(raised.exception, primary)
                        self.assertEqual(calls, index)
                        self.assertEqual(len(os.listdir("/proc/self/fd")), before)
        self.assertTrue(retirement.producer_ready(directory, subject.LABEL, manifest))



    def test_actual_retirement_context_normal_and_failure_exit_attempt_all_real_fd_closes(self):
        import execution_guard as guard
        actual_close = os.close
        for body_fault in (False, True):
            for cleanup_fault in (False, True):
                with self.subTest(body_fault=body_fault, cleanup_fault=cleanup_fault):
                    before = len(os.listdir("/proc/self/fd"))
                    primary = MemoryError("synthetic-retirement-body-failure")
                    cleanup = OSError("synthetic-retirement-close-after-release")
                    closed = []
                    opened = []
                    def close(fd):
                        actual_close(fd)
                        closed.append(fd)
                        if cleanup_fault and len(closed) == 1:
                            raise cleanup
                    caught = None
                    try:
                        with patch.object(guard.os, "close", side_effect=close):
                            with guard.RetirementResources() as owner:
                                for _ in range(2):
                                    opened.append(guard.retirement_owned_fd(owner, lambda: os.open(
                                        self.source, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)))
                                if body_fault:
                                    raise primary
                    except BaseException as error:
                        caught = error
                    if body_fault:
                        self.assertIs(caught, primary)
                        if cleanup_fault:
                            self.assertIn("retirement-product-cleanup-refused", primary.__notes__)
                    elif cleanup_fault:
                        self.assertIs(caught, cleanup)
                    else:
                        self.assertIsNone(caught)
                    self.assertEqual(closed, list(reversed(opened)))
                    self.assertEqual(len(closed), 2)
                    self.assertEqual(len(set(closed)), 2)
                    self.assertEqual(len(os.listdir("/proc/self/fd")), before)


if __name__ == "__main__":
    unittest.main()
