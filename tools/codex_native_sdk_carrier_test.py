"""Real small SDK/registry/JDK bytes and carrier/NAR/custody adversarial models.

The only SDK seam is the synthetic selected JDK root. Existing SDK validators,
registry/module/link-absence logic, byte readers and canonical NAR run unchanged.
No model claims a genuine carrier producer, metadata or application qualification.
"""
from contextlib import closing, contextmanager, ExitStack, redirect_stderr
import copy
import io
import json
import os
import pickle
from pathlib import Path
import re
import shutil
import stat
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

import codex_native_sdk_carrier as carrier
import codex_retained_sdk_export as sdk


class CarrierModels(unittest.TestCase):
    @contextmanager
    def copy_fixture(self, name, count=6):
        clock = carrier.Clock(self.deadline)
        output = carrier.Output(self.root / name, clock)
        output.mkdir("sdk")
        output.mkdir("sdk/batch")
        values = [b"", b"1", b"seven77", b"eight888", b"c" * 65536, b"l" * 65537]
        values = [values[index % len(values)] for index in range(count)]
        path = self.root / (name + "-payload")
        self.write(path, b"".join(values))
        payload = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        witness, files, offset = carrier.identity(os.fstat(payload)), {}, 0
        for index, raw in enumerate(values):
            files[("sdk", "batch/f" + str(index))] = {"offset": offset, "size": len(raw),
                "sha256": carrier.sha(raw), "mode": 0o555 if index % 2 else 0o444}
            offset += len(raw)
        accepted = []
        def accept(name, selected, size):
            output.materialized[name] = selected
            accepted.append((name, selected, size, threading.get_ident()))
        try:
            yield output, payload, witness, files, clock, accept, accepted, values
        finally:
            os.close(payload)
            output.close()

    def test_two_copy_workers_overlap_with_two_jobs_owner_authority_and_complete_fsync(self):
        with self.copy_fixture("workers-overlap", 8) as case:
            output, payload, witness, files, clock, accept, accepted, values = case
            owner = threading.get_ident()
            lock, barrier = threading.Lock(), threading.Barrier(2)
            worker_ids, worker_threads, active, peaks, parents, captured, fsynced = set(), set(), [0], [0, 0, 0], set(), [], set()
            real_job, real_queue = carrier._copy_regular_job, carrier.Queue
            real_open, real_dup, real_fsync, real_chmod = os.open, os.dup, os.fsync, os.fchmod
            real_check, real_parent, real_keep = carrier.Root.check, carrier.Root._parent, carrier._ParentHandles.keep
            outstanding = [0]
            queues = []
            class BoundedQueue(real_queue):
                def __init__(queue, *args, **kwargs):
                    super().__init__(*args, **kwargs)
                    queues.append(queue)
                    self.assertEqual(queue.maxsize, 2)
                def put_nowait(queue, item):
                    if queue is queues[0]:
                        self.assertEqual(threading.get_ident(), owner)
                        with lock:
                            outstanding[0] += 1
                            peaks[1] = max(peaks[1], outstanding[0])
                    return super().put_nowait(item)
            def accepted_copy(*args):
                accept(*args)
                with lock: outstanding[0] -= 1
            def job(state, parent, *args):
                with lock:
                    active[0] += 1
                    peaks[0] = max(peaks[0], active[0])
                    worker_ids.add(threading.get_ident())
                    worker_threads.add(threading.current_thread())
                    parents.add(parent)
                try:
                    barrier.wait(5)
                    return real_job(state, parent, *args)
                finally:
                    with lock:
                        active[0] -= 1
                        parents.remove(parent)
            def checked(root):
                self.assertEqual(threading.get_ident(), owner)
                return real_check(root)
            def parent(root, *args):
                self.assertEqual(threading.get_ident(), owner)
                return real_parent(root, *args)
            def keep(handles, *args):
                self.assertEqual(threading.get_ident(), owner)
                result = real_keep(handles, *args)
                peaks[2] = max(peaks[2], len(handles.entries))
                return result
            def opened(*args, **kwargs):
                fd = real_open(*args, **kwargs)
                with lock: captured.append(fd)
                return fd
            def duplicated(fd):
                copy = real_dup(fd)
                with lock: captured.append(copy)
                return copy
            def fsync(fd):
                with lock: fsynced.add(tuple(carrier.identity(os.fstat(fd), True)[:2]))
                return real_fsync(fd)
            def chmod(fd, mode):
                self.assertIn(tuple(carrier.identity(os.fstat(fd), True)[:2]), fsynced)
                return real_chmod(fd, mode)
            with patch.object(carrier, "Queue", BoundedQueue), patch.object(carrier, "_copy_regular_job", job), \
                    patch.object(carrier.Root, "check", checked), patch.object(carrier.Root, "_parent", parent), \
                    patch.object(carrier._ParentHandles, "keep", keep), patch.object(carrier.os, "open", opened), \
                    patch.object(carrier.os, "dup", duplicated), patch.object(carrier.os, "fsync", fsync), \
                    patch.object(carrier.os, "fchmod", chmod):
                carrier._copy_regulars(output, payload, witness, files, clock, accepted_copy)
            self.assertEqual(peaks[:2], [2, 2])
            self.assertLessEqual(peaks[2], 32)
            self.assertEqual(len(worker_ids), 2)
            self.assertNotIn(owner, worker_ids)
            self.assertTrue(all(not thread.is_alive() for thread in worker_threads))
            self.assertEqual((active[0], outstanding[0], parents), (0, 0, set()))
            self.assertEqual(len(accepted), len(values))
            self.assertEqual(len(fsynced), len(values))
            for index, (name, selected, size, thread) in enumerate(accepted):
                leaf = output.path / name
                self.assertEqual((leaf.read_bytes(), size, thread), (values[index], len(values[index]), owner))
                self.assertEqual(carrier.identity(leaf.stat()), selected)
                self.assertEqual(stat.S_IMODE(leaf.stat().st_mode), files[("sdk", "batch/f" + str(index))]["mode"])
            self.assert_descriptors_closed(set(captured))
            os.fstat(payload)
            output.root.check()

    def test_two_copy_workers_first_io_failure_cancels_joins_before_parent_close(self):
        with self.copy_fixture("workers-first-error", 6) as case:
            output, payload, witness, files, clock, accept, accepted, _ = case
            blocked, release, failed = threading.Event(), threading.Event(), threading.Event()
            lock, live, parents, states, targets, submitted = threading.Lock(), [0], set(), [], [], [0]
            real_job, real_queue, real_read, real_fsync, real_close = carrier._copy_regular_job, carrier.Queue, os.pread, os.fsync, os.close
            queues = []
            class BoundedQueue(real_queue):
                def __init__(queue, *args, **kwargs):
                    super().__init__(*args, **kwargs)
                    queues.append(queue)
                def put_nowait(queue, item):
                    if queue is queues[0]: submitted[0] += 1
                    return super().put_nowait(item)
            def job(state, parent, *args):
                with lock:
                    live[0] += 1
                    parents.add(parent)
                    states.append(state)
                try: return real_job(state, parent, *args)
                finally:
                    with lock:
                        live[0] -= 1
                        parents.remove(parent)
            def read(fd, size, offset):
                self.assertTrue(blocked.wait(5))
                failed.set()
                raise OSError("first actual copy read refusal")
            def fsync(fd):
                targets.append(fd)
                blocked.set()
                self.assertTrue(release.wait(5))
                return real_fsync(fd)
            def close(fd):
                with lock: self.assertNotIn(fd, parents, "owner closed a running worker parent")
                return real_close(fd)
            controller_errors = []
            def unblock():
                try:
                    self.assertTrue(failed.wait(5))
                    self.assertTrue(states[0].cancel.wait(5))
                except BaseException as error:
                    controller_errors.append(error)
                finally:
                    release.set()
            controller = threading.Thread(target=unblock)
            controller.start()
            try:
                with patch.object(carrier, "Queue", BoundedQueue), patch.object(carrier, "_copy_regular_job", job), \
                        patch.object(carrier.os, "pread", read), patch.object(carrier.os, "fsync", fsync), \
                        patch.object(carrier.os, "close", close):
                    with self.assertRaisesRegex(OSError, "first actual copy read refusal"):
                        carrier._copy_regulars(output, payload, witness, files, clock, accept)
            finally:
                release.set()
                controller.join()
            self.assertEqual(controller_errors, [])
            self.assertTrue(failed.is_set())
            self.assertEqual((live[0], parents, accepted), (0, set(), []))
            self.assertEqual(submitted[0], 2)
            self.assert_descriptors_closed(targets)
            output.root.check()
            os.fstat(payload)

    def test_two_copy_workers_enqueue_interruption_preserves_parent_leases_until_join(self):
        with self.copy_fixture("workers-submit") as case:
            output, payload, witness, files, clock, accept, accepted, _ = case
            real_queue, real_job = carrier.Queue, carrier._copy_regular_job
            submitted, parents, queues, workers = [0], [], [], set()
            class BoundedQueue(real_queue):
                def __init__(queue, *args, **kwargs):
                    super().__init__(*args, **kwargs)
                    queues.append(queue)
                def put_nowait(queue, item):
                    if queue is queues[0]:
                        submitted[0] += 1
                        parents.append(item[1][0])
                        result = super().put_nowait(item)
                        if submitted[0] == 2: raise RuntimeError("model post-enqueue refusal")
                        return result
                    return super().put_nowait(item)
            def job(*args):
                workers.add(threading.current_thread())
                return real_job(*args)
            with patch.object(carrier, "Queue", BoundedQueue), patch.object(carrier, "_copy_regular_job", job):
                with self.assertRaisesRegex(RuntimeError, "model post-enqueue refusal"):
                    carrier._copy_regulars(output, payload, witness, files, clock, accept)
            self.assertEqual(accepted, [])
            self.assertEqual(submitted[0], 2)
            self.assertTrue(all(not worker.is_alive() for worker in workers))
            self.assert_descriptors_closed(parents)
            os.fstat(payload)
            output.root.check()

    def test_two_copy_workers_retry_interrupted_join_then_refuse_without_late_success(self):
        with self.copy_fixture("workers-join", 2) as case:
            output, payload, witness, files, clock, accept, accepted, _ = case
            real_join, joins = threading.Thread.join, [0]
            def join(worker, *args, **kwargs):
                joins[0] += 1
                if joins[0] == 1: raise KeyboardInterrupt("model join interruption")
                return real_join(worker, *args, **kwargs)
            with patch.object(carrier.threading.Thread, "join", join):
                with self.assertRaisesRegex(KeyboardInterrupt, "model join interruption"):
                    carrier._copy_regulars(output, payload, witness, files, clock, accept)
            self.assertEqual(joins[0], 3)
            self.assertEqual(len(accepted), 2)
            os.fstat(payload)
            output.root.check()

    def test_two_copy_workers_failed_start_admits_no_descriptors_and_preserves_unknown_outcome(self):
        real_start = threading.Thread.start
        for launched in (False, True):
            with self.subTest(launched=launched), self.copy_fixture("workers-start-" + str(launched), 2) as case:
                output, payload, witness, files, clock, accept, accepted, _ = case
                attempts, threads, jobs, ready = [0], [], [], []
                real_worker = carrier._copy_worker
                def worker(*args):
                    ready.append(threading.current_thread())
                    return real_worker(*args)
                def start(thread):
                    threads.append(thread)
                    attempts[0] += 1
                    if attempts[0] == 2:
                        if launched: real_start(thread)
                        raise KeyboardInterrupt("model interrupted bootstrap")
                    return real_start(thread)
                def job(*args):
                    jobs.append(args)
                    self.fail("copy capability admitted after failed start")
                with patch.object(carrier.threading.Thread, "start", start), \
                        patch.object(carrier, "_copy_worker", worker), patch.object(carrier, "_copy_regular_job", job):
                    with self.assertRaisesRegex(KeyboardInterrupt, "model interrupted bootstrap") as caught:
                        carrier._copy_regulars(output, payload, witness, files, clock, accept)
                self.assertEqual((attempts[0], jobs, accepted), (2, [], []))
                self.assertFalse(threads[0].is_alive())
                if launched:
                    self.assertFalse(threads[1].is_alive())
                else:
                    self.assertIn("copy-worker-start-outcome-unknown", caught.exception.__notes__)
                self.assertEqual(list((output.path / "sdk/batch").iterdir()), [])
                output.root.check()
                os.fstat(payload)

    def test_two_copy_workers_actual_late_bootstrap_has_no_copy_capability_after_unknown_start(self):
        with self.copy_fixture("workers-late-bootstrap", 2) as case:
            output, payload, witness, files, clock, accept, accepted, _ = case
            launched, release = threading.Event(), threading.Event()
            real_start, real_inner = threading.Thread.start, threading.Thread._bootstrap_inner
            callers, late_workers, controller_errors, copied = [], [], [], []
            def inner(worker):
                if worker.name == "sdk-copy-1":
                    launched.set()
                    if not release.wait(5): controller_errors.append("late bootstrap release missing")
                return real_inner(worker)
            def start(worker):
                if worker.name != "sdk-copy-1": return real_start(worker)
                late_workers.append(worker)
                # The real start waits for _started while its actual OS thread
                # is alive but deliberately delayed before that event is set.
                caller = threading.Thread(target=lambda: real_start(worker), name="model-bootstrap-caller")
                callers.append(caller)
                real_start(caller)
                self.assertTrue(launched.wait(5))
                raise KeyboardInterrupt("model unknown OS-start outcome")
            try:
                with patch.object(carrier.threading.Thread, "start", start), \
                        patch.object(carrier.threading.Thread, "_bootstrap_inner", inner), \
                        patch.object(carrier, "_copy_regular_job", side_effect=lambda *args: copied.append(args)):
                    with self.assertRaisesRegex(KeyboardInterrupt, "unknown OS-start outcome") as caught:
                        carrier._copy_regulars(output, payload, witness, files, clock, accept)
                    self.assertIn("copy-worker-start-outcome-unknown", caught.exception.__notes__)
                    self.assertEqual((copied, accepted), ([], []))
                    self.assertEqual(list((output.path / "sdk/batch").iterdir()), [])
                    release.set()
                    for caller in callers: caller.join()
                    for worker in late_workers: worker.join()
                    self.assertTrue(all(not worker.is_alive() for worker in late_workers))
                    self.assertEqual(copied, [])
            finally:
                release.set()
                for caller in callers: caller.join()
                for worker in late_workers: worker.join()
            self.assertEqual(controller_errors, [])
            output.root.check()
            os.fstat(payload)

    def test_two_copy_workers_delayed_ready_expires_before_any_copy_capability(self):
        with self.copy_fixture("workers-ready", 2) as case:
            output, payload, witness, files, clock, accept, accepted, _ = case
            real_worker, entered = carrier._copy_worker, []
            def worker(state, jobs, results, gate, ready, stop):
                entered.append(threading.current_thread())
                # A real started worker delays its own ready signal, without
                # borrowing physical capabilities; expiry wakes it only to exit.
                if threading.current_thread().name.endswith("1"):
                    clock.deadline = time.monotonic() - 1
                    self.assertTrue(stop.wait(5))
                return real_worker(state, jobs, results, gate, ready, stop)
            with patch.object(carrier, "_copy_worker", worker), \
                    patch.object(carrier, "_copy_regular_job", side_effect=AssertionError("unexpected physical dispatch")):
                with self.assertRaisesRegex(ValueError, "deadline"):
                    carrier._copy_regulars(output, payload, witness, files, clock, accept)
            self.assertEqual(accepted, [])
            self.assertEqual(list((output.path / "sdk/batch").iterdir()), [])
            self.assertTrue(all(not thread.is_alive() for thread in entered))
            os.fstat(payload)

    def test_two_copy_workers_late_leaf_parent_root_and_alias_mutations_refuse_owner_acceptance(self):
        real = carrier._copy_regular_job
        for change in ("inode", "mode", "chmod-restored", "mtime-restored", "bytes", "symlink", "hardlink", "parent", "root", "alias"):
            with self.subTest(change=change), self.copy_fixture("workers-mutation-" + change, 2) as case:
                output, payload, witness, files, clock, accept, accepted, _ = case
                lock, changed = threading.Lock(), [False]
                def mutate(state, parent, leaf, *args):
                    result = real(state, parent, leaf, *args)
                    if leaf == "f0":
                        with lock:
                            changed[0] = True
                            selected = output.path / "sdk/batch/f0"
                            info = selected.stat()
                            if change in ("parent", "alias"):
                                batch = output.path / "sdk/batch"
                                batch.rename(output.path / "sdk/old-batch")
                                if change == "parent": batch.mkdir(mode=0o700)
                                else: batch.symlink_to(output.path / "sdk/old-batch", target_is_directory=True)
                            elif change == "root":
                                output.path.rename(output.path.with_name(output.path.name + "-aside"))
                                output.path.mkdir(mode=0o700)
                            elif change in ("inode", "symlink"):
                                selected.unlink()
                                if change == "inode": self.write(selected, b"")
                                else: selected.symlink_to(self.root / "unselected-target")
                            elif change == "hardlink": os.link(selected, self.root / "workers-foreign-hardlink")
                            elif change == "mode": selected.chmod(0o555)
                            elif change == "bytes":
                                selected.chmod(0o600); selected.write_bytes(b"unexpected"); selected.chmod(0o444)
                            elif change == "mtime-restored":
                                selected.chmod(0o600); selected.write_bytes(b"")
                                os.utime(selected, ns=(info.st_atime_ns, info.st_mtime_ns)); selected.chmod(0o444)
                            else: selected.chmod(0o600); selected.chmod(0o444)
                    return result
                with patch.object(carrier, "_copy_regular_job", mutate):
                    with self.assertRaises(ValueError):
                        carrier._copy_regulars(output, payload, witness, files, clock, accept)
                self.assertTrue(changed[0])
                self.assertEqual(accepted, [])

    def test_two_copy_workers_foreign_parent_and_exclusive_name_refuse(self):
        for change in ("foreign", "existing", "symlink", "duplicate"):
            with self.subTest(change=change), self.copy_fixture("workers-foreign-" + change, 2) as case:
                output, payload, witness, files, clock, accept, accepted, _ = case
                real = carrier._copy_regular_job
                foreign = self.root / ("foreign-parent-" + change)
                foreign.mkdir(mode=0o700)
                fd = os.open(foreign, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
                def substituted(state, parent, leaf, selected, *args):
                    return real(state, fd, leaf, selected, *args)
                if change == "existing": self.write(output.path / "sdk/batch/f0", b"already here")
                elif change == "symlink": (output.path / "sdk/batch/f0").symlink_to(foreign / "never-follow")
                elif change == "duplicate":
                    class Entries(dict):
                        def items(unused): return [(('sdk', 'batch/f0'), files[('sdk', 'batch/f0')])] * 2
                    files = Entries(files)
                try:
                    with ExitStack() as stack:
                        if change == "foreign": stack.enter_context(patch.object(carrier, "_copy_regular_job", substituted))
                        with self.assertRaises((ValueError, OSError)):
                            carrier._copy_regulars(output, payload, witness, files, clock, accept)
                    self.assertFalse(list(foreign.iterdir()))
                finally: os.close(fd)

    def test_two_copy_workers_actual_byte_digest_extent_mode_and_fsync_failures_refuse(self):
        for boundary in ("digest", "truncated", "write", "fsync", "chmod"):
            with self.subTest(boundary=boundary), self.copy_fixture("workers-io-" + boundary, 2) as case:
                output, payload, witness, files, clock, accept, accepted, _ = case
                if boundary == "digest": files[("sdk", "batch/f0")]["sha256"] = "f" * 64
                elif boundary == "truncated": files[("sdk", "batch/f1")]["size"] += 1
                with ExitStack() as stack:
                    if boundary == "write": stack.enter_context(patch.object(carrier.os, "write", side_effect=OSError("write refused")))
                    elif boundary == "fsync": stack.enter_context(patch.object(carrier.os, "fsync", side_effect=OSError("fsync refused")))
                    elif boundary == "chmod": stack.enter_context(patch.object(carrier.os, "fchmod", side_effect=OSError("chmod refused")))
                    with self.assertRaises((ValueError, OSError)):
                        carrier._copy_regulars(output, payload, witness, files, clock, accept)
                self.assertLess(len(accepted), 2)

    def test_two_copy_workers_partial_writes_preserve_each_actual_digest_and_fsync(self):
        with self.copy_fixture("workers-partial-write", 6) as case:
            output, payload, witness, files, clock, accept, accepted, values = case
            real_write, real_fsync, counts = os.write, os.fsync, []
            def short(fd, raw): return real_write(fd, raw[:17])
            def fsync(fd): counts.append(tuple(carrier.identity(os.fstat(fd), True)[:2])); return real_fsync(fd)
            with patch.object(carrier.os, "write", short), patch.object(carrier.os, "fsync", fsync):
                carrier._copy_regulars(output, payload, witness, files, clock, accept)
            self.assertEqual(len(set(counts)), 6)
            self.assertEqual([row[2] for row in accepted], [len(raw) for raw in values])
            for index, raw in enumerate(values): self.assertEqual((output.path / ("sdk/batch/f" + str(index))).read_bytes(), raw)

    def test_two_copy_workers_original_float_integer_and_blocked_fsync_expiry_join(self):
        for boundary in ("pre", "read", "fsync"):
            with self.subTest(boundary=boundary), self.copy_fixture("workers-clock-" + boundary, 2) as case:
                output, payload, witness, files, clock, accept, accepted, _ = case
                original_until = time.monotonic_ns() + 10**9
                clock.until_ns = original_until
                real_read, real_fsync, calls = os.pread, os.fsync, []
                def read(*args):
                    result = real_read(*args)
                    clock.until_ns = time.monotonic_ns() - 1
                    return result
                blocked, release = threading.Event(), threading.Event()
                def fsync(fd):
                    calls.append(fd); blocked.set()
                    self.assertTrue(release.wait(5))
                    return real_fsync(fd)
                controller_errors = []
                def expire():
                    try:
                        self.assertTrue(blocked.wait(5))
                        clock.until_ns = time.monotonic_ns() - 1
                    except BaseException as error:
                        controller_errors.append(error)
                    finally:
                        release.set()
                if boundary == "pre": clock.deadline = time.monotonic() - 1
                controller = threading.Thread(target=expire) if boundary == "fsync" else None
                if controller: controller.start()
                try:
                    with ExitStack() as stack:
                        if boundary == "read": stack.enter_context(patch.object(carrier.os, "pread", read))
                        elif boundary == "fsync": stack.enter_context(patch.object(carrier.os, "fsync", fsync))
                        with self.assertRaisesRegex(ValueError, "deadline"):
                            carrier._copy_regulars(output, payload, witness, files, clock, accept)
                finally:
                    release.set()
                    if controller: controller.join()
                self.assertEqual(controller_errors, [])
                if boundary == "read":
                    self.assertLessEqual(len(accepted), 1)
                    if accepted: self.assertEqual((accepted[0][0], accepted[0][2]), ("sdk/batch/f0", 0))
                else:
                    self.assertEqual(accepted, [])
                if boundary == "fsync":
                    self.assertTrue(calls)
                    self.assert_descriptors_closed(calls)
                os.fstat(payload)

    def test_two_copy_workers_owned_payload_mutation_refuses_with_no_completed_marker(self):
        root, _, pin = self.seal("workers-held-payload")
        real, changed = carrier._copy_regular_job, [False]
        lock = threading.Lock()
        def mutate(*args):
            result = real(*args)
            with lock:
                if not changed[0]:
                    changed[0] = True
                    payload = root / "payload.bin"
                    payload.chmod(0o600)
                    raw = payload.read_bytes(); payload.write_bytes(raw); payload.chmod(0o444)
            return result
        output, emitted = self.root / "workers-held-output", io.StringIO()
        with redirect_stderr(emitted), patch.object(carrier, "_copy_regular_job", mutate):
            with self.assertRaises(ValueError): carrier.extract(root, pin, output, self.deadline)
        self.assertTrue(changed[0])
        self.assertFalse((output / "extraction-receipt.json").exists())
        self.assertIn("copy-refused", emitted.getvalue())
        self.assertNotIn("copy-complete", emitted.getvalue())
        self.assertNotIn("final-proof-complete", emitted.getvalue())

    def fresh_fixture(self, name):
        parent = self.root / name
        parent.mkdir(mode=0o700)
        values = {("sdk", "empty"): b"", ("sdk", "one"): b"1", ("sdk", "seven"): b"7" * 7,
            ("sdk", "eight"): b"8" * 8, ("sdk", "nine"): b"9" * 9,
            ("sdk", "chunk"): b"c" * 65536, ("sdk", "long"): b"l" * 65537,
            ("sdk", "a/child"): b"directory child", ("sdk", "a-"): b"flat sibling",
            ("sdk", "z"): b"z", ("sdk", "é"): b"utf8", ("jdk", "first"): b"first role"}
        expected = {}
        for role in ("sdk", "jdk"):
            (parent / role).mkdir(mode=0o700)
            expected[(role, "")] = {"kind": "directory", "mode": 0o555}
        (parent / "sdk/a").mkdir(mode=0o700)
        expected[("sdk", "a")] = {"kind": "directory", "mode": 0o555}
        for (role, path), raw in values.items():
            mode = 0o555 if path == "nine" else 0o444
            self.write(parent / role / path, raw, mode)
            expected[(role, path)] = {"kind": "file", "mode": mode, "size": len(raw), "sha256": carrier.sha(raw)}
        (parent / "sdk/inert").symlink_to("/unselected-external-target/must-not-be-opened")
        expected[("sdk", "inert")] = {"kind": "symlink", "target": "/unselected-external-target/must-not-be-opened"}
        self.seal_dirs(parent / "sdk")
        self.seal_dirs(parent / "jdk")
        return parent, expected, values

    def fresh_roots(self, parent, clock, stack):
        return {role: stack.enter_context(carrier.Root(parent / role, clock)) for role in ("sdk", "jdk")}

    def test_fused_real_stream_matches_full_scan_nar_with_one_read_and_eof_per_file(self):
        parent, expected, values = self.fresh_fixture("fusion-golden")
        clock = carrier.Clock(self.deadline)
        real = carrier._FreshNarFile.read
        reads = []
        def record(stream, size=-1):
            block = real(stream, size)
            reads.append((stream.key, size, len(block)))
            return block
        with ExitStack() as stack:
            roots = self.fresh_roots(parent, clock, stack)
            observed, witnesses = carrier.scan(roots, expected, clock)
            nars = carrier.nar_origins(roots, expected, clock)
            with patch.object(carrier._FreshNarFile, "read", record):
                fused, held, actual = carrier._scan_nar(roots, expected, clock)
            self.assertEqual((fused, held, actual), (observed, witnesses, nars))
        for key, raw in values.items():
            selected = [(size, count) for which, size, count in reads if which == key]
            self.assertEqual(sum(count for _, count in selected), len(raw))
            self.assertEqual(sum(count == 0 for _, count in selected), 1)
            self.assertEqual(selected[-1], (1, 0))
            self.assertTrue(all(0 < size <= 65536 for size, _ in selected))
        order = [key for key, _, count in reads if count and key[0] == "sdk"]
        self.assertLess(order.index(("sdk", "a/child")), order.index(("sdk", "a-")))
        self.assertLess(order.index(("sdk", "z")), order.index(("sdk", "é")))
        self.assertEqual(values[("sdk", "empty")], b"")

    def test_fused_wrong_selected_digest_refuses_actual_bytes(self):
        parent, expected, _ = self.fresh_fixture("fusion-hash")
        expected[("sdk", "seven")]["sha256"] = "f" * 64
        clock = carrier.Clock(self.deadline)
        with ExitStack() as stack:
            roots = self.fresh_roots(parent, clock, stack)
            with self.assertRaisesRegex(ValueError, "fresh-stream-content"):
                carrier._scan_nar(roots, expected, clock)

    def test_fused_size_mode_hardlink_symlink_and_special_file_refuse_before_read(self):
        for change in ("size", "mode", "hardlink", "symlink", "fifo"):
            with self.subTest(change=change):
                parent, expected, _ = self.fresh_fixture("fusion-type-" + change)
                leaf = parent / "sdk/seven"
                leaf.parent.chmod(0o700)
                if change == "size":
                    leaf.chmod(0o600); leaf.write_bytes(b"short"); leaf.chmod(0o444)
                elif change == "mode":
                    leaf.chmod(0o555)
                elif change == "hardlink":
                    os.link(leaf, self.root / ("external-hardlink-" + change))
                else:
                    leaf.unlink()
                    if change == "symlink": leaf.symlink_to(self.root / "never-follow")
                    else: os.mkfifo(leaf, 0o444)
                leaf.parent.chmod(0o555)
                clock = carrier.Clock(self.deadline)
                with ExitStack() as stack:
                    roots = self.fresh_roots(parent, clock, stack)
                    with patch.object(carrier._FreshNarFile, "read", side_effect=AssertionError("invalid namespace read")):
                        with self.assertRaises(ValueError):
                            carrier._scan_nar(roots, expected, clock)

    def test_fused_custom_opener_restores_owner_executable_check(self):
        parent, expected, _ = self.fresh_fixture("fusion-executable")
        leaf = parent / "sdk/seven"
        leaf.chmod(0o454)
        expected[("sdk", "seven")]["mode"] = 0o454
        clock = carrier.Clock(self.deadline)
        with ExitStack() as stack:
            roots = self.fresh_roots(parent, clock, stack)
            with self.assertRaisesRegex(ValueError, "fresh-stream-executable"):
                carrier._scan_nar(roots, expected, clock)

    def test_fused_read_mutation_truncation_growth_and_fd_cleanup_refuse(self):
        real = carrier._FreshNarFile.read
        for change in ("bytes", "truncate", "grow"):
            with self.subTest(change=change):
                parent, expected, _ = self.fresh_fixture("fusion-read-" + change)
                clock = carrier.Clock(self.deadline)
                descriptors, changed = [], [False]
                def mutate(stream, size=-1):
                    if stream.key == ("sdk", "long"):
                        descriptors.extend((stream.fd, stream.parent))
                    block = real(stream, size)
                    if stream.key == ("sdk", "long") and block and not changed[0]:
                        changed[0] = True
                        leaf = parent / "sdk/long"
                        leaf.chmod(0o600)
                        with leaf.open("r+b") as out:
                            if change == "truncate": out.truncate(1)
                            elif change == "grow": out.seek(0, 2); out.write(b"extra")
                            else: out.seek(0); out.write(b"changed")
                        leaf.chmod(0o444)
                    return block
                with ExitStack() as stack:
                    roots = self.fresh_roots(parent, clock, stack)
                    with patch.object(carrier._FreshNarFile, "read", mutate):
                        with self.assertRaises(ValueError):
                            carrier._scan_nar(roots, expected, clock)
                self.assertTrue(changed[0])
                self.assert_descriptors_closed(set(descriptors))

    def test_fused_final_namespace_revisits_earlier_role_after_all_reads(self):
        original = carrier._FreshNarFile.__init__
        for change in ("inode", "chmod-restored", "mtime-restored", "link", "extra", "missing", "directory", "root", "alias"):
            with self.subTest(change=change):
                parent, expected, _ = self.fresh_fixture("fusion-late-" + change)
                clock = carrier.Clock(self.deadline)
                changed = [False]
                def mutate(stream, root, name, *args):
                    original(stream, root, name, *args)
                    if root.path.name == "sdk" and not changed[0]:
                        changed[0] = True
                        early = parent / "jdk/first"
                        if change in ("root", "alias"):
                            moved = parent / "old-jdk"
                            (parent / "jdk").rename(moved)
                            if change == "root": shutil.copytree(moved, parent / "jdk", symlinks=True)
                            else: (parent / "jdk").symlink_to(moved, target_is_directory=True)
                        elif change == "directory":
                            (parent / "sdk").chmod(0o700)
                            (parent / "sdk/a").rename(parent / "sdk/a-aside")
                            shutil.copytree(parent / "sdk/a-aside", parent / "sdk/a")
                            (parent / "sdk/a-aside").chmod(0o700)
                            (parent / "sdk/a-aside/child").unlink()
                            (parent / "sdk/a-aside").rmdir()
                            (parent / "sdk").chmod(0o555)
                        elif change == "link":
                            (parent / "sdk").chmod(0o700)
                            (parent / "sdk/inert").unlink()
                            (parent / "sdk/inert").symlink_to("/other-inert-target")
                            (parent / "sdk").chmod(0o555)
                        elif change in ("inode", "extra", "missing"):
                            (parent / "jdk").chmod(0o700)
                            if change == "inode":
                                raw = early.read_bytes(); early.unlink(); self.write(early, raw)
                            elif change == "extra": self.write(parent / "jdk/extra", b"extra")
                            else: early.unlink()
                            (parent / "jdk").chmod(0o555)
                        else:
                            info = early.stat()
                            early.chmod(0o600)
                            if change == "mtime-restored":
                                early.write_bytes(early.read_bytes())
                                os.utime(early, ns=(info.st_atime_ns, info.st_mtime_ns))
                            early.chmod(0o444)
                with ExitStack() as stack:
                    roots = self.fresh_roots(parent, clock, stack)
                    with patch.object(carrier._FreshNarFile, "__init__", mutate):
                        with self.assertRaises(ValueError):
                            carrier._scan_nar(roots, expected, clock)
                self.assertTrue(changed[0])

    def test_fused_entry_byte_depth_bounds_and_missing_protected_namespace_refuse(self):
        for change in ("entries", "bytes", "depth", "missing"):
            with self.subTest(change=change):
                parent, expected, _ = self.fresh_fixture("fusion-bound-" + change)
                clock = carrier.Clock(self.deadline)
                with ExitStack() as stack:
                    roots = self.fresh_roots(parent, clock, stack)
                    if change == "entries": stack.enter_context(patch.object(carrier, "MAX_ENTRIES", 1))
                    elif change == "bytes": stack.enter_context(patch.object(carrier, "MAX_BYTES", 1))
                    elif change == "depth": expected[("sdk", "../escape")] = expected[("sdk", "seven")]
                    else: del expected[("sdk", "seven")]
                    with self.assertRaises(ValueError):
                        carrier._scan_nar(roots, expected, clock)

    def test_fused_expiry_at_stream_eof_and_final_namespace_closes_all_resources(self):
        for boundary in ("pre", "read", "eof", "final", "integer"):
            with self.subTest(boundary=boundary):
                parent, expected, _ = self.fresh_fixture("fusion-clock-" + boundary)
                clock = carrier.Clock(self.deadline)
                clock.until_ns = self.context["work_cutoff_monotonic_ns"]
                now, nanos, descriptors = [self.deadline - 1], [clock.until_ns - 1], []
                real_read, real_close, real_namespace = carrier._FreshNarFile.read, carrier._FreshNarFile.close, carrier._fresh_namespace
                passes = [0]
                def read(stream, size=-1):
                    block = real_read(stream, size)
                    if boundary in ("read", "integer") or (boundary == "eof" and not block):
                        if boundary == "integer": nanos[0] = clock.until_ns
                        else: now[0] = self.deadline
                    return block
                def close(stream):
                    descriptors.extend(fd for fd in (stream.fd, stream.parent) if fd is not None)
                    return real_close(stream)
                def namespace(*args):
                    result = real_namespace(*args); passes[0] += 1
                    if boundary == "final" and passes[0] == 2: now[0] = self.deadline
                    return result
                with ExitStack() as stack:
                    roots = self.fresh_roots(parent, clock, stack)
                    root_descriptors = [fd for root in roots.values() for _, fd, _ in root.chain]
                    if boundary == "pre": now[0] = self.deadline
                    with patch.object(carrier.time, "monotonic", side_effect=lambda: now[0]), \
                            patch.object(carrier.time, "monotonic_ns", side_effect=lambda: nanos[0]), \
                            patch.object(carrier._FreshNarFile, "read", read), \
                            patch.object(carrier._FreshNarFile, "close", close), \
                            patch.object(carrier, "_fresh_namespace", namespace):
                        with self.assertRaises(ValueError): carrier._scan_nar(roots, expected, clock)
                if boundary != "pre": self.assertTrue(descriptors)
                self.assert_descriptors_closed(set(descriptors) | set(root_descriptors))

    def test_scoped_fusion_keeps_every_later_full_scan_and_standalone_path(self):
        root, _, pin = self.seal("fusion-carrier")
        output = self.root / "fusion-scoped"
        with patch.object(carrier, "scan", wraps=carrier.scan) as scans, \
                patch.object(carrier, "nar_origins", wraps=carrier.nar_origins) as nars, \
                patch.object(carrier, "_scan_nar", wraps=carrier._scan_nar) as fused:
            with carrier.HeldCarrier(root, pin, self.deadline) as scope:
                result = carrier.extract(root, pin, output, self.deadline, _held_carrier=scope)
                receipt_pin = carrier.sha(carrier.encoded(result))
                carrier.revalidate_extraction(root, pin, output, self.deadline,
                    pinned_extraction_receipt_sha256=receipt_pin, _held_carrier=scope)
                scope.full_final()
                carrier.revalidate_extraction(root, pin, output, self.deadline,
                    pinned_extraction_receipt_sha256=receipt_pin, _held_carrier=scope)
            self.assertEqual((fused.call_count, scans.call_count, nars.call_count), (3, 4, 0))
            carrier.extract(root, pin, self.root / "fusion-standalone", self.deadline)
            self.assertEqual((fused.call_count, scans.call_count, nars.call_count), (3, 7, 1))

    def test_fused_stream_eof_probe_is_required_for_a_normal_exit(self):
        parent, expected, _ = self.fresh_fixture("fusion-required-eof")
        clock = carrier.Clock(self.deadline)
        with ExitStack() as stack:
            roots = self.fresh_roots(parent, clock, stack)
            witnesses = carrier._fresh_namespace(roots, expected, clock)
            observed, completed, aggregate = {}, set(), [0]
            stream = carrier._FreshNarFile(roots["sdk"], "seven", expected[("sdk", "seven")],
                witnesses, "sdk", observed, completed, aggregate, clock)
            descriptors = (stream.fd, stream.parent)
            with self.assertRaisesRegex(ValueError, "fresh-stream-content"):
                with stream: self.assertEqual(stream.read(7), b"7" * 7)
            self.assertEqual(completed, set())
            self.assert_descriptors_closed(descriptors)

    def test_fused_open_read_and_serializer_refusal_close_actual_descriptors(self):
        for boundary in ("open", "read", "serializer"):
            with self.subTest(boundary=boundary):
                parent, expected, _ = self.fresh_fixture("fusion-error-" + boundary)
                clock = carrier.Clock(self.deadline)
                captured = []
                real_open, real_read, real_nar = carrier.os.open, carrier.os.read, carrier.nar.hash_descriptor
                def opened(*args, **kwargs):
                    fd = real_open(*args, **kwargs); captured.append(fd); return fd
                def refused_read(fd, size):
                    raise OSError("model stream IO refusal")
                def refused_nar(*args, **kwargs):
                    real_nar(*args, **kwargs)
                    raise ValueError("model serializer refusal")
                def refused_open(name, flags, *args, **kwargs):
                    if name == "first" and flags & os.O_NONBLOCK:
                        raise OSError("model regular open refusal")
                    return opened(name, flags, *args, **kwargs)
                with ExitStack() as stack:
                    roots = self.fresh_roots(parent, clock, stack)
                    with ExitStack() as errors:
                        errors.enter_context(patch.object(carrier.os, "open", refused_open if boundary == "open" else opened))
                        if boundary == "read": errors.enter_context(patch.object(carrier.os, "read", refused_read))
                        if boundary == "serializer": errors.enter_context(patch.object(carrier.nar, "hash_descriptor", refused_nar))
                        with self.assertRaises((ValueError, OSError)):
                            carrier._scan_nar(roots, expected, clock)
                self.assertTrue(captured)
                self.assert_descriptors_closed(set(captured))

    def test_scoped_fused_writer_identity_substitution_refuses_before_publication(self):
        root, _, pin = self.seal("fusion-writer-carrier")
        output = self.root / "fusion-writer-output"
        real = carrier._scan_nar
        def replaced(roots, expected, clock):
            leaf = roots["sdk"].path / "repositories/public+/tool"
            leaf.parent.chmod(0o700)
            raw = leaf.read_bytes(); leaf.unlink(); self.write(leaf, raw, 0o555)
            leaf.parent.chmod(0o555)
            return real(roots, expected, clock)
        with self.assertRaisesRegex(ValueError, "created-member-identity"):
            with carrier.HeldCarrier(root, pin, self.deadline) as scope:
                descriptors = self.held_fds(scope)
                with patch.object(carrier, "_scan_nar", side_effect=replaced):
                    carrier.extract(root, pin, output, self.deadline, _held_carrier=scope)
        self.assert_descriptors_closed(descriptors)
        self.assertFalse((output / "extraction-receipt.json").exists())

    def held_fds(self, scope):
        return [fd for _, fd, _ in scope._held] + [fd for _, fd, _ in scope._chain]

    def assert_descriptors_closed(self, descriptors):
        for fd in descriptors:
            with self.assertRaises(OSError):
                os.fstat(fd)

    def test_scoped_real_full_proof_reuses_one_owner_then_requires_fresh_final(self):
        root, original, pin = self.seal()
        public = carrier.publication_report(root, pin, self.deadline)
        output = self.root / "scoped-extracted"
        owners = []
        real = carrier.binding
        def full(owner, selected, clock):
            owners.append(owner)
            return real(owner, selected, clock)
        with patch.object(carrier, "binding", side_effect=full) as calls:
            with carrier.HeldCarrier(root, pin, self.deadline) as scope:
                descriptors = self.held_fds(scope)
                self.assertEqual(len(scope._held), 4)
                result = carrier.extract(root, pin, output, self.deadline, _held_carrier=scope)
                receipt_pin = carrier.sha(carrier.encoded(result))
                self.assertEqual(calls.call_count, 1)
                self.assertEqual(scope.report(), original)
                self.assertEqual(carrier.publication_report(root, pin, self.deadline, _held_carrier=scope), public)
                self.assertEqual(carrier.revalidate_extraction(root, pin, output, self.deadline,
                    pinned_extraction_receipt_sha256=receipt_pin, _held_carrier=scope), result)
                self.assertEqual(calls.call_count, 1)
                # Public standalone validation stays a separate complete read.
                self.assertEqual(carrier.validate_binding(root, pin, self.deadline), original)
                self.assertEqual(calls.call_count, 2)
                scope.full_final()
                self.assertEqual(carrier.revalidate_extraction(root, pin, output, self.deadline,
                    pinned_extraction_receipt_sha256=receipt_pin, _held_carrier=scope), result)
                self.assertEqual(calls.call_count, 3)
                self.assertIs(owners[0], owners[2])
                self.assertIsNot(owners[0], owners[1])
                self.assertEqual(scope.report(), original)
                self.assertEqual((output / "sdk/receipt.json").read_bytes(), self.original)
                self.assertFalse(result["metadata_qualified"])
                with self.assertRaises(TypeError):
                    scope._binding()[2][("sdk", "")]["mode"] = 0o700
                copied = scope.report()
                copied["origin"]["root"] = "/foreign"
                self.assertEqual(scope.report(), original)
            self.assert_descriptors_closed(descriptors)
            with self.assertRaises(ValueError):
                scope.report()
            with self.assertRaises(ValueError):
                scope.__enter__()

    def test_scoped_all_four_leaf_mutations_refuse_current_held_proof(self):
        for index, name in enumerate(carrier.FILES):
            for change in ("inode", "mode", "chmod-restored", "mtime-restored", "bytes", "hardlink", "symlink"):
                with self.subTest(name=name, change=change):
                    root, _, pin = self.seal("leaf-" + str(index) + "-" + change)
                    path = root / name
                    with self.assertRaises(ValueError):
                        with carrier.HeldCarrier(root, pin, self.deadline) as scope:
                            scope.report()
                            descriptors = self.held_fds(scope)
                            original = path.stat()
                            root.chmod(0o700)
                            if change in ("inode", "symlink"):
                                aside = self.root / ("old-" + str(index) + "-" + change)
                                path.rename(aside)
                                if change == "inode":
                                    self.write(path, aside.read_bytes(), 0o444)
                                else:
                                    path.symlink_to(aside)
                            elif change == "mode":
                                path.chmod(0o555)
                            elif change == "chmod-restored":
                                path.chmod(0o600)
                                path.chmod(0o444)
                            elif change == "mtime-restored":
                                os.utime(path, ns=(original.st_atime_ns, original.st_mtime_ns + 10**9))
                                os.utime(path, ns=(original.st_atime_ns, original.st_mtime_ns))
                            elif change == "bytes":
                                path.chmod(0o600)
                                with path.open("r+b") as stream:
                                    first = stream.read(1)
                                    stream.seek(0)
                                    stream.write(bytes([first[0] ^ 1]))
                                path.chmod(0o444)
                            else:
                                os.link(path, self.root / ("extra-hardlink-" + str(index)))
                            root.chmod(0o555)
                            scope.report()
                    self.assert_descriptors_closed(descriptors)

    def test_scoped_same_byte_named_ancestor_root_and_alias_changes_refuse(self):
        for change in ("root", "ancestor", "alias"):
            with self.subTest(change=change):
                parent = self.root / ("parent-" + change)
                parent.mkdir(mode=0o700)
                root, _, pin = self.seal("source-" + change)
                root.chmod(0o700)
                root.rename(parent / "carrier")
                root = parent / "carrier"
                root.chmod(0o555)
                parent.chmod(0o555)
                alias = self.root / ("alias-" + change)
                alias.symlink_to(root)
                with self.assertRaises(ValueError):
                    with carrier.HeldCarrier(root, pin, self.deadline) as scope:
                        scope.report()
                        descriptors = self.held_fds(scope)
                        if change == "root":
                            parent.chmod(0o700)
                            root.rename(parent / "old-carrier")
                            shutil.copytree(parent / "old-carrier", root, symlinks=True)
                            parent.chmod(0o555)
                            scope.report()
                        elif change == "ancestor":
                            parent.rename(self.root / "old-parent")
                            shutil.copytree(self.root / "old-parent", parent, symlinks=True)
                            scope.report()
                        else:
                            foreign = self.root / "foreign-alias-root"
                            shutil.copytree(root, foreign, symlinks=True)
                            alias.unlink()
                            alias.symlink_to(foreign)
                            carrier.publication_report(alias.resolve(strict=True), pin, self.deadline,
                                _held_carrier=scope)
                self.assert_descriptors_closed(descriptors)

    def test_scoped_foreign_owner_pin_clock_type_and_closed_scope_refuse(self):
        root, _, pin = self.seal()
        with carrier.HeldCarrier(root, pin, self.deadline) as scope:
            scope.report()
            for candidate, selected, deadline in ((self.root / "foreign", pin, self.deadline),
                    (root, "f" * 64, self.deadline), (root, pin, self.deadline + 1)):
                with self.assertRaises(ValueError):
                    carrier.publication_report(candidate, selected, deadline, _held_carrier=scope)
            with self.assertRaises(ValueError):
                carrier.publication_report(root, pin, self.deadline, _held_carrier={})
            owner, clock = scope._root, scope._clock
            with carrier.Root(root, clock) as foreign:
                scope._root = foreign
                with self.assertRaises(ValueError):
                    scope.check()
                scope._root = owner
            scope._clock = carrier.Clock(self.deadline)
            with self.assertRaises(ValueError):
                scope.check()
            scope._clock = clock
            scope.full_final()
            descriptors = self.held_fds(scope)
        self.assert_descriptors_closed(descriptors)
        with self.assertRaises(ValueError):
            carrier.publication_report(root, pin, self.deadline, _held_carrier=scope)

    def test_scoped_before_use_after_use_race_refuses_and_closes_owner(self):
        root, _, pin = self.seal()
        real = carrier.decode
        mutate = False
        def change(raw):
            nonlocal mutate
            result = real(raw)
            if mutate:
                mutate = False
                path = root / "payload.bin"
                path.chmod(0o600)
                path.chmod(0o444)
            return result
        with self.assertRaises(ValueError):
            with carrier.HeldCarrier(root, pin, self.deadline) as scope:
                scope.report()
                descriptors = self.held_fds(scope)
                mutate = True
                with patch.object(carrier, "decode", side_effect=change):
                    carrier.publication_report(root, pin, self.deadline, _held_carrier=scope)
        self.assert_descriptors_closed(descriptors)

    def test_scoped_original_float_integer_expiry_and_partial_entry_cleanup(self):
        for kind in ("float", "integer", "partial"):
            with self.subTest(kind=kind):
                root, _, pin = self.seal("deadline-" + kind)
                captured = []
                real_clock, real_open = carrier.Clock, carrier.Root.open
                def clock(deadline):
                    selected = real_clock(deadline)
                    if kind == "integer":
                        selected.until_ns = time.monotonic_ns() + 60 * 10**9
                    return selected
                def open_leaf(owner, name):
                    if kind == "partial" and name == "payload.bin":
                        captured.extend(fd for _, fd, _ in owner.chain)
                        raise ValueError("partial entry")
                    fd, witness = real_open(owner, name)
                    captured.append(fd)
                    return fd, witness
                with patch.object(carrier, "Clock", side_effect=clock), patch.object(carrier.Root, "open", open_leaf):
                    with self.assertRaises(ValueError):
                        with carrier.HeldCarrier(root, pin, self.deadline) as scope:
                            scope.report()
                            captured = self.held_fds(scope)
                            if kind == "float":
                                with patch.object(carrier.time, "monotonic", return_value=self.deadline):
                                    scope.report()
                            else:
                                with patch.object(carrier.time, "monotonic_ns", return_value=scope._until_ns):
                                    scope.report()
                self.assert_descriptors_closed(captured)

    def test_scoped_missing_or_failed_final_full_proof_never_accepts_exit(self):
        for kind in ("missing", "failed"):
            with self.subTest(kind=kind):
                root, _, pin = self.seal("final-" + kind)
                with self.assertRaises(ValueError):
                    with carrier.HeldCarrier(root, pin, self.deadline) as scope:
                        scope.report()
                        descriptors = self.held_fds(scope)
                        if kind == "failed":
                            with patch.object(carrier, "binding", side_effect=ValueError("final full refused")):
                                scope.full_final()
                self.assert_descriptors_closed(descriptors)

    def test_scoped_final_full_read_precedes_last_fresh_output_mutation_refusal(self):
        root, _, pin = self.seal()
        output = self.root / "final-raced-output"
        real = carrier.binding
        def final(owner, selected, clock):
            result = real(owner, selected, clock)
            path = output / "jdk/ordinary"
            path.chmod(0o600)
            path.write_bytes(b"changed during long final carrier read")
            path.chmod(0o444)
            return result
        with self.assertRaises(ValueError):
            with carrier.HeldCarrier(root, pin, self.deadline) as scope:
                result = carrier.extract(root, pin, output, self.deadline, _held_carrier=scope)
                descriptors = self.held_fds(scope)
                with patch.object(carrier, "binding", side_effect=final):
                    scope.full_final()
                carrier.revalidate_extraction(root, pin, output, self.deadline,
                    pinned_extraction_receipt_sha256=carrier.sha(carrier.encoded(result)), _held_carrier=scope)
        self.assert_descriptors_closed(descriptors)

    def test_scoped_real_named_leaf_mutation_during_full_final_refuses(self):
        root, _, pin = self.seal()
        real = carrier.binding
        def final(owner, selected, clock):
            result = real(owner, selected, clock)
            path = root / "manifest.json"
            root.chmod(0o700)
            path.rename(self.root / "held-manifest.json")
            self.write(path, (self.root / "held-manifest.json").read_bytes())
            root.chmod(0o555)
            return result
        with self.assertRaises(ValueError):
            with carrier.HeldCarrier(root, pin, self.deadline) as scope:
                scope.report()
                descriptors = self.held_fds(scope)
                with patch.object(carrier, "binding", side_effect=final):
                    scope.full_final()
        self.assert_descriptors_closed(descriptors)

    def test_scoped_extraction_requires_last_fresh_proof_after_full_final(self):
        root, _, pin = self.seal()
        with self.assertRaises(ValueError):
            with carrier.HeldCarrier(root, pin, self.deadline) as scope:
                result = carrier.extract(root, pin, self.root / "unfinished-last-proof", self.deadline,
                    _held_carrier=scope)
                descriptors = self.held_fds(scope)
                # A fresh proof performed before full_final cannot satisfy exit.
                carrier.revalidate_extraction(root, pin, self.root / "unfinished-last-proof", self.deadline,
                    pinned_extraction_receipt_sha256=carrier.sha(carrier.encoded(result)), _held_carrier=scope)
                scope.full_final()
        self.assert_descriptors_closed(descriptors)

    def test_scoped_copies_serialization_and_foreign_thread_never_transfer_authority(self):
        root, _, pin = self.seal()
        with carrier.HeldCarrier(root, pin, self.deadline) as scope:
            scope.report()
            for transfer in (copy.copy, copy.deepcopy, pickle.dumps):
                with self.subTest(transfer=transfer), self.assertRaises(ValueError):
                    transfer(scope)
            with patch.object(carrier.threading, "get_ident", return_value=scope._thread + 1):
                with self.assertRaises(ValueError):
                    scope.report()
            with patch.object(carrier.os, "getpid", return_value=scope._pid + 1):
                with self.assertRaises(ValueError):
                    scope.report()
            scope.check()
            scope.full_final()
            descriptors = self.held_fds(scope)
        self.assert_descriptors_closed(descriptors)

    def test_scoped_existing_unregistered_extraction_refuses_before_fresh_reads(self):
        root, _, pin = self.seal()
        output = self.root / "standalone-existing-output"
        receipt = carrier.extract(root, pin, output, self.deadline)
        with carrier.HeldCarrier(root, pin, self.deadline) as scope:
            scope.report()
            descriptors = self.held_fds(scope)
            with patch.object(carrier, "scan", side_effect=AssertionError("unregistered output read")), \
                    patch.object(carrier, "_scan_nar", side_effect=AssertionError("unregistered output read")):
                with self.assertRaisesRegex(ValueError, "registered-extraction"):
                    carrier.revalidate_extraction(root, pin, output, self.deadline,
                        pinned_extraction_receipt_sha256=carrier.sha(carrier.encoded(receipt)), _held_carrier=scope)
            with self.assertRaisesRegex(ValueError, "fresh-output-join"):
                scope._complete_fresh(output, receipt)
            scope.full_final()
        self.assert_descriptors_closed(descriptors)

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.origin, self.jdk = self.root / "origin", self.root / "jdk-origin"
        self.origin.mkdir(mode=0o700)
        self.jdk.mkdir(mode=0o700)
        self.jdk_patch = patch.object(sdk, "JDK", str(self.jdk))
        self.jdk_patch.start()
        self.write(self.jdk / "ordinary", b"synthetic immutable JDK bytes")
        (self.jdk / "inert").symlink_to("/not-authorized/sdk-carrier-model")
        repositories = self.origin / "repositories"
        repositories.mkdir(mode=0o700)
        public, other = repositories / "public+", repositories / "other"
        public.mkdir(mode=0o700)
        other.mkdir(mode=0o700)
        self.write(public / "MODULE.bazel", b'module(name="public")\n')
        self.write(public / "tool", b"tool model\x00bytes", 0o555)
        (public / "missing").symlink_to("../other/absent")
        graph = self.origin / "graph"
        graph.mkdir(mode=0o700)
        registry_bytes = b'{"public":"registry"}\n'
        registry_pin = carrier.sha(registry_bytes)
        url = "https://bcr.bazel.build/bazel_registry.json"
        lock = sdk.canonical({"registryFileHashes": {url: registry_pin}})
        for name in sdk.GRAPH:
            self.write(graph / name, lock if name == "MODULE.bazel.lock" else b"graph model " + name.encode(), 0o400)
        cache = self.origin / "registry-cache"
        self.write(cache / "content_addressable/sha256" / registry_pin / "file", registry_bytes)
        self.seal_dirs(self.origin)
        self.seal_dirs(self.jdk)
        budget = lambda: sdk.Budget(time.time() + 120)
        rows = []
        for root in (other, public):
            files = sdk.inventory(root, budget(), sealed=True)
            rows.append({"canonical_name": root.name, "root_kind": "generated", "source_root": str(root),
                         "files": files, "inventory_sha256": carrier.sha(sdk.canonical(files)),
                         "absent_links": [] if root == other else [{"origin": "public+/missing", "target": "other/absent"}]})
        graph_pins = {name: {"sha256": carrier.sha((graph / name).read_bytes())} for name in sdk.GRAPH}
        registry = sdk.registry_metadata(graph / "MODULE.bazel.lock", graph_pins["MODULE.bazel.lock"]["sha256"],
                                         cache, budget(), sealed=True)
        receipt = {"schema": sdk.SCHEMA, "baseline_receipt_sha256": sdk.BASELINE_SHA,
                   "baseline_inventory_sha256": sdk.BASELINE_INVENTORY, "graph_files": graph_pins,
                   "repositories": rows, "inventory_sha256": carrier.sha(sdk.canonical(rows)),
                   "mapping_sha256": graph_pins["MODULE.bazel.lock"]["sha256"],
                   "excluded": ["_main", "bazel_tools", "*.marker"], "qualification_only": False,
                   "nix_store_roots": [sdk.JDK], "modules": {"public": {"canonical_name": "public+",
                       "module_file_sha256": graph_pins.get("MODULE.bazel", {}).get("sha256")}},
                   "nix_inventory": sdk.inventory(self.jdk, budget(), sealed=True), "registry_metadata": registry,
                   "selection_sha256": "3" * 64, "producer": "//tools:codex_retained_sdk_export_run",
                   "counts": {"entries_read": 3, "bytes_read": 1,
                              "inventory_passes": {"qualification": 1, "copy": 1, "sealed_readback": 1},
                              "max_entries_per_pass": sdk.MAX_FILES, "max_inventory_passes": 3}}
        receipt["modules"]["public"]["module_file_sha256"] = carrier.sha((public / "MODULE.bazel").read_bytes())
        self.origin.chmod(0o700)
        self.original = sdk.canonical(receipt)
        self.write(self.origin / "receipt.json", self.original, 0o400)
        self.origin.chmod(0o555)
        self.pin = carrier.sha(self.original)
        entry = time.monotonic_ns()
        self.context = {"mode": "native-sdk-carrier-seal-reserved",
                        "epoch": "/srv/fast-local/jess/state/codex/omux-integrated-execution-20261005/12345678-1234-1234-1234-123456789abc",
                        "source_commit": "1" * 40, "graph_sha256": "2" * 64,
                        "entry_monotonic_ns": entry, "deadline_monotonic_ns": entry + 1200 * 10**9,
                        "work_cutoff_monotonic_ns": entry + 1170 * 10**9}
        self.deadline = self.context["work_cutoff_monotonic_ns"] / 10**9

    @staticmethod
    def write(path, raw, mode=0o444):
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        path.write_bytes(raw)
        path.chmod(mode)

    @staticmethod
    def seal_dirs(root):
        for path, _, _ in os.walk(root, topdown=False, followlinks=False):
            Path(path).chmod(0o555)

    def tearDown(self):
        self.jdk_patch.stop()
        for path, _, _ in os.walk(self.root, followlinks=False):
            Path(path).chmod(0o700)
        self.temporary.cleanup()

    def seal(self, name="carrier"):
        report = carrier.seal(self.origin, self.pin, self.root / name, self.deadline, producer_context=self.context)
        return self.root / name, report, carrier.sha(carrier.encoded(report))

    def rewrite(self, root, manifest=None, payload=None):
        root.chmod(0o700)
        receipt = json.loads((root / "receipt.json").read_bytes())
        if payload is not None:
            (root / "payload.bin").chmod(0o600)
            (root / "payload.bin").write_bytes(payload)
            (root / "payload.bin").chmod(0o444)
            receipt["payload_sha256"] = carrier.sha(payload)
            receipt["payload_bytes"] = len(payload)
        if manifest is not None:
            raw = carrier.encoded(manifest)
            (root / "manifest.json").chmod(0o600)
            self.write(root / "manifest.json", raw)
            receipt["manifest_sha256"], receipt["manifest_bytes"] = carrier.sha(raw), len(raw)
            receipt["entry_count"] = len(manifest["entries"])
        (root / "receipt.json").chmod(0o600)
        self.write(root / "receipt.json", carrier.encoded(receipt))
        root.chmod(0o555)
        return carrier.sha(carrier.encoded(receipt))

    def test_real_roundtrip_full_registry_graph_jdk_nar_and_distinct_custody(self):
        root, report, pin = self.seal()
        self.assertEqual(carrier.validate_binding(root, pin, self.deadline), report)
        publication = carrier.publication_report(root, pin, self.deadline)
        self.assertEqual({row["name"] for row in publication["files"]}, set(carrier.FILES))
        output = self.root / "extracted"
        fresh = carrier.extract(root, pin, output, self.deadline)
        self.assertEqual((output / "sdk/receipt.json").read_bytes(), self.original)
        self.assertEqual(stat.S_IMODE((output / "sdk/receipt.json").stat().st_mode), 0o400)
        self.assertEqual(stat.S_IMODE((output / "sdk/graph/MODULE.bazel.lock").stat().st_mode), 0o400)
        self.assertEqual((output / "jdk/ordinary").read_bytes(), (self.jdk / "ordinary").read_bytes())
        self.assertEqual(os.readlink(output / "jdk/inert"), "/not-authorized/sdk-carrier-model")
        self.assertFalse((output / "sdk/repositories/other/absent").exists())
        self.assertNotEqual(fresh["fresh_custody"]["sdk"]["root_identity"], report["origin_custody"]["sdk"]["root_identity"])
        self.assertFalse(fresh["original_inodes_reused"])
        self.assertFalse(fresh["metadata_qualified"])
        self.assertEqual(carrier.revalidate_extraction(root, pin, output, self.deadline,
                         pinned_extraction_receipt_sha256=carrier.sha(carrier.encoded(fresh))), fresh)

    def retained_transport(self, source, name="bazel-retained"):
        # Model Bazel9 READONLY tree-artifact retention on fresh fixture copies,
        # never chmod the original producer or any genuine retained selection.
        retained = self.root / name
        shutil.copytree(source, retained)
        for leaf in carrier.FILES:
            (retained / leaf).chmod(0o555)
        self.seal_dirs(retained)
        return retained

    def test_real_core_bazel_retained_transport_roundtrip_preserves_logical_modes_and_clock(self):
        source, report, pin = self.seal()
        original = {name: (source / name).read_bytes() for name in carrier.FILES}
        self.assertTrue(all(stat.S_IMODE((source / name).stat().st_mode) == 0o444 for name in carrier.FILES))
        retained = self.retained_transport(source)
        self.assertEqual(carrier.validate_binding(retained, pin, self.deadline), report)
        publication = carrier.publication_report(retained, pin, self.deadline)
        self.assertEqual(publication["files"], [{"name": name, "sha256": carrier.sha(original[name]),
                                               "size": len(original[name])} for name in carrier.FILES])
        output = self.root / "retained-extracted"
        fresh = carrier.extract(retained, pin, output, self.deadline)
        manifest = json.loads(original["manifest.json"])
        self.assertEqual(fresh["nars"], manifest["nars"])
        self.assertEqual(fresh["producer_context"], self.context)
        self.assertEqual(report["producer_context"]["work_cutoff_monotonic_ns"] / 10**9, self.deadline)
        self.assertEqual(stat.S_IMODE((output / "sdk/receipt.json").stat().st_mode), 0o400)
        self.assertEqual(stat.S_IMODE((output / "sdk/graph/MODULE.bazel.lock").stat().st_mode), 0o400)
        self.assertEqual(stat.S_IMODE((output / "sdk/repositories/public+/MODULE.bazel").stat().st_mode), 0o444)
        self.assertEqual(stat.S_IMODE((output / "sdk/repositories/public+/tool").stat().st_mode), 0o555)
        self.assertEqual(stat.S_IMODE((output / "jdk/ordinary").stat().st_mode), 0o444)
        self.assertFalse(fresh["original_inodes_reused"])
        self.assertFalse(fresh["sdk_execution_qualified"])
        self.assertFalse(fresh["metadata_qualified"])
        self.assertFalse(fresh["source_witnesses_replaced"])
        self.assertEqual(carrier.revalidate_extraction(retained, pin, output, self.deadline,
            pinned_extraction_receipt_sha256=carrier.sha(carrier.encoded(fresh))), fresh)
        self.assertEqual(carrier.publication_report(retained, pin, self.deadline), publication)
        for name in carrier.FILES:
            self.assertEqual((retained / name).read_bytes(), original[name])
            self.assertEqual(stat.S_IMODE((retained / name).stat().st_mode), 0o555)
            self.assertEqual(stat.S_IMODE((source / name).stat().st_mode), 0o444)

    def test_every_retained_transport_leaf_refuses_writable_or_special_modes_at_public_apis(self):
        source, _, pin = self.seal()
        retained = self.retained_transport(source)
        output = self.root / "good-extracted"
        fresh = carrier.extract(retained, pin, output, self.deadline)
        fresh_pin = carrier.sha(carrier.encoded(fresh))
        for name in carrier.FILES:
            for mode in (0o600, 0o644, 0o666, 0o755):
                with self.subTest(leaf=name, mode=oct(mode)):
                    (retained / name).chmod(mode)
                    with self.assertRaises(ValueError):
                        carrier.validate_binding(retained, pin, self.deadline)
                    with self.assertRaises(ValueError):
                        carrier.publication_report(retained, pin, self.deadline)
                    with self.assertRaises(ValueError):
                        carrier.extract(retained, pin, self.root / "refused-extraction", self.deadline)
                    with self.assertRaises(ValueError):
                        carrier.revalidate_extraction(retained, pin, output, self.deadline,
                                                     pinned_extraction_receipt_sha256=fresh_pin)
                    self.assertFalse((self.root / "refused-extraction").exists())
                    (retained / name).chmod(0o555)

        # The guarded workload forbids creating SUID/SGID files. Model only
        # the returned mode witness after a real nofollow/custody-checked open;
        # each public route must reject it at the transport mode predicate.
        real_open = carrier.Root.open
        for name in carrier.FILES:
            for mode in (0o4555, 0o2555):
                with self.subTest(leaf=name, special_mode=oct(mode)):
                    opened = []
                    def special_mode_witness(root, leaf):
                        fd, witness = real_open(root, leaf)
                        if root.path == retained and leaf == name:
                            opened.append(stat.S_IMODE(witness[4]))
                            witness = list(witness)
                            witness[4] |= mode & 0o7000
                        return fd, witness
                    with patch.object(carrier.Root, "open", special_mode_witness):
                        with self.assertRaisesRegex(ValueError, "^SDK carrier refused: transport-leaf-mode$"):
                            carrier.validate_binding(retained, pin, self.deadline)
                        with self.assertRaisesRegex(ValueError, "^SDK carrier refused: transport-leaf-mode$"):
                            carrier.publication_report(retained, pin, self.deadline)
                        with self.assertRaisesRegex(ValueError, "^SDK carrier refused: transport-leaf-mode$"):
                            carrier.extract(retained, pin, self.root / "refused-extraction", self.deadline)
                        with self.assertRaisesRegex(ValueError, "^SDK carrier refused: transport-leaf-mode$"):
                            carrier.revalidate_extraction(retained, pin, output, self.deadline,
                                                         pinned_extraction_receipt_sha256=fresh_pin)
                    self.assertEqual(opened, [0o555] * 4)
                    self.assertFalse((self.root / "refused-extraction").exists())
                    self.assertEqual(stat.S_IMODE((retained / name).stat().st_mode), 0o555)

    def test_retained_transport_symlink_and_same_bytes_mode_or_inode_race_refuse(self):
        for name in carrier.FILES:
            with self.subTest(symlink=name):
                source, _, pin = self.seal("symlink-source-" + name)
                retained = self.retained_transport(source, "symlink-retained-" + name)
                retained.chmod(0o700)
                leaf = retained / name
                foreign = self.root / ("foreign-" + name)
                self.write(foreign, leaf.read_bytes(), 0o555)
                leaf.unlink()
                leaf.symlink_to(foreign)
                retained.chmod(0o555)
                with self.assertRaises(ValueError):
                    carrier.validate_binding(retained, pin, self.deadline)
                with self.assertRaises(ValueError):
                    carrier.publication_report(retained, pin, self.deadline)
                with self.assertRaises(ValueError):
                    carrier.extract(retained, pin, self.root / ("symlink-out-" + name), self.deadline)
                self.assertFalse((self.root / ("symlink-out-" + name)).exists())
        for change in ("allowed-mode", "same-byte-inode"):
            with self.subTest(race=change):
                source, _, pin = self.seal("race-source-" + change)
                retained = self.retained_transport(source, "race-retained-" + change)
                original = carrier.Range.read
                changed = False
                def race(part, size=-1):
                    nonlocal changed
                    block = original(part, size)
                    if block and not changed:
                        changed = True
                        leaf = retained / "payload.bin"
                        if change == "allowed-mode":
                            leaf.chmod(0o444)
                        else:
                            retained.chmod(0o700)
                            raw = leaf.read_bytes()
                            leaf.unlink()
                            self.write(leaf, raw, 0o555)
                            retained.chmod(0o555)
                    return block
                with patch.object(carrier.Range, "read", race), self.assertRaises(ValueError):
                    carrier.extract(retained, pin, self.root / ("race-out-" + change), self.deadline)
                self.assertTrue(changed)
                self.assertFalse((self.root / ("race-out-" + change)).exists())

    def test_current_owned_seal_does_not_admit_retained_transport_mode(self):
        original = carrier.Output.file
        def retained_mode_too_early(output, name, raw):
            original(output, name, raw)
            if name == "manifest.json":
                (output.path / name).chmod(0o555)
        with patch.object(carrier.Output, "file", retained_mode_too_early), self.assertRaises(ValueError):
            self.seal("refused-current-owned")

    def test_deterministic_content_with_original_clock_context(self):
        first, _, _ = self.seal("first")
        second, _, _ = self.seal("second")
        for name in carrier.FILES:
            self.assertEqual((first / name).read_bytes(), (second / name).read_bytes())
        wrong = {**self.context, "work_cutoff_monotonic_ns": self.context["work_cutoff_monotonic_ns"] + 1}
        with self.assertRaises(ValueError):
            carrier.seal(self.origin, self.pin, self.root / "renewed", self.deadline, producer_context=wrong)
        self.assertFalse((self.root / "renewed").exists())

    def test_extra_origin_member_and_hardlink_refuse_before_publication(self):
        public = self.origin / "repositories/public+"
        public.chmod(0o700)
        self.write(public / "extra", b"unselected")
        public.chmod(0o555)
        with self.assertRaises(ValueError):
            self.seal()
        self.assertFalse((self.root / "carrier").exists())
        public.chmod(0o700)
        (public / "extra").unlink()
        os.link(public / "tool", self.root / "foreign-hardlink")
        public.chmod(0o555)
        with self.assertRaises(ValueError):
            self.seal()

    def test_payload_corruption_truncation_and_unlisted_carrier_refuse(self):
        for change in ("corrupt", "truncate", "extra"):
            with self.subTest(change=change):
                root, _, pin = self.seal(change)
                if change == "extra":
                    root.chmod(0o700)
                    self.write(root / "undeclared", b"extra")
                    root.chmod(0o555)
                else:
                    path = root / "payload.bin"
                    data = path.read_bytes()
                    path.chmod(0o600)
                    path.write_bytes((bytes([data[0] ^ 1]) + data[1:]) if change == "corrupt" else data[:-1])
                    path.chmod(0o444)
                with self.assertRaises(ValueError):
                    carrier.extract(root, pin, self.root / (change + "-out"), self.deadline)
                self.assertFalse((self.root / (change + "-out")).exists())

    def test_duplicate_traversal_special_parent_and_offset_manifests_refuse(self):
        for change in ("duplicate", "traversal", "device", "parent", "offset", "nar"):
            with self.subTest(change=change):
                root, _, _ = self.seal(change)
                value = json.loads((root / "manifest.json").read_bytes())
                if change == "duplicate":
                    value["entries"].append(dict(value["entries"][-1]))
                elif change == "traversal":
                    value["entries"][-1]["path"] = "../../foreign"
                elif change == "device":
                    value["entries"][-1]["kind"] = "device"
                elif change == "parent":
                    row = next(row for row in value["entries"] if row["kind"] == "directory" and row["path"] == "repositories")
                    row.update(kind="symlink", target="/foreign")
                    row.pop("mode")
                elif change == "offset":
                    next(row for row in value["entries"] if row["kind"] == "file")["offset"] += 1
                else:
                    value["nars"]["sdk"]["narHash"] = "sha256:" + "0" * 64
                pin = self.rewrite(root, manifest=value)
                with self.assertRaises(ValueError):
                    carrier.extract(root, pin, self.root / (change + "-out"), self.deadline)

    def test_origin_same_byte_root_replacement_is_refused(self):
        original = carrier.nar_origins
        def mutate(roots, rows, clock):
            result = original(roots, rows, clock)
            self.origin.rename(self.root / "detached-origin")
            shutil.copytree(self.root / "detached-origin", self.origin, symlinks=True)
            return result
        with patch.object(carrier, "nar_origins", side_effect=mutate):
            with self.assertRaises(ValueError):
                self.seal()

    def test_extracted_same_bytes_new_inode_and_created_absence_refuse_readback(self):
        root, _, pin = self.seal()
        output = self.root / "extracted"
        fresh = carrier.extract(root, pin, output, self.deadline)
        receipt_pin = carrier.sha(carrier.encoded(fresh))
        leaf = output / "sdk/repositories/public+/tool"
        leaf.parent.chmod(0o700)
        raw = leaf.read_bytes()
        leaf.unlink()
        self.write(leaf, raw, 0o555)
        leaf.parent.chmod(0o555)
        with self.assertRaises(ValueError):
            carrier.revalidate_extraction(root, pin, output, self.deadline, pinned_extraction_receipt_sha256=receipt_pin)
        other = output / "sdk/repositories/other"
        other.chmod(0o700)
        self.write(other / "absent", b"formerly absent")
        other.chmod(0o555)
        with self.assertRaises(ValueError):
            carrier.revalidate_extraction(root, pin, output, self.deadline, pinned_extraction_receipt_sha256=receipt_pin)

    def test_chmod_intermediate_symlink_refuses_without_touching_foreign_mode(self):
        root, _, pin = self.seal()
        foreign = self.root / "foreign"
        foreign.mkdir(mode=0o700)
        original = carrier.Output.seal_directory
        mutated = False
        def replace(output, name):
            nonlocal mutated
            if name == "sdk/repositories/public+" and not mutated:
                mutated = True
                selected = output.path / "sdk/repositories"
                selected.rename(output.path / "sdk/detached")
                selected.symlink_to(foreign, target_is_directory=True)
            return original(output, name)
        with patch.object(carrier.Output, "seal_directory", new=replace):
            with self.assertRaises((ValueError, OSError)):
                carrier.extract(root, pin, self.root / "raced", self.deadline)
        self.assertEqual(stat.S_IMODE(foreign.stat().st_mode), 0o700)
        self.assertFalse((self.root / "raced/extraction-receipt.json").exists())

    def test_output_existing_foreign_root_and_expired_cutoff_are_untouched(self):
        root, _, pin = self.seal()
        foreign = self.root / "foreign"
        foreign.mkdir(mode=0o700)
        self.write(foreign / "keep", b"foreign bytes")
        with self.assertRaises(FileExistsError):
            carrier.extract(root, pin, foreign, self.deadline)
        self.assertEqual((foreign / "keep").read_bytes(), b"foreign bytes")
        with self.assertRaises(ValueError):
            carrier.extract(root, pin, self.root / "expired", time.monotonic()-1)
        self.assertFalse((self.root / "expired").exists())

    def test_oversized_origin_rows_refuse_before_hash_and_absence_allocations(self):
        repository_rows = json.loads(self.original)
        repository_rows["repositories"][0]["files"] = [
            {"path": "unselected", "kind": "file", "mode": 0o444, "sha256": "4" * 64}
        ] * 129
        nix_rows = json.loads(self.original)
        nix_rows["nix_inventory"] = [{"path": "unselected"}] * 129
        invalid_list = json.loads(self.original)
        invalid_list["repositories"][0]["files"] = {"unselected": True}
        with patch.object(carrier, "MAX_ENTRIES", 128), \
                patch.object(sdk, "canonical", side_effect=AssertionError("hashed before row bound")), \
                patch.object(sdk, "public_link_absences", side_effect=AssertionError("allocated before row bound")):
            for name, receipt in (("repositories", repository_rows), ("jdk", nix_rows), ("type", invalid_list)):
                with self.subTest(name=name), self.assertRaises(ValueError):
                    carrier.receipt_shape(receipt, carrier.Clock(self.deadline))

    def test_integer_original_cutoff_refuses_when_float_clock_still_before(self):
        clock = carrier.Clock(self.deadline)
        clock.until_ns = self.context["work_cutoff_monotonic_ns"]
        with (patch.object(carrier.time, "monotonic", return_value=self.deadline-0.001),
              patch.object(carrier.time, "monotonic_ns", return_value=clock.until_ns)):
            with self.assertRaisesRegex(ValueError, "integer-deadline"):
                clock.tick()

    def test_created_regular_leaf_same_bytes_replacement_refuses_before_ready(self):
        root, _, pin = self.seal()
        original = carrier.scan
        replaced = False
        def replace(roots, expected, clock):
            nonlocal replaced
            if roots["sdk"].path.parent.name == "raced-leaf" and not replaced:
                replaced = True
                leaf = roots["sdk"].path / "repositories/public+/tool"
                leaf.parent.chmod(0o700)
                raw = leaf.read_bytes()
                leaf.unlink()
                self.write(leaf, raw, 0o555)
                leaf.parent.chmod(0o555)
            return original(roots, expected, clock)
        with patch.object(carrier, "scan", side_effect=replace):
            with self.assertRaisesRegex(ValueError, "created-member-identity"):
                carrier.extract(root, pin, self.root / "raced-leaf", self.deadline)
        self.assertFalse((self.root / "raced-leaf/extraction-receipt.json").exists())

    def test_published_metadata_mutation_refuses_api_return(self):
        write = carrier.Output.file
        def swap_manifest(output, name, raw):
            write(output, name, raw)
            if name == "receipt.json":
                target = output.path / "manifest.json"
                target.chmod(0o600)
                target.write_bytes(target.read_bytes() + b" ")
                target.chmod(0o444)
        with patch.object(carrier.Output, "file", swap_manifest), self.assertRaises(ValueError):
            self.seal("unaccepted-carrier")
        root, _, pin = self.seal()
        finish = carrier.Output.finish
        def swap_fresh_receipt(output):
            finish(output)
            target = output.path / "extraction-receipt.json"
            if target.exists():
                target.chmod(0o600)
                target.write_bytes(target.read_bytes() + b" ")
                target.chmod(0o444)
        with patch.object(carrier.Output, "finish", swap_fresh_receipt), self.assertRaises(ValueError):
            carrier.extract(root, pin, self.root / "unaccepted-extraction", self.deadline)

    def test_fresh_mutation_during_final_carrier_validation_refuses(self):
        root, _, pin = self.seal()
        output = self.root / "extracted"
        fresh = carrier.extract(root, pin, output, self.deadline)
        original, calls = carrier.binding, 0
        def mutate(*args, **kwargs):
            nonlocal calls
            result = original(*args, **kwargs)
            calls += 1
            if calls == 2:
                leaf = output / "jdk/ordinary"
                leaf.chmod(0o600)
                leaf.write_bytes(b"mutated during long final carrier pass")
                leaf.chmod(0o444)
            return result
        with patch.object(carrier, "binding", side_effect=mutate):
            with self.assertRaises(ValueError):
                carrier.revalidate_extraction(root, pin, output, self.deadline,
                    pinned_extraction_receipt_sha256=carrier.sha(carrier.encoded(fresh)))

    def parent_output(self, name="parents"):
        output = carrier.Output(self.root / name, carrier.Clock(self.deadline))
        for path in ("sdk", "sdk/one", "sdk/one/two"):
            output.mkdir(path)
        return output

    def test_parent_handles_reduce_real_opens_preserving_stat_checks(self):
        with closing(self.parent_output()) as output:
            real_open, real_stat = os.open, os.stat
            with patch.object(carrier.os, "open", wraps=real_open) as opened, \
                    patch.object(carrier.os, "stat", wraps=real_stat) as named:
                for _ in range(2):
                    fd, leaf = output.root.parent("sdk/one/two/leaf")
                    self.assertEqual(leaf, "leaf")
                    self.assertEqual(carrier.identity(os.fstat(fd), True),
                                     carrier.identity((output.path / "sdk/one/two").stat(), True))
                    os.close(fd)
                baseline_opens, baseline_stats = opened.call_count, named.call_count
            with carrier._ParentHandles(output.root) as parents:
                with patch.object(carrier.os, "open", wraps=real_open) as opened, \
                        patch.object(carrier.os, "stat", wraps=real_stat) as named:
                    for _ in range(2):
                        fd, leaf = parents.parent("sdk/one/two/leaf")
                        self.assertEqual(leaf, "leaf")
                        self.assertEqual(carrier.identity(os.fstat(fd), True),
                                         carrier.identity((output.path / "sdk/one/two").stat(), True))
                        os.close(fd)
                    self.assertEqual(baseline_opens, 6)
                    self.assertEqual(opened.call_count, 3)
                    self.assertEqual(named.call_count, baseline_stats)
                retained = [fd for fd, _ in parents.entries.values()]
            for fd in retained:
                with self.assertRaises(OSError):
                    os.fstat(fd)

    def test_parent_handles_refuse_same_byte_parent_mode_and_symbolic_replacement(self):
        for change in ("same-byte", "mode", "symbolic"):
            with self.subTest(change=change), closing(self.parent_output(change)) as output:
                parent = output.path / "sdk/one/two"
                self.write(parent / "unchanged", b"same bytes")
                with carrier._ParentHandles(output.root) as parents:
                    fd, _ = parents.parent("sdk/one/two/leaf")
                    os.close(fd)
                    if change == "mode":
                        parent.chmod(0o500)
                    else:
                        parent.rename(parent.with_name("detached"))
                        if change == "same-byte":
                            parent.mkdir(mode=0o700)
                            self.write(parent / "unchanged", b"same bytes")
                        else:
                            foreign = self.root / "foreign-parent"
                            foreign.mkdir(mode=0o700)
                            parent.symlink_to(foreign, target_is_directory=True)
                    with self.assertRaises(ValueError):
                        parents.parent("sdk/one/two/leaf")

    def test_parent_handles_refuse_named_root_replacement(self):
        with closing(self.parent_output()) as output:
            with carrier._ParentHandles(output.root) as parents:
                fd, _ = parents.parent("sdk/one/two/leaf")
                os.close(fd)
                output.path.rename(self.root / "detached-root")
                output.path.mkdir(mode=0o700)
                with self.assertRaisesRegex(ValueError, "named-ancestor"):
                    parents.parent("sdk/one/two/leaf")

    def test_parent_handles_cached_dup_rechecks_after_named_race(self):
        with closing(self.parent_output()) as output:
            with carrier._ParentHandles(output.root) as parents:
                fd, _ = parents.parent("sdk/one/two/leaf")
                os.close(fd)
                cached = parents.entries["sdk/one/two"][0]
                real_dup, borrowed = os.dup, []
                def replace_after_dup(fd):
                    child = real_dup(fd)
                    if fd == cached:
                        borrowed.append(child)
                        parent = output.path / "sdk/one/two"
                        parent.rename(parent.with_name("detached"))
                        parent.mkdir(mode=0o700)
                    return child
                with patch.object(carrier.os, "dup", side_effect=replace_after_dup):
                    with self.assertRaisesRegex(ValueError, "internal-parent-race"):
                        parents.parent("sdk/one/two/leaf")
                self.assertEqual(len(borrowed), 1)
                with self.assertRaises(OSError):
                    os.fstat(borrowed[0])

    def test_parent_handles_bound_evict_and_close_exact_owned_descriptors(self):
        with closing(self.parent_output()) as output:
            for index in range(34):
                output.mkdir("sdk/d" + str(index))
            with carrier._ParentHandles(output.root) as parents:
                fd, _ = parents.parent("sdk/d0/leaf")
                os.close(fd)
                evicted = parents.entries["sdk/d0"][0]
                real_close, evicted_closed = os.close, []
                def record_close(fd):
                    if fd == evicted and carrier.identity(os.fstat(fd), True) == output.root.named["sdk/d0"]:
                        evicted_closed.append(fd)
                    real_close(fd)
                with patch.object(carrier.os, "close", side_effect=record_close):
                    for index in range(1, 34):
                        fd, _ = parents.parent("sdk/d" + str(index) + "/leaf")
                        os.close(fd)
                        self.assertLessEqual(len(parents.entries), 32)
                self.assertNotIn("sdk/d0", parents.entries)
                self.assertEqual(evicted_closed, [evicted])
                held = [fd for fd, _ in parents.entries.values()]
            self.assertEqual(parents.entries, {})
            for fd in held:
                with self.assertRaises(OSError):
                    os.fstat(fd)
            output.root.check()
            with self.assertRaisesRegex(ValueError, "parent-handles-closed"):
                parents.parent("sdk/d1/leaf")

    def test_parent_handles_original_expiry_and_exception_close_descriptors(self):
        for reason in ("deadline", "integer-deadline", "exception"):
            with self.subTest(reason=reason), closing(self.parent_output(reason)) as output:
                parents = carrier._ParentHandles(output.root)
                held = []
                with self.assertRaisesRegex(ValueError, reason):
                    with parents:
                        fd, _ = parents.parent("sdk/one/two/leaf")
                        os.close(fd)
                        held = [fd for fd, _ in parents.entries.values()]
                        if reason == "deadline":
                            original = output.root.clock.deadline
                            with patch.object(carrier.time, "monotonic", return_value=original):
                                parents.parent("sdk/one/two/leaf")
                        elif reason == "integer-deadline":
                            output.root.clock.until_ns = time.monotonic_ns() + 10**9
                            with patch.object(carrier.time, "monotonic_ns", return_value=output.root.clock.until_ns):
                                parents.parent("sdk/one/two/leaf")
                        else:
                            raise ValueError("exception")
                self.assertEqual(parents.entries, {})
                output.root.clock.until_ns = None
                for fd in held:
                    with self.assertRaises(OSError):
                        os.fstat(fd)
                output.root.check()


    def extraction_phases(self, raw):
        rows = []
        for line in raw.splitlines():
            match = re.fullmatch(r"sdk-carrier-extract: ([a-z-]+) elapsed_ns=([0-9]+) copied_files=([0-9]+) copied_bytes=([0-9]+) created_directories=([0-9]+)", line)
            self.assertIsNotNone(match, "only redacted static phase and bounded numeric counters")
            rows.append((match[1], *(int(value) for value in match.groups()[1:])))
        self.assertLessEqual(len(rows), 7)
        self.assertEqual([row[1] for row in rows], sorted(row[1] for row in rows))
        for _, _, files, size, directories in rows:
            self.assertLessEqual(files, carrier.MAX_ENTRIES)
            self.assertLessEqual(size, carrier.MAX_BYTES)
            self.assertLessEqual(directories, carrier.MAX_ENTRIES)
        return rows

    def test_extract_bound_report_same_owner_full_proofs_and_redacted_phase_order(self):
        root, original, pin = self.seal()
        output = self.root / "fused-output"
        seen, owners = [], []
        original_binding = carrier.binding
        def binding(owner, selected_pin, clock):
            result = original_binding(owner, selected_pin, clock)
            owners.append(owner)
            return result
        def bound(report):
            self.assertEqual(report, original)
            self.assertFalse(output.exists())
            self.assertEqual(len(owners), 1)
            owners[0].check()
            seen.append(report)
        emitted = io.StringIO()
        with redirect_stderr(emitted), patch.object(carrier, "binding", side_effect=binding) as proofs:
            result = carrier.extract(root, pin, output, self.deadline, on_bound=bound)
        self.assertEqual(seen, [original])
        self.assertEqual(proofs.call_count, 2)
        self.assertIs(owners[0], owners[1])
        self.assertEqual(owners[0].chain, [])
        self.assertEqual(result["carrier_receipt_sha256"], pin)
        self.assertFalse(result["metadata_qualified"])
        self.assertEqual((output / "sdk/receipt.json").read_bytes(), self.original)
        phases = self.extraction_phases(emitted.getvalue())
        self.assertEqual([row[0] for row in phases], ["initial-start", "initial-bound", "directories-start", "directories-ready",
            "copy-complete", "final-proof-start", "final-proof-complete"])
        manifest = json.loads((root / "manifest.json").read_bytes())
        count = sum(entry["kind"] == "file" for entry in manifest["entries"])
        self.assertTrue(all(row[2:4] == (0, 0) for row in phases[:4]))
        self.assertTrue(all(row[2:4] == (count, original["payload_bytes"]) for row in phases[4:]))
        directory_count = sum(entry["kind"] == "directory" for entry in manifest["entries"])
        self.assertTrue(all(row[4] == 0 for row in phases[:3]))
        self.assertTrue(all(row[4] == directory_count for row in phases[3:]))
        for sensitive in (str(root), str(output), pin, original["origin"]["root"], "synthetic"):
            self.assertNotIn(sensitive, emitted.getvalue())

    def test_extract_bound_refusal_and_same_byte_custody_or_expiry_close_owner(self):
        for change in ("refusal", "same-byte-root", "same-byte-leaf", "leaf-mode", "deadline", "integer-deadline"):
            with self.subTest(change=change):
                root, _, pin = self.seal("bound-" + change)
                output = self.root / ("out-" + change)
                original_binding, held = carrier.binding, []
                now, now_ns = [time.monotonic()], [time.monotonic_ns()]
                integer_cutoff = now_ns[0] + 10**9
                def binding(owner, selected_pin, clock):
                    result = original_binding(owner, selected_pin, clock)
                    held.extend(fd for _, fd, _ in owner.chain)
                    if change == "integer-deadline":
                        owner.clock.until_ns = integer_cutoff
                    return result
                def bound(unused):
                    self.assertFalse(output.exists())
                    if change == "refusal":
                        raise ValueError("origin callback refused")
                    if change == "same-byte-root":
                        root.rename(root.with_name(root.name + "-detached"))
                        root.mkdir(mode=0o555)
                    elif change == "same-byte-leaf":
                        leaf = root / "payload.bin"
                        raw = leaf.read_bytes()
                        leaf.chmod(0o600)
                        leaf.write_bytes(raw)
                        leaf.chmod(0o444)
                    elif change == "leaf-mode":
                        (root / "payload.bin").chmod(0o400)
                    elif change == "deadline":
                        now[0] = self.deadline
                    else:
                        now_ns[0] = integer_cutoff
                emitted = io.StringIO()
                with redirect_stderr(emitted), patch.object(carrier, "binding", side_effect=binding), \
                        patch.object(carrier.time, "monotonic", side_effect=lambda: now[0]), \
                        patch.object(carrier.time, "monotonic_ns", side_effect=lambda: now_ns[0]):
                    with self.assertRaises(ValueError):
                        carrier.extract(root, pin, output, self.deadline, on_bound=bound)
                self.assertFalse(output.exists())
                self.assertEqual([row[0] for row in self.extraction_phases(emitted.getvalue())],
                                 ["initial-start", "initial-bound"])
                for fd in held:
                    with self.assertRaises(OSError):
                        os.fstat(fd)

    def test_extract_corrupt_carrier_refuses_before_bound_callback(self):
        root, _, pin = self.seal()
        leaf = root / "payload.bin"
        raw = leaf.read_bytes()
        leaf.chmod(0o600)
        leaf.write_bytes(b"!" + raw[1:])
        leaf.chmod(0o444)
        output = self.root / "unbound-output"
        callback, emitted = unittest.mock.Mock(), io.StringIO()
        with redirect_stderr(emitted), self.assertRaisesRegex(ValueError, "payload-file-digest"):
            carrier.extract(root, pin, output, self.deadline, on_bound=callback)
        callback.assert_not_called()
        self.assertFalse(output.exists())
        self.assertEqual([row[0] for row in self.extraction_phases(emitted.getvalue())], ["initial-start"])

    def test_extract_failed_copy_reports_only_fully_checked_file_counters(self):
        for reason in ("refusal", "deadline", "integer-deadline"):
            with self.subTest(reason=reason):
                root, _, pin = self.seal("partial-" + reason)
                output = self.root / ("partial-copy-" + reason)
                armed, first_accepted = [False], threading.Event()
                entries = [row for row in json.loads((root / "manifest.json").read_bytes())["entries"]
                           if row["kind"] == "file"]
                second_offset, second_size = entries[1]["offset"], entries[1]["size"]
                original_read, original_copy = carrier.Range.read, carrier._copy_regulars
                def bound(unused):
                    armed[0] = True
                def copies(owner, payload, witness, files, clock, on_copied):
                    def accepted(*args):
                        on_copied(*args)
                        first_accepted.set()
                    return original_copy(owner, payload, witness, files, clock, accepted)
                def fail_second_copy(part, count):
                    if armed[0] and part.start == second_offset and part.size == second_size and not part.position:
                        self.assertTrue(first_accepted.wait(5), "first copy was not owner-accepted")
                        if reason == "refusal":
                            raise ValueError("injected copy refusal")
                        original_clock = part.clock.clock if isinstance(part.clock, carrier._CopyState) else part.clock
                        if reason == "deadline":
                            with patch.object(carrier.time, "monotonic", return_value=original_clock.deadline):
                                return original_read(part, count)
                        original_clock.until_ns = time.monotonic_ns() + 10**9
                        with patch.object(carrier.time, "monotonic_ns", return_value=original_clock.until_ns):
                            return original_read(part, count)
                    return original_read(part, count)
                emitted = io.StringIO()
                with redirect_stderr(emitted), patch.object(carrier.Range, "read", new=fail_second_copy), \
                        patch.object(carrier, "_copy_regulars", new=copies):
                    with self.assertRaisesRegex(ValueError, "copy refusal" if reason == "refusal" else reason):
                        carrier.extract(root, pin, output, self.deadline, on_bound=bound)
                phases = self.extraction_phases(emitted.getvalue())
                self.assertEqual([row[0] for row in phases],
                    ["initial-start", "initial-bound", "directories-start", "directories-ready", "copy-refused"])
                self.assertEqual(phases[-1][2:4], (1, len((self.jdk / "ordinary").read_bytes())))
                self.assertFalse((output / "extraction-receipt.json").exists())
                self.assertEqual((output / "jdk/ordinary").read_bytes(), (self.jdk / "ordinary").read_bytes())


    def test_mkdir_parent_handles_reduce_real_opens_with_same_named_checks(self):
        with closing(self.parent_output()) as output:
            real_open, real_stat = os.open, os.stat
            with patch.object(carrier.os, "open", wraps=real_open) as opened, \
                    patch.object(carrier.os, "stat", wraps=real_stat) as named:
                for leaf in ("a", "b"):
                    output.mkdir("sdk/one/two/" + leaf)
                baseline_opens, baseline_stats = opened.call_count, named.call_count
            with carrier._ParentHandles(output.root) as parents:
                with patch.object(carrier.os, "open", wraps=real_open) as opened, \
                        patch.object(carrier.os, "stat", wraps=real_stat) as named:
                    for leaf in ("c", "d"):
                        output.mkdir("sdk/one/two/" + leaf, parent_handles=parents)
                    self.assertEqual(baseline_opens, 8)
                    self.assertEqual(opened.call_count, 5)
                    self.assertEqual(named.call_count, baseline_stats)
                cached = [fd for fd, _ in parents.entries.values()]
            for leaf in ("a", "b", "c", "d"):
                name = "sdk/one/two/" + leaf
                self.assertEqual(output.root.named[name],
                                 carrier.identity((output.path / name).stat(), True))
                self.assertEqual(stat.S_IMODE((output.path / name).stat().st_mode), 0o700)
            for fd in cached:
                with self.assertRaises(OSError):
                    os.fstat(fd)
            output.root.check()

    def test_mkdir_parent_handles_require_same_owner_and_live_scope(self):
        with closing(self.parent_output("left")) as left, closing(self.parent_output("right")) as right:
            with carrier._ParentHandles(right.root) as foreign:
                with self.assertRaisesRegex(ValueError, "mkdir-parent-owner"):
                    left.mkdir("sdk/one/two/new", parent_handles=foreign)
            self.assertFalse((left.path / "sdk/one/two/new").exists())
            parents = carrier._ParentHandles(left.root)
            parents.close()
            with self.assertRaisesRegex(ValueError, "parent-handles-closed"):
                left.mkdir("sdk/one/two/new", parent_handles=parents)
            self.assertFalse((left.path / "sdk/one/two/new").exists())
            left.root.check()
            right.root.check()

    def test_mkdir_cached_parent_refuses_inode_mode_and_link_changes_without_foreign_write(self):
        for change in ("inode", "mode", "link"):
            with self.subTest(change=change), closing(self.parent_output("mkdir-" + change)) as output:
                with carrier._ParentHandles(output.root) as parents:
                    output.mkdir("sdk/one/two/seed", parent_handles=parents)
                    parent = output.path / "sdk/one/two"
                    foreign = self.root / ("foreign-" + change)
                    foreign.mkdir(mode=0o700)
                    self.write(foreign / "marker", b"foreign bytes")
                    if change == "mode":
                        parent.chmod(0o500)
                    else:
                        parent.rename(parent.with_name("detached"))
                        if change == "inode":
                            parent.mkdir(mode=0o700)
                            (parent / "seed").mkdir(mode=0o700)
                        else:
                            parent.symlink_to(foreign, target_is_directory=True)
                    with self.assertRaises(ValueError):
                        output.mkdir("sdk/one/two/new", parent_handles=parents)
                    self.assertNotIn("sdk/one/two/new", output.root.named)
                    self.assertFalse((foreign / "new").exists())
                    self.assertEqual((foreign / "marker").read_bytes(), b"foreign bytes")
                    self.assertEqual(stat.S_IMODE(foreign.stat().st_mode), 0o700)

    def test_mkdir_cached_dup_still_refuses_named_parent_race(self):
        with closing(self.parent_output()) as output:
            with carrier._ParentHandles(output.root) as parents:
                output.mkdir("sdk/one/two/seed", parent_handles=parents)
                cached = parents.entries["sdk/one/two"][0]
                real_dup, borrowed = os.dup, []
                def replace_after_dup(fd):
                    child = real_dup(fd)
                    if fd == cached:
                        borrowed.append(child)
                        parent = output.path / "sdk/one/two"
                        parent.rename(parent.with_name("detached"))
                        parent.mkdir(mode=0o700)
                    return child
                with patch.object(carrier.os, "dup", side_effect=replace_after_dup):
                    with self.assertRaisesRegex(ValueError, "internal-parent-race"):
                        output.mkdir("sdk/one/two/new", parent_handles=parents)
                self.assertEqual(len(borrowed), 1)
                with self.assertRaises(OSError):
                    os.fstat(borrowed[0])
                self.assertNotIn("sdk/one/two/new", output.root.named)

    def test_mkdir_created_child_before_held_after_join_refuses_same_mode_replacement(self):
        with closing(self.parent_output()) as output:
            with carrier._ParentHandles(output.root) as parents:
                output.mkdir("sdk/one/two/seed", parent_handles=parents)
                real_open, created_fds = os.open, []
                def replace_child(name, flags, *args, **kwargs):
                    fd = real_open(name, flags, *args, **kwargs)
                    if name == "new":
                        created_fds.append(fd)
                        child = output.path / "sdk/one/two/new"
                        child.rename(child.with_name("detached-child"))
                        child.mkdir(mode=0o700)
                    return fd
                with patch.object(carrier.os, "open", side_effect=replace_child):
                    with self.assertRaisesRegex(ValueError, "created-directory-race"):
                        output.mkdir("sdk/one/two/new", parent_handles=parents)
                self.assertNotIn("sdk/one/two/new", output.root.named)
                self.assertEqual(len(created_fds), 1)
                with self.assertRaises(OSError):
                    os.fstat(created_fds[0])

    def test_mkdir_scope_bounds_eviction_and_cancellation_descriptor_cleanup(self):
        with closing(self.parent_output()) as output:
            for index in range(34):
                output.mkdir("sdk/d" + str(index))
            parents = carrier._ParentHandles(output.root)
            retained = []
            real_open = os.open
            def cancelled_child(name, flags, *args, **kwargs):
                if name == "cancelled":
                    raise KeyboardInterrupt("model cancellation")
                return real_open(name, flags, *args, **kwargs)
            with self.assertRaises(KeyboardInterrupt):
                with parents:
                    for index in range(34):
                        output.mkdir("sdk/d" + str(index) + "/child", parent_handles=parents)
                        self.assertLessEqual(len(parents.entries), 32)
                    self.assertNotIn("sdk/d0", parents.entries)
                    retained = [fd for fd, _ in parents.entries.values()]
                    with patch.object(carrier.os, "open", side_effect=cancelled_child):
                        output.mkdir("sdk/d33/cancelled", parent_handles=parents)
            self.assertEqual(parents.entries, {})
            for fd in retained:
                with self.assertRaises(OSError):
                    os.fstat(fd)
            self.assertNotIn("sdk/d33/cancelled", output.root.named)
            output.root.check()

    def test_extract_directory_refusal_emits_bounded_checked_count_and_closes_scope(self):
        for reason in ("role-cancel", "cancel", "deadline", "integer-deadline"):
            with self.subTest(reason=reason):
                root, _, pin = self.seal("directory-" + reason)
                output = self.root / ("directory-out-" + reason)
                original_mkdir, prepared, owners, retained = carrier.Output.mkdir, [0], [], []
                def refuse_second(directory, name, *, parent_handles=None):
                    if reason == "role-cancel" and name == "sdk" and parent_handles is None:
                        raise KeyboardInterrupt("role directory cancellation")
                    if parent_handles is not None:
                        prepared[0] += 1
                        if prepared[0] == 2:
                            owners.append(parent_handles)
                            retained.extend(fd for fd, _ in parent_handles.entries.values())
                            if reason == "cancel":
                                raise KeyboardInterrupt("directory cancellation")
                            if reason == "deadline":
                                with patch.object(carrier.time, "monotonic", return_value=directory.clock.deadline):
                                    return original_mkdir(directory, name, parent_handles=parent_handles)
                            directory.clock.until_ns = time.monotonic_ns() + 10**9
                            with patch.object(carrier.time, "monotonic_ns", return_value=directory.clock.until_ns):
                                return original_mkdir(directory, name, parent_handles=parent_handles)
                    return original_mkdir(directory, name, parent_handles=parent_handles)
                emitted = io.StringIO()
                expected = KeyboardInterrupt if reason in ("role-cancel", "cancel") else ValueError
                with redirect_stderr(emitted), patch.object(carrier.Output, "mkdir", new=refuse_second):
                    with self.assertRaises(expected):
                        carrier.extract(root, pin, output, self.deadline)
                phases = self.extraction_phases(emitted.getvalue())
                self.assertEqual([row[0] for row in phases],
                    ["initial-start", "initial-bound", "directories-start", "directories-refused"])
                self.assertEqual(phases[-1][2:], (0, 0, 0 if reason == "role-cancel" else 3))
                self.assertFalse((output / "extraction-receipt.json").exists())
                self.assertEqual(len(owners), 0 if reason == "role-cancel" else 1)
                for owner in owners:
                    self.assertEqual(owner.entries, {})
                for fd in retained:
                    with self.assertRaises(OSError):
                        os.fstat(fd)


if __name__ == "__main__":
    unittest.main()
