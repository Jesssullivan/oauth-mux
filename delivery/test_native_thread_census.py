"""Bounded diagnostic models and isolated owned-child tests, not native proof."""
from __future__ import annotations

import ast
import copy
import errno
import io
import os
from pathlib import Path
import selectors
import signal
import subprocess
import sys
import threading
import time
from types import SimpleNamespace
import unittest
from unittest import mock

import native_thread_census as census
import test_installed_legacy_native_tui as legacy

ACTUAL = "--actual-owned-children" in sys.argv
if ACTUAL:
    sys.argv.remove("--actual-owned-children")


def status(count=b"3", *, extra=b""):
    return b"Name:\tprivate-name-bait /private/path\nPid:\t123\nPPid:\t12\nUid:\t1\t1\t1\t1\nNSpid:\t123\nThreads:\t" + count + b"\n" + extra


def empty_census():
    value = census.Census.__new__(census.Census)
    value.creator = (os.getpid(), threading.get_ident())
    value.uid = os.getuid()
    value.outer_deadline = time.monotonic_ns() + 2_000_000_000
    value.root = 45
    value.entries = {}
    value.states = dict.fromkeys(census.ROLES, "not-created")
    value.states["self"] = "profile"
    value.fds = set()
    value.sampled = False
    value.pending_control = None
    return value


class ParserTests(unittest.TestCase):
    def test_only_bounded_numeric_projection_is_retained(self):
        result = census.parse_status(status())
        self.assertEqual(result[-1], 3)
        value = census.record("self", "observed", result[-1])
        self.assertEqual(census.parse_record(value), value)
        self.assertNotIn(b"private", value)
        projection = census.Projection(sample_threads=False)
        projection.feed(status(b"not-a-number"))
        self.assertIsNone(projection.finish()[-1])
        projection.clear()
        self.assertEqual(projection.fields, {})

    def test_duplicate_missing_noncanonical_and_overlong_count_refused(self):
        for number in (b"", b"0", b"-1", b"+1", b"01", b"1\r", b"65537", b"9" * 257):
            with self.subTest(case=len(number)):
                with self.assertRaises(census.Unavailable):
                    census.parse_status(status(number))
        for payload in (status(extra=b"Threads:\t4\n"), status().replace(b"Threads:\t3\n", b""),
                        status()[:-1], b"Name:" + b"x" * census.MAX_STATUS):
            with self.assertRaises(census.Unavailable):
                census.parse_status(payload)

    def test_unknown_or_ancestor_namespace_profile_is_unavailable(self):
        for replacement in (b"", b"NSpid:\t999\t123\n", b"NSpid:\t999\n",
                            b"NSpid:\t0123\n", b"NSpid:\tunknown\n"):
            payload = status().replace(b"NSpid:\t123\n", replacement)
            with self.assertRaises(census.Unavailable) as caught:
                census.parse_status(payload)
            self.assertEqual(caught.exception.reason, "profile")

    def test_record_grammar_is_closed(self):
        for payload in (
            b"OMUX_NATIVE_THREADS_V1/failure-before-cleanup/foreign/observed/1\n",
            b"OMUX_NATIVE_THREADS_V1/failure-before-cleanup/self/secret/none\n",
            b"OMUX_NATIVE_THREADS_V1/failure-before-cleanup/self/observed/01\n",
            b"OMUX_NATIVE_THREADS_V1/failure-before-cleanup/self/retired/1\n",
            b"OMUX_NATIVE_THREADS_V1/failure-before-cleanup/self/observed/0\n",
            b"OMUX_NATIVE_THREADS_V1/failure-before-cleanup/self/observed/65537\n",
        ):
            with self.assertRaises(ValueError):
                census.parse_record(payload)


class OwnershipModels(unittest.TestCase):
    def model(self, *, returncode=None, live=True):
        value = empty_census()
        child = SimpleNamespace(pid=123, returncode=returncode)
        events = []
        def created(*args, **kwargs):
            events.append("created")
            return child
        def directory(*args, **kwargs):
            events.append("directory")
            return value._own(61)
        witness = (123, os.getpid(), (os.getuid(),) * 4, None)
        patches = (
            mock.patch.object(census.subprocess, "Popen", side_effect=created),
            mock.patch.object(census.os, "pidfd_open", return_value=60),
            mock.patch.object(census.os, "get_inheritable", return_value=False),
            mock.patch.object(census.os, "close"),
            mock.patch.object(census.signal, "getsignal", return_value=signal.SIG_DFL),
            mock.patch.object(census, "_procfs"),
            mock.patch.object(value, "_live", return_value=live),
            mock.patch.object(value, "_open", side_effect=directory),
            mock.patch.object(value, "_status", return_value=witness),
            mock.patch.object(value, "_witness", return_value=(1, 2, value.uid)),
        )
        return value, child, events, patches

    def test_immediate_owned_creation_has_one_launch_and_no_child_wait(self):
        value, child, events, patches = self.model()
        with self.enter_patches(patches):
            returned = census.owned_popen(value, "daemon", ["declared-owned-fixture"])
            events.append("returned")
            self.assertIs(returned, child)
            self.assertEqual(events, ["created", "directory", "returned"])
            self.assertIn("daemon", value.entries)
            value.close()

    def test_reaped_ready_or_mismatched_child_never_grants_observation(self):
        for code, live in ((0, True), (None, False)):
            value, child, events, patches = self.model(returncode=code, live=live)
            with self.enter_patches(patches):
                self.assertIs(census.owned_popen(value, "daemon", ["declared-owned-fixture"]), child)
                self.assertEqual(value.states["daemon"], "retired")
                self.assertNotIn("directory", events)
                self.assertEqual(value.fds, set())
        value, child, events, patches = self.model()
        with self.enter_patches(patches), mock.patch.object(value, "_status", return_value=(124, 9, (0,) * 4, None)):
            census.owned_popen(value, "daemon", ["declared-owned-fixture"])
            self.assertEqual(value.states["daemon"], "identity")
            self.assertEqual(value.fds, set())

    def test_capture_baseexceptions_return_original_child_and_defer_controls(self):
        for error in (RuntimeError(), KeyboardInterrupt(), SystemExit()):
            value = empty_census()
            child = SimpleNamespace(pid=123, returncode=None)
            with mock.patch.object(census.subprocess, "Popen", return_value=child) as launch, \
                    mock.patch.object(value, "_capture_created", side_effect=error):
                self.assertIs(census.owned_popen(value, "keyring", ["declared-owned-fixture"]), child)
                self.assertEqual(launch.call_count, 1)
                self.assertEqual(value.states["keyring"], "profile")
                assigned_anchor = child
                if isinstance(error, (KeyboardInterrupt, SystemExit)):
                    try:
                        census.checkpoint(value)
                    except BaseException as deferred:
                        self.assertTrue(deferred is error, "deferred control object changed")
                        self.assertIs(assigned_anchor, child)
                    else:
                        self.fail("control exception suppressed")
                else:
                    census.checkpoint(value)
                self.assertIsNone(value.pending_control)

    def test_first_pending_control_is_retained_and_constructor_controls_propagate(self):
        value = empty_census()
        first, later = KeyboardInterrupt(), SystemExit()
        value.defer_control(first)
        value.defer_control(later)
        with self.assertRaises(KeyboardInterrupt) as caught:
            census.checkpoint(value)
        self.assertTrue(caught.exception is first, "first control object changed")
        self.assertIsNone(value.pending_control)
        with mock.patch.object(census.Census, "_open", side_effect=KeyboardInterrupt()), \
                mock.patch.object(census.signal, "getsignal", return_value=signal.SIG_DFL):
            with self.assertRaises(KeyboardInterrupt):
                census.Census(time.monotonic_ns() + 1_000_000_000)

    def test_retired_sampling_never_reopens_a_numeric_selector(self):
        value = empty_census()
        child = SimpleNamespace(pid=123, returncode=0)
        value.entries["daemon"] = (61, 60, child, (123, 12, (1,) * 4), (1, 2, 1))
        with mock.patch.object(value, "_status", side_effect=AssertionError("status must remain unread")), \
                mock.patch.object(value, "_open", side_effect=AssertionError("numeric selector must remain closed")):
            records = value.failure_records()
        self.assertIn(census.record("daemon", "retired"), records)
        self.assertEqual(value.failure_records(), ())

    def test_deadline_profile_and_close_failure_remain_unavailable(self):
        for deadline in (None, False, -1, 0, time.monotonic_ns() - 1):
            value = empty_census()
            value.outer_deadline = deadline
            self.assertTrue(all(b"/deadline/none\n" in row for row in value.failure_records()))
        with mock.patch.object(census, "_procfs", side_effect=census.Unavailable("profile")), \
                mock.patch.object(census.Census, "_open", autospec=True,
                                  side_effect=lambda self, *a, **kw: self._own(45)), \
                mock.patch.object(census.os, "close"):
            value = census.Census(time.monotonic_ns() + 1_000_000_000)
            self.assertEqual(value.states["self"], "profile")
        value = empty_census()
        value.fds = {60, 61, 62}
        with mock.patch.object(census.os, "close", side_effect=OSError()) as close:
            value.close()
            self.assertEqual(close.call_count, 3)
            self.assertEqual(value.fds, set())

    def test_expiry_during_read_closes_status_and_never_returns_threads(self):
        value = empty_census()
        clock = [1]
        def opened(*args, **kwargs):
            return value._own(70)
        def read(*args):
            clock[0] = 101
            return status()
        with mock.patch.object(value, "_open", side_effect=opened), \
                mock.patch.object(census, "_procfs"), \
                mock.patch.object(census.os, "fstat", return_value=SimpleNamespace(st_mode=census.stat.S_IFREG)), \
                mock.patch.object(census.os, "read", side_effect=read) as actual_read, \
                mock.patch.object(census.os, "close") as closed, \
                mock.patch.object(census.time, "monotonic_ns", side_effect=lambda: clock[0]):
            with self.assertRaises(census.Unavailable) as caught:
                value._status(61, 100)
            self.assertEqual(caught.exception.reason, "deadline")
            self.assertEqual(closed.call_count, 1)
            self.assertEqual(actual_read.call_count, 1)
            self.assertTrue(not value.fds, "expired status descriptor retained")

    def test_expiry_between_roles_does_not_open_the_next_status(self):
        value = empty_census()
        clock = [1]
        value.outer_deadline = 100
        uid = value.uid
        identity = (value.creator[0], os.getppid(), (uid,) * 4)
        witness = (1, 2, uid)
        value.entries["self"] = (61, None, None, identity, witness)
        for index, role in enumerate(census.ROLES[1:]):
            value.entries[role] = (62 + index, 70 + index,
                                   SimpleNamespace(pid=123 + index, returncode=None),
                                   (123 + index, value.creator[0], (uid,) * 4), witness)
        def read_status(directory, deadline):
            self.assertTrue(directory == 61, "next role read after expiry")
            clock[0] = 101
            return (*identity, 3)
        with mock.patch.object(value, "_witness", return_value=witness), \
                mock.patch.object(value, "_status", side_effect=read_status) as read, \
                mock.patch.object(value, "_live", return_value=True), \
                mock.patch.object(census.time, "monotonic_ns", side_effect=lambda: clock[0]):
            rows = value.failure_records()
        self.assertIn(census.record("self", "observed", 3), rows)
        for role in census.ROLES[1:]:
            self.assertIn(census.record(role, "deadline"), rows)
        self.assertEqual(read.call_count, 1)

    def test_parent_uid_directory_and_self_namespace_drift_refuse_counts(self):
        for kind in ("pid", "parent", "uid", "device", "inode", "directory-uid"):
            value = empty_census()
            identity = (123, value.creator[0], (value.uid,) * 4)
            witness = (1, 2, value.uid)
            value.entries["daemon"] = (61, 60, SimpleNamespace(pid=123, returncode=None), identity, witness)
            changed = ((124, value.creator[0], (value.uid,) * 4, 3) if kind == "pid"
                       else (123, value.creator[0] + 1, (value.uid,) * 4, 3) if kind == "parent"
                       else (123, value.creator[0], (value.uid + 1,) * 4, 3) if kind == "uid"
                       else (*identity, 3))
            changed_witness = ((2, 2, value.uid) if kind == "device"
                               else (1, 3, value.uid) if kind == "inode"
                               else (1, 2, value.uid + 1) if kind == "directory-uid"
                               else witness)
            with mock.patch.object(value, "_live", return_value=True), \
                    mock.patch.object(value, "_witness", return_value=changed_witness), \
                    mock.patch.object(value, "_status", return_value=changed) as read:
                rows = value.failure_records()
            self.assertIn(census.record("daemon", "identity"), rows)
            self.assertTrue(not any(b"/daemon/observed/" in row for row in rows), "drift granted a count")
            if kind in ("device", "inode", "directory-uid"):
                self.assertEqual(read.call_count, 0)
        value = empty_census()
        pid, parent, uid = value.creator[0], os.getppid(), value.uid
        identity = (pid, parent, (uid,) * 4)
        witness = (1, 2, uid)
        value.entries["self"] = (61, None, None, identity, witness)
        payload = (f"Pid:\t{pid}\nPPid:\t{parent}\nUid:\t{uid}\t{uid}\t{uid}\t{uid}\n"
                   f"NSpid:\t{pid}\t{pid}\nThreads:\t3\n").encode("ascii")
        with mock.patch.object(value, "_witness", return_value=witness), \
                mock.patch.object(value, "_open", side_effect=lambda *a, **kw: value._own(70)), \
                mock.patch.object(census, "_procfs"), \
                mock.patch.object(census.os, "fstat", return_value=SimpleNamespace(st_mode=census.stat.S_IFREG)), \
                mock.patch.object(census.os, "read", side_effect=[payload, b""]), \
                mock.patch.object(census.os, "close"):
            rows = value.failure_records()
        self.assertIn(census.record("self", "profile"), rows)
        self.assertTrue(not any(b"/self/observed/" in row for row in rows), "namespace drift granted a count")
        self.assertTrue(not value.fds, "namespace-drift status descriptor retained")

    @staticmethod
    def enter_patches(patches):
        from contextlib import ExitStack
        stack = ExitStack()
        for patch in patches:
            stack.enter_context(patch)
        return stack


class FixtureHookModels(unittest.TestCase):
    def scope(self, events):
        # Execute the exact fixture's exception/cleanup AST with only its work
        # body replaced. This checks the actual hook location and bare re-raise,
        # rather than reproducing the intended handler in a test helper.
        module = ast.parse(Path(legacy.__file__).read_text())
        inside = next(node for node in module.body if isinstance(node, ast.FunctionDef) and node.name == "inside")
        scope = copy.deepcopy(next(node for node in inside.body if isinstance(node, ast.Try) and node.finalbody))
        scope.body = [ast.Expr(value=ast.Call(func=ast.Name(id="operation", ctx=ast.Load()), args=[], keywords=[]))]
        source = ast.parse("def fixture_scope(operation, census):\n    pass\n")
        source.body[0].body = [scope]
        source = ast.fix_missing_locations(source)
        namespace = {
            "native_threads": census, "sys": SimpleNamespace(stderr=io.StringIO(), exc_info=sys.exc_info),
            "terminal": None, "bootstrap_native": None, "daemon": None,
            "keyring_process": object(), "drains": [],
            "support": SimpleNamespace(stop=lambda child: events.append("cleanup")),
            "require": lambda condition, message: self.assertTrue(condition, message),
            "PHASE": "fixed-phase", "DIAGNOSTIC": "fixed-diagnostic",
        }
        exec(compile(source, "declared-fixture-hook-model", "exec"), namespace)
        return namespace["fixture_scope"], namespace

    def test_success_closes_without_records_and_failure_samples_before_cleanup(self):
        for fail in (False, True):
            events = []
            scope, namespace = self.scope(events)
            original = ValueError("private-primary-bait")
            fake = SimpleNamespace(
                failure_records=lambda: (events.append("sample") or (census.record("self", "observed", 3),)),
                close=lambda: events.append("closed"))
            def work():
                if fail:
                    raise original
            if fail:
                with self.assertRaises(ValueError) as caught:
                    scope(work, fake)
                self.assertTrue(caught.exception is original, "primary exception changed")
                self.assertEqual(events, ["sample", "cleanup", "closed"])
                self.assertNotIn("private", namespace["sys"].stderr.getvalue())
            else:
                scope(work, fake)
                self.assertEqual(events, ["cleanup", "closed"])
                self.assertEqual(namespace["sys"].stderr.getvalue(), "")

    def test_census_parser_output_and_close_baseexceptions_keep_original(self):
        for stage in ("sample", "parser", "output", "close"):
            for error in (RuntimeError(), KeyboardInterrupt(), SystemExit()):
                events = []
                scope, namespace = self.scope(events)
                original = ValueError("private-primary-bait")
                fake = SimpleNamespace(
                    failure_records=lambda: (census.record("self", "observed", 3),),
                    close=lambda: events.append("closed"))
                def throw(*args):
                    raise error
                if stage == "sample":
                    fake.failure_records = throw
                elif stage == "output":
                    namespace["sys"].stderr = SimpleNamespace(write=throw)
                elif stage == "close":
                    fake.close = throw
                def work():
                    raise original
                patch = mock.patch.object(census, "parse_record", side_effect=error) if stage == "parser" else mock.patch.object(census, "PREFIX", census.PREFIX)
                with patch, self.assertRaises(ValueError) as caught:
                    scope(work, fake)
                self.assertTrue(caught.exception is original, "diagnostics changed primary exception")
                self.assertIn("cleanup", events)
                self.assertEqual(caught.exception.args, ("private-primary-bait",))

    def test_pending_control_raises_after_assignment_with_original_cleanup_anchor(self):
        for control in (KeyboardInterrupt(), SystemExit()):
            events = []
            scope, namespace = self.scope(events)
            value = empty_census()
            child = SimpleNamespace(pid=123, returncode=None)
            stop = mock.Mock(side_effect=lambda owned: events.append("cleanup"))
            namespace["support"].stop = stop
            def work():
                # Same assignment-before-checkpoint order as each legacy caller.
                namespace["keyring_process"] = census.owned_popen(value, "keyring", ["declared-owned-fixture"])
                events.append("assigned")
                census.checkpoint(value)
            with mock.patch.object(census.subprocess, "Popen", return_value=child) as created, \
                    mock.patch.object(value, "_capture_created", side_effect=control):
                try:
                    scope(work, value)
                except BaseException as caught:
                    self.assertTrue(caught is control, "deferred control object changed")
                else:
                    self.fail("deferred control suppressed")
            self.assertEqual(created.call_count, 1)
            self.assertTrue(stop.call_args.args[0] is child, "original cleanup anchor changed")
            self.assertEqual(events, ["assigned", "cleanup"])
            self.assertTrue(not value.fds, "deferred-control descriptors retained")
            self.assertIsNone(value.pending_control)

    def test_diagnostic_exception_preserves_original_traceback_tail(self):
        events = []
        scope, namespace = self.scope(events)
        original = ValueError("private-primary-bait")
        witness = []
        def work():
            try:
                raise original
            except ValueError:
                witness.append(sys.exc_info()[2])
                raise
        fake = SimpleNamespace(
            failure_records=mock.Mock(side_effect=KeyboardInterrupt()),
            close=lambda: events.append("closed"))
        try:
            scope(work, fake)
        except ValueError as error:
            self.assertTrue(error is original, "primary exception changed")
            tail = error.__traceback__
            while tail.tb_next is not None:
                tail = tail.tb_next
            self.assertTrue(tail is witness[0], "primary traceback tail changed")
        else:
            self.fail("primary exception suppressed")
        self.assertEqual(namespace["PHASE"], "fixed-phase")
        self.assertEqual(namespace["DIAGNOSTIC"], "fixed-diagnostic")
        self.assertEqual(events, ["cleanup", "closed"])

    def test_native_constructor_factory_captures_before_other_initialization(self):
        events = []
        child = SimpleNamespace(stderr=object(), stdout=SimpleNamespace(fileno=lambda: 123))
        def factory(*args, **kwargs):
            events.append("created-and-enrolled")
            return child
        with mock.patch.object(legacy.support, "DiscardLog", side_effect=lambda stream: events.append("drain")), \
                mock.patch.object(legacy.support.selectors, "DefaultSelector"), \
                mock.patch.object(legacy.support.os, "set_blocking"):
            result = legacy.support.JsonProcess(["declared-native"], {}, Path("/"), popen_factory=factory)
        self.assertIs(result.process, child)
        self.assertEqual(events[:2], ["created-and-enrolled", "drain"])


@unittest.skipUnless(ACTUAL, "separate declared owned-process gate")
class OwnedProcessTests(unittest.TestCase):
    def start(self, value):
        script = (
            "import sys,threading\n"
            "event=threading.Event()\n"
            "workers=[threading.Thread(target=event.wait,daemon=True) for _ in range(2)]\n"
            "[worker.start() for worker in workers]\n"
            "print('ready',flush=True)\n"
            "sys.stdin.buffer.read(1)\n"
        )
        child = census.owned_popen(value, "native-resume", [sys.executable, "-I", "-B", "-c", script],
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        try:
            self.assertTrue("native-resume" in value.entries, "owned child enrollment unavailable")
            with selectors.DefaultSelector() as selector:
                selector.register(child.stdout, selectors.EVENT_READ)
                self.assertTrue(bool(selector.select(2)), "owned child handshake deadline")
                self.assertTrue(os.read(child.stdout.fileno(), 6) == b"ready\n", "owned child handshake changed")
        except BaseException:
            self.finish(child)
            raise
        return child

    @staticmethod
    def finish(process):
        if process is not None:
            if process.stdin is not None and not process.stdin.closed:
                process.stdin.close()
            process.wait(timeout=2)
            if process.stdout is not None:
                process.stdout.close()

    def assert_descriptors_closed(self, owned):
        for fd in owned:
            try:
                os.fstat(fd)
            except OSError as error:
                self.assertTrue(error.errno == errno.EBADF, "saved diagnostic descriptor has unexpected state")
            else:
                self.fail("saved diagnostic descriptor remains open")

    def test_owned_child_threads_and_descriptor_cleanup(self):
        value = census.Census(time.monotonic_ns() + 5_000_000_000)
        child = None
        try:
            self.assertTrue("self" in value.entries, "declared procfs ownership profile unavailable")
            child = self.start(value)
            rows = value.failure_records()
            self.assertIn(census.record("native-resume", "observed", 3), rows)
            self.assertEqual(value.failure_records(), ())
            self.assertTrue(len(value.fds) <= census.MAX_OWNED_FDS, "owned descriptor bound exceeded")
        finally:
            saved = tuple(value.fds)
            try:
                self.finish(child)
            finally:
                value.close()
                self.assertTrue(not value.fds, "owned diagnostic descriptors retained")
                self.assert_descriptors_closed(saved)

    def test_retired_held_directory_cannot_select_another_owned_child(self):
        value = census.Census(time.monotonic_ns() + 5_000_000_000)
        child = replacement = None
        try:
            child = self.start(value)
            self.finish(child)
            replacement = subprocess.Popen([sys.executable, "-I", "-B", "-c", "import sys;sys.stdin.buffer.read(1)"],
                                           stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            with mock.patch.object(value, "_open", side_effect=AssertionError("numeric reopening forbidden")):
                rows = value.failure_records()
            self.assertIn(census.record("native-resume", "retired"), rows)
            self.assertNotIn(census.record("native-resume", "observed", 1), rows)
            # This proves retained-selector refusal, not forced numeric PID reuse.
        finally:
            saved = tuple(value.fds)
            try:
                self.finish(child)
                self.finish(replacement)
            finally:
                value.close()
                self.assertTrue(not value.fds, "owned diagnostic descriptors retained")
                self.assert_descriptors_closed(saved)

if __name__ == "__main__":
    unittest.main()
