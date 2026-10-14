"""Models of the exact seed predicate and failure cleanup; no native execution."""
import ast
import copy
import io
from pathlib import Path
import sys
from types import FunctionType, SimpleNamespace
import unittest
from unittest import mock

import test_installed_legacy_native_tui as legacy


MESSAGE = "legacy seed initialization changed process or attachment"


def fixture():
    owner_id = "a" * 64
    endpoint = Path("/synthetic") / ("omux-owner-" + owner_id[:16]) / "owner.sock"
    reference = {
        "owner_id": owner_id, "adapter_epoch": "1", "endpoint_generation": "1",
        "thread_instance_generation": "1", "attachment_generation": "1",
    }
    thread = {
        "thread_id": "00000000-0000-0000-0000-000000000001",
        "native_ref": reference, "thread_instance_generation": "1",
        "attachment_generation": "1",
    }
    owner = {
        "owner_id": owner_id, "process_nonce": "b" * 64,
        "owner_endpoint": str(endpoint), "support": "compatible_hook",
        "endpoint_generation": "1", "threads": [thread],
        "private_metadata": "synthetic-private-bait",
    }
    found = {"installed": True, "native_support": False, "hook_compatible": True,
             "owners": [owner]}
    attached = {"owner": owner, "thread_id": thread["thread_id"], "reference": reference}
    return endpoint, found, attached


class SeedAttachmentModels(unittest.TestCase):
    def scope(self, found, expected, *, pid=123, fault=None):
        # Copy the actual predicate and its original handler/finally. Only the
        # unrelated native work is removed; no child, RPC or native fixture runs.
        module = ast.parse(Path(legacy.__file__).read_text())
        inside = next(node for node in module.body
                      if isinstance(node, ast.FunctionDef) and node.name == "inside")
        scope = copy.deepcopy(next(node for node in inside.body
                                   if isinstance(node, ast.Try) and node.finalbody))
        # The seeded predicate now lives in the explicit seeded else branch.
        # Locate its actual enclosing statement list, retaining the original
        # PID short circuit and adjacent diagnostic assignments unchanged.
        matches = [(statements, index) for parent in ast.walk(scope)
                   for _, statements in ast.iter_fields(parent) if isinstance(statements, list)
                   for index, node in enumerate(statements)
                   if isinstance(node, ast.Expr) and isinstance(node.value, ast.Call)
                   and isinstance(node.value.func, ast.Name) and node.value.func.id == "require"
                   and any(isinstance(value, ast.Constant) and value.value == MESSAGE
                           for value in node.value.args)]
        self.assertEqual(len(matches), 1, "exact seeded predicate must remain unique")
        statements, predicate = matches[0]
        scope.body = statements[predicate - 1:predicate + 2]
        source = ast.parse("def fixture_scope():\n    global DIAGNOSTIC\n    pass\n")
        source.body[0].body[-1:] = [scope]
        source = ast.fix_missing_locations(source)
        endpoint, _, _ = fixture()
        events = []
        primary = ValueError("synthetic-private-primary-bait")
        tails = []
        failed_messages = []

        def require(condition, message):
            if not condition:
                failed_messages.append(message)
                try:
                    raise primary
                except ValueError:
                    tails.append(sys.exc_info()[2])
                    raise

        def cli(*args, **kwargs):
            events.append("rpc")
            if fault is not None:
                try:
                    raise fault
                except BaseException:
                    tails.append(sys.exc_info()[2])
                    raise
            return found

        request = mock.Mock(side_effect=cli)
        anchor = SimpleNamespace(process=SimpleNamespace(pid=pid),
                                 close=lambda: events.append("cleanup-bootstrap"))
        namespace = dict(legacy.__dict__)
        namespace.update(
            cli=request, endpoint=endpoint, first=expected, first_pid=123,
            bootstrap_native=anchor, terminal=None, daemon=None,
            keyring_process=None, drains=[], census=object(),
            native_threads=SimpleNamespace(
                emit_failure=lambda value, emit: events.append("failure-hook"),
                close=lambda value, primary: events.append("census-close")),
            support=SimpleNamespace(stop=lambda owned: self.fail("unexpected process stop")),
            sys=SimpleNamespace(stderr=io.StringIO(), exc_info=sys.exc_info),
            require=require, PHASE="native-seed-history", DIAGNOSTIC="unclassified",
            failed_messages=failed_messages,
        )
        exec(compile(source, "declared-seed-predicate-model", "exec"), namespace)
        # Execute the imported real helper code against isolated model globals;
        # do not mirror or regenerate its RPC/equality/projection boundary.
        for name in ("discovered_attachment", "seed_history_attachment_difference",
                     "seed_history_attachment"):
            helper = getattr(legacy, name)
            namespace[name] = FunctionType(helper.__code__, namespace, name,
                                          helper.__defaults__, helper.__closure__)
        return namespace["fixture_scope"], namespace, request, events, primary, tails, anchor

    def failure(self, run, namespace, events, expected, diagnostic, tails=None):
        try:
            run()
        except BaseException as error:
            self.assertTrue(error is expected, "primary/control exception object changed")
            if tails:
                tail = error.__traceback__
                while tail.tb_next is not None:
                    tail = tail.tb_next
                self.assertTrue(tail is tails[0], "original traceback tail changed")
        else:
            self.fail("original failing predicate or exception admitted")
        self.assertEqual(namespace["DIAGNOSTIC"], diagnostic)
        self.assertEqual(namespace["PHASE"], "native-seed-history")
        self.assertEqual(events[-3:], ["failure-hook", "cleanup-bootstrap", "census-close"])
        self.assertEqual(namespace["sys"].stderr.getvalue(), "")
        self.assertIn(diagnostic, legacy.DIAGNOSTICS)
        if namespace["failed_messages"] and diagnostic != "seed-history-discovery-validation":
            self.assertEqual(namespace["failed_messages"], [MESSAGE])

    def test_pid_short_circuit_makes_zero_discovery_calls(self):
        _, found, expected = fixture()
        run, namespace, request, events, primary, tails, anchor = self.scope(
            found, expected, pid=124)
        self.failure(run, namespace, events, primary, "seed-history-process", tails)
        request.assert_not_called()
        self.assertTrue(namespace["bootstrap_native"] is anchor)

    def test_equal_complete_attachment_calls_original_rpc_once(self):
        _, found, expected = fixture()
        run, namespace, request, events, _, _, _ = self.scope(found, copy.deepcopy(expected))
        run()
        request.assert_called_once_with("integrations.discover", {"adapter": "codex"})
        self.assertEqual(namespace["DIAGNOSTIC"], "unclassified")
        self.assertEqual(events, ["rpc", "cleanup-bootstrap", "census-close"])

    def test_absence_identity_reference_and_other_remain_original_failures(self):
        for changed in ("no-thread", "no-reference", "thread", "owner", "nonce",
                        "endpoint", "reference", "other"):
            _, found, expected = fixture()
            expected = copy.deepcopy(expected)
            category = "other"
            if changed == "no-thread":
                found["owners"][0]["threads"] = []
                category = "absent"
            elif changed == "no-reference":
                found["owners"][0]["threads"][0]["native_ref"] = None
                category = "absent"
            elif changed == "thread":
                expected["thread_id"] = "00000000-0000-0000-0000-000000000002"
                category = "identity"
            elif changed in ("owner", "nonce", "endpoint"):
                field = {"owner": "owner_id", "nonce": "process_nonce",
                         "endpoint": "owner_endpoint"}[changed]
                expected["owner"][field] = "synthetic-private-difference"
                category = "identity"
            elif changed == "reference":
                expected["reference"]["adapter_epoch"] = "2"
                category = "reference"
            else:
                expected["owner"]["private_metadata"] = "synthetic-private-difference"
            with self.subTest(case=changed):
                run, namespace, request, events, primary, tails, _ = self.scope(found, expected)
                self.failure(run, namespace, events, primary,
                             "seed-history-attachment-" + category, tails)
                request.assert_called_once_with("integrations.discover", {"adapter": "codex"})

    def test_rpc_and_unchanged_validation_exceptions_keep_original_objects(self):
        for stage in ("rpc", "validation"):
            _, found, expected = fixture()
            fault = ValueError("synthetic-private-rpc-bait") if stage == "rpc" else None
            if stage == "validation":
                found["installed"] = False
            run, namespace, request, events, primary, tails, _ = self.scope(
                found, expected, fault=fault)
            self.failure(run, namespace, events, fault if fault is not None else primary,
                         "seed-history-discovery-" + stage, tails)
            request.assert_called_once_with("integrations.discover", {"adapter": "codex"})

    def test_full_equality_runs_once_and_preserves_equality_exception(self):
        for fault in (None, RuntimeError("synthetic-private-equality-bait"),
                      KeyboardInterrupt(), SystemExit()):
            _, found, expected = fixture()
            run, namespace, request, events, primary, tails, _ = self.scope(found, expected)
            equality_calls = []

            class Compared:
                def __eq__(self, other):
                    equality_calls.append(other)
                    if fault is not None:
                        try:
                            raise fault
                        except BaseException:
                            tails.append(sys.exc_info()[2])
                            raise
                    return False

                def __repr__(self):
                    raise AssertionError("private state representation requested")

            observed = Compared()
            original_discovery = namespace["discovered_attachment"]

            def discovery(cli, endpoint):
                original_discovery(cli, endpoint)
                return observed

            namespace["discovered_attachment"] = discovery
            diagnostic = ("seed-history-attachment-comparison" if fault is not None
                          else "seed-history-attachment-other")
            self.failure(run, namespace, events, fault if fault is not None else primary,
                         diagnostic, tails)
            self.assertEqual(len(equality_calls), 1)
            self.assertTrue(equality_calls[0] is expected)
            request.assert_called_once_with("integrations.discover", {"adapter": "codex"})

    def test_rpc_response_forwarded_unchanged_and_true_equality_once(self):
        _, found, expected = fixture()
        run, namespace, request, events, _, _, _ = self.scope(found, expected)
        comparisons = []

        class Compared:
            def __eq__(self, other):
                comparisons.append(other)
                return True

        def discovery(cli, endpoint):
            self.assertTrue(cli("integrations.discover", {"adapter": "codex"}) is found,
                            "original RPC response object changed")
            return Compared()

        namespace["discovered_attachment"] = discovery
        projection = mock.Mock(side_effect=AssertionError("equal state projected"))
        namespace["seed_history_attachment_difference"] = projection
        run()
        self.assertEqual(len(comparisons), 1)
        self.assertTrue(comparisons[0] is expected)
        projection.assert_not_called()
        request.assert_called_once_with("integrations.discover", {"adapter": "codex"})
        self.assertEqual(namespace["DIAGNOSTIC"], "unclassified")
        self.assertEqual(events, ["rpc", "cleanup-bootstrap", "census-close"])

    def test_projection_ordinary_fault_cannot_weaken_full_dict_predicate(self):
        _, found, _ = fixture()
        # The unchanged full comparison is false; this malformed private shape
        # then raises KeyError during the optional projection.
        run, namespace, request, events, primary, tails, _ = self.scope(found, {})
        self.failure(run, namespace, events, primary, "seed-history-attachment-other", tails)
        request.assert_called_once_with("integrations.discover", {"adapter": "codex"})

    def test_projection_control_reaches_original_owned_cleanup(self):
        for control in (KeyboardInterrupt(), SystemExit()):
            _, found, expected = fixture()
            expected = copy.deepcopy(expected)
            expected["owner"]["private_metadata"] = "synthetic-private-difference"
            run, namespace, request, events, _, tails, anchor = self.scope(found, expected)

            def projection(*args):
                try:
                    raise control
                except BaseException:
                    tails.append(sys.exc_info()[2])
                    raise

            namespace["seed_history_attachment_difference"] = projection
            self.failure(run, namespace, events, control, "seed-history-attachment-other", tails)
            request.assert_called_once_with("integrations.discover", {"adapter": "codex"})
            self.assertTrue(namespace["bootstrap_native"] is anchor)

    def test_failure_hook_control_never_replaces_existing_rpc_primary(self):
        for control in (RuntimeError(), KeyboardInterrupt(), SystemExit()):
            _, found, expected = fixture()
            fault = ValueError("synthetic-private-rpc-bait")
            run, namespace, _, events, _, tails, _ = self.scope(found, expected, fault=fault)

            def emission(*args):
                events.append("failure-hook")
                raise control

            namespace["native_threads"].emit_failure = emission
            self.failure(run, namespace, events, fault, "seed-history-discovery-rpc", tails)

    def test_projection_does_not_render_private_metadata(self):
        _, found, expected = fixture()
        expected = copy.deepcopy(expected)

        class Private:
            def __eq__(self, other):
                return False

            def __str__(self):
                raise AssertionError("private state string requested")

            def __repr__(self):
                raise AssertionError("private state representation requested")

        found["owners"][0]["private_metadata"] = Private()
        run, namespace, _, events, primary, tails, _ = self.scope(found, expected)
        self.failure(run, namespace, events, primary, "seed-history-attachment-other", tails)
        for label in legacy.SEED_ATTACHMENT_DIAGNOSTICS:
            self.assertIn(label, legacy.DIAGNOSTICS)
            self.assertTrue(label.isascii() and len(label) <= 64)


if __name__ == "__main__":
    unittest.main()
