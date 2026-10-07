"""Pure runner boundary tests: these never launch Nix."""
import unittest
from unittest.mock import Mock, patch
from types import SimpleNamespace
import os
import subprocess
from contextlib import contextmanager

import evaluation_runner as runner

from evaluation_runner import EvaluationFailure, checked_inputs, checked_source, command, evaluator_environment, failure_category, hash_command, sanitize_diagnostic


class EvaluationRunnerTests(unittest.TestCase):
    @contextmanager
    def fake_evaluator(self, clock, *, selecting=None, reading=None, waiting=None,
                       spawn_advance=0, payload=b'{"checked":true}'):
        process = Mock(pid=12345, returncode=None)
        process.stdout.fileno.return_value = 10
        process.stderr.fileno.return_value = 11
        events, timeouts, cleanup_timeouts, keys = [], [], [], {}
        packets = {10: [payload, b""], 11: [b""]}
        selector = Mock()
        selector.__enter__ = Mock(return_value=selector)
        selector.__exit__ = Mock(return_value=False)
        def register(stream, mask, data):
            keys[stream.fileno()] = SimpleNamespace(fileobj=stream, data=data)
        def select(timeout):
            timeouts.append(timeout)
            if selecting is not None:
                selecting(len(timeouts), timeout)
            return [(key, runner.selectors.EVENT_READ) for key in list(keys.values())]
        def read(fd, maximum):
            self.assertEqual(maximum, 4096)
            packet = packets[fd].pop(0)
            if reading is not None:
                reading(fd, packet)
            return packet
        def spawn(*args, **kwargs):
            clock[0] += spawn_advance
            return process
        def reap(**kwargs):
            self.assertEqual(set(kwargs), {"timeout"})
            self.assertGreater(kwargs["timeout"], 0)
            self.assertLessEqual(kwargs["timeout"], 5)
            cleanup_timeouts.append(kwargs["timeout"])
            events.append("reap")
            process.returncode = 0
            return 0
        selector.register.side_effect = register
        selector.get_map.side_effect = lambda: keys
        selector.unregister.side_effect = lambda stream: keys.pop(stream.fileno())
        selector.select.side_effect = select
        process.wait.side_effect = reap
        process.stdout.close.side_effect = lambda: events.append("stdout-close")
        process.stderr.close.side_effect = lambda: events.append("stderr-close")
        status = SimpleNamespace(si_status=0, si_code=os.CLD_EXITED)
        with (patch.object(runner.time, "monotonic", side_effect=lambda: clock[0]),
              patch.object(runner.time, "sleep", side_effect=lambda seconds: clock.__setitem__(0, clock[0] + seconds)),
              patch.object(runner.subprocess, "Popen", side_effect=spawn) as launched,
              patch.object(runner.selectors, "DefaultSelector", return_value=selector),
              patch.object(runner.os, "read", side_effect=read) as reads,
              patch.object(runner.os, "waitid", side_effect=waiting or (lambda *args: status)) as observed,
              patch.object(runner.os, "getpgid", return_value=process.pid),
              patch.object(runner.os, "killpg", side_effect=lambda *args: events.append("signal")),
              patch.object(runner.signal, "getsignal", return_value=0),
              patch.object(runner.signal, "signal", return_value=0) as signals,
              patch.object(runner, "wait_unreaped", wraps=runner.wait_unreaped) as leader_wait):
            yield SimpleNamespace(process=process, events=events, timeouts=timeouts,
                                  cleanup_timeouts=cleanup_timeouts, selector=selector,
                                  launched=launched, reads=reads, observed=observed,
                                  signals=signals, leader_wait=leader_wait)

    def assert_evaluator_cleanup(self, evidence):
        self.assertEqual(evidence.events, ["signal", "reap", "stdout-close", "stderr-close"])
        evidence.selector.close.assert_called_once_with()
        self.assertTrue(all(call.args[2] & os.WNOWAIT for call in evidence.observed.call_args_list))
        self.assertEqual(evidence.signals.call_count, 6)  # Three saved handlers restored.

    def test_expired_and_nonfinite_enclosing_deadlines_refuse_before_spawn(self):
        for deadline in (99, 100, 101, 105, -1, float("nan"), float("inf"), -float("inf"),
                         True, "private deadline", {}, 10 ** 10000):
            with self.subTest(kind=type(deadline).__name__), \
                    patch.object(runner.time, "monotonic", return_value=100), \
                    patch.object(runner.subprocess, "Popen") as launched:
                with self.assertRaises(EvaluationFailure) as failure:
                    runner.evaluate(["/private/nix", "private-expression"], "/private/home",
                                    deadline=deadline)
                self.assertIn(failure.exception.category, {"evaluation-deadline", "evaluation-deadline-input"})
                self.assertEqual(failure.exception.phase, "module-evaluation")
                self.assertEqual(failure.exception.diagnostic, "")
                self.assertNotIn("private", str(failure.exception))
                launched.assert_not_called()

    def test_default_and_later_deadline_keep_original_sixty_second_cap_and_hash_api(self):
        for deadline in (None, 1000):
            clock = [100.0]
            with self.subTest(deadline=deadline), \
                    self.fake_evaluator(clock, spawn_advance=2, payload=b"sha256-modeled\n") as evidence:
                self.assertEqual(runner.evaluate(["/declared/nix"], "/private/home", "sha256-modeled",
                                                deadline=deadline), {"lockedSourceNar": True})
                self.assertEqual(evidence.leader_wait.call_args.args[1], 160.0)
                self.assertEqual(evidence.cleanup_timeouts, [5])
                self.assert_evaluator_cleanup(evidence)

    def test_enclosing_deadline_clips_select_and_survives_output_reads_without_renewal(self):
        clock = [100.0]
        deadline = 106.25
        def selecting(count, timeout):
            clock[0] = 100.5 if count == 1 else deadline - 5
        with self.fake_evaluator(clock, selecting=selecting) as evidence:
            with self.assertRaises(EvaluationFailure) as failure:
                runner.evaluate(["/declared/nix"], "/private/home", deadline=deadline)
            self.assertEqual(failure.exception.category, "evaluation-deadline")
            self.assertEqual(evidence.timeouts, [1, 0.75])
            self.assertEqual(evidence.reads.call_count, 2)  # Readiness at expiry cannot authorize another read.
            evidence.leader_wait.assert_not_called()
            self.assert_evaluator_cleanup(evidence)

    def test_last_pipe_read_cannot_renew_enclosing_deadline_for_leader_wait(self):
        clock = [100.0]
        deadline = 105.25
        def reading(fd, packet):
            if fd == 10 and not packet:
                clock[0] = deadline - 5
        with self.fake_evaluator(clock, reading=reading) as evidence:
            with self.assertRaises(EvaluationFailure) as failure:
                runner.evaluate(["/declared/nix"], "/private/home", deadline=deadline)
            self.assertEqual(failure.exception.category, "evaluation-deadline")
            evidence.leader_wait.assert_not_called()
            self.assert_evaluator_cleanup(evidence)

    def test_leader_poll_uses_clipped_deadline_and_keeps_owned_group_cleanup(self):
        clock = [100.0]
        deadline = 105.02
        with self.fake_evaluator(clock, waiting=lambda *args: None) as evidence:
            with self.assertRaises(subprocess.TimeoutExpired):
                runner.evaluate(["/declared/nix"], "/private/home", deadline=deadline)
            self.assertEqual(evidence.leader_wait.call_args.args[1], deadline - 5)
            self.assertGreaterEqual(clock[0], deadline - 5)
            self.assert_evaluator_cleanup(evidence)

    def test_zero_exit_observed_after_deadline_cannot_admit_success(self):
        clock = [100.0]
        deadline = 105.25
        def waiting(*args):
            clock[0] = deadline - 5
            return SimpleNamespace(si_status=0, si_code=os.CLD_EXITED)
        with self.fake_evaluator(clock, waiting=waiting) as evidence:
            with self.assertRaises(EvaluationFailure) as failure:
                runner.evaluate(["/declared/nix"], "/private/home", deadline=deadline)
            self.assertEqual(failure.exception.category, "evaluation-deadline")
            self.assertEqual(evidence.leader_wait.call_args.args[1], deadline - 5)
            self.assert_evaluator_cleanup(evidence)

    def test_shared_cleanup_wait_is_clipped_to_original_enclosing_deadline(self):
        clock, observations = [100.0], [0]
        deadline = 108.0
        def waiting(*args):
            observations[0] += 1
            clock[0] = 102.0 if observations[0] == 1 else 104.0
            return SimpleNamespace(si_status=0, si_code=os.CLD_EXITED)
        with self.fake_evaluator(clock, waiting=waiting) as evidence:
            def reaping(**kwargs):
                self.assertEqual(kwargs, {"timeout": 4.0})
                evidence.cleanup_timeouts.append(kwargs["timeout"])
                clock[0] = 107.0
                evidence.events.append("reap")
                evidence.process.returncode = 0
                return 0
            evidence.process.wait.side_effect = reaping
            self.assertEqual(runner.evaluate(["/declared/nix"], "/private/home", deadline=deadline),
                             {"checked": True})
            self.assertEqual(evidence.leader_wait.call_args.args[1], 103.0)
            self.assertEqual(evidence.cleanup_timeouts, [4.0])
            self.assert_evaluator_cleanup(evidence)

    def test_cleanup_crossing_original_enclosing_deadline_cannot_admit_zero_exit(self):
        for deadline, cleanup_bound in ((108.0, 108.0), (1000.0, 165.0), (None, 165.0)):
            clock = [100.0]
            with self.subTest(deadline=deadline), self.fake_evaluator(clock) as evidence:
                def late_reaping(**kwargs):
                    self.assertLessEqual(kwargs["timeout"], 5)
                    evidence.events.append("reap")
                    evidence.process.returncode = 0
                    clock[0] = cleanup_bound
                    return 0
                evidence.process.wait.side_effect = late_reaping
                with self.assertRaises(EvaluationFailure) as failure:
                    runner.evaluate(["/declared/nix"], "/private/home", deadline=deadline)
                self.assertEqual(failure.exception.category, "evaluation-cleanup-refused")
                self.assertEqual(failure.exception.cleanup_category, "cleanup-deadline")
                self.assert_evaluator_cleanup(evidence)

    def test_cleanup_wait_timeout_preserves_primary_and_still_closes_and_restores(self):
        clock = [100.0]
        primary = EvaluationFailure("module-evaluation", "evaluation-output-bound",
                                    stderr=b"error: token=private-material at /private/source")
        with self.fake_evaluator(clock) as evidence:
            evidence.selector.select.side_effect = primary
            def failed_wait(**kwargs):
                self.assertEqual(kwargs, {"timeout": 5})
                evidence.events.append("wait-timeout")
                raise subprocess.TimeoutExpired("private-cleanup-command", 5, output=b"private-output")
            evidence.process.wait.side_effect = failed_wait
            with self.assertRaises(EvaluationFailure) as failure:
                runner.evaluate(["/declared/nix"], "/private/home", deadline=108)
            self.assertIs(failure.exception, primary)
            self.assertEqual(primary.category, "evaluation-output-bound")
            self.assertEqual(primary.cleanup_category, "cleanup-deadline")
            self.assertNotIn("private", primary.diagnostic + str(primary) + primary.cleanup_category)
            self.assertEqual(evidence.events, ["signal", "wait-timeout", "stdout-close", "stderr-close"])
            self.assertEqual(evidence.signals.call_count, 6)

    def test_cleanup_ownership_refusal_still_closes_restores_and_never_passes(self):
        clock = [100.0]
        with self.fake_evaluator(clock) as evidence, \
                patch.object(runner.os, "getpgid", return_value=evidence.process.pid + 1):
            with self.assertRaises(EvaluationFailure) as failure:
                runner.evaluate(["/declared/nix"], "/private/home", deadline=108)
            self.assertEqual(failure.exception.category, "evaluation-cleanup-refused")
            self.assertEqual(failure.exception.cleanup_category, "cleanup-ownership-refusal")
            self.assertEqual(evidence.events, ["stdout-close", "stderr-close"])
            evidence.process.wait.assert_not_called()
            self.assertEqual(evidence.signals.call_count, 6)

    def test_selector_close_refusal_preserves_primary_and_other_owned_releases(self):
        clock = [100.0]
        primary = EvaluationFailure("module-evaluation", "evaluation-output-bound")
        with self.fake_evaluator(clock) as evidence:
            evidence.selector.select.side_effect = primary
            evidence.selector.close.side_effect = OSError("private selector close refusal")
            with self.assertRaises(EvaluationFailure) as failure:
                runner.evaluate(["/declared/nix"], "/private/home", deadline=108)
            self.assertIs(failure.exception, primary)
            self.assertEqual(primary.cleanup_category, "cleanup-io-refusal")
            self.assert_evaluator_cleanup(evidence)

    def test_after_install_failure_or_interruption_restores_already_recorded_handlers(self):
        for primary in (ValueError("private handler installation refusal"), KeyboardInterrupt()):
            clock, signals, installed = [100.0], [], {}
            def changing(signum, handler):
                signals.append(signum)
                installed[signum] = handler
                if len(signals) == 2:
                    raise primary  # Mutation happened before the original handler could be returned.
                return 0
            with self.subTest(kind=type(primary).__name__), self.fake_evaluator(clock) as evidence, \
                    patch.object(runner.signal, "signal", side_effect=changing):
                with self.assertRaises(type(primary)) as failure:
                    runner.evaluate(["/declared/nix"], "/private/home", deadline=108)
                self.assertIs(failure.exception, primary)
                self.assertEqual(signals, [runner.signal.SIGINT, runner.signal.SIGTERM] * 2)
                self.assertEqual(installed, {runner.signal.SIGINT: 0, runner.signal.SIGTERM: 0})
                self.assertEqual(evidence.events, ["signal", "reap", "stdout-close", "stderr-close"])

    def test_fd_close_and_handler_restore_refusals_do_not_skip_independent_releases(self):
        clock, signals = [100.0], []
        def changing(signum, handler):
            signals.append(signum)
            if len(signals) == 4:
                raise OSError("private restoration refusal")
            return 0
        with self.fake_evaluator(clock) as evidence, \
                patch.object(runner.signal, "signal", side_effect=changing):
            def failed_close():
                evidence.events.append("stdout-close")
                raise OSError("private descriptor close refusal")
            evidence.process.stdout.close.side_effect = failed_close
            with self.assertRaises(EvaluationFailure) as failure:
                runner.evaluate(["/declared/nix"], "/private/home", deadline=108)
            self.assertEqual(failure.exception.category, "evaluation-cleanup-refused")
            self.assertEqual(failure.exception.cleanup_category, "cleanup-io-refusal")
            self.assertEqual(evidence.events, ["signal", "reap", "stdout-close", "stderr-close"])
            self.assertEqual(signals, [runner.signal.SIGINT, runner.signal.SIGTERM, runner.signal.SIGHUP] * 2)

    def test_group_is_signalled_while_leader_remains_waitable(self):
        from evaluation_runner import cleanup_owned_group, wait_unreaped
        process = Mock(pid=12345, returncode=None)
        events = []
        process.wait.side_effect = lambda **kwargs: events.append('reap')
        with (patch('evaluation_runner.os.waitid', return_value=SimpleNamespace(si_status=0, si_code=os.CLD_EXITED)) as observed,
                patch('evaluation_runner.os.getpgid', return_value=12345),
                patch('evaluation_runner.os.killpg', side_effect=lambda *args: events.append('signal'))):
            self.assertEqual(wait_unreaped(process, 100), 0)
            cleanup_owned_group(process)
            self.assertTrue(all(call.args[2] & os.WNOWAIT for call in observed.call_args_list))
        self.assertEqual(events, ['signal', 'reap'])

    def test_reaped_leader_cannot_authorize_group_signal(self):
        from evaluation_runner import cleanup_owned_group
        with patch('evaluation_runner.os.killpg') as send:
            with self.assertRaises(ValueError):
                cleanup_owned_group(Mock(pid=12345, returncode=0))
            send.assert_not_called()

    source = "/nix/store/" + "a" * 32 + "-source"

    def test_source_must_be_in_declared_closure(self):
        manifest = {"system": "x86_64-linux", "packages": {"nixpkgs": {"out": self.source}}}
        self.assertEqual(checked_inputs(manifest, [self.source]), (self.source, "x86_64-linux"))
        with self.assertRaises(ValueError):
            checked_inputs(manifest, [])

    def test_missing_source_never_falls_back_to_flake_fetch(self):
        with self.assertRaises(ValueError):
            checked_inputs({"system": "x86_64-linux"}, [])

    def test_store_build_and_fetch_boundaries_are_explicit(self):
        argv = command("/declared/nix", "/declared/evaluation-tests.nix", self.source, "x86_64-linux")
        self.assertEqual(argv[argv.index("--store") + 1], "dummy://?read-only=false")
        self.assertIn("--offline", argv)
        self.assertIn("--impure", argv)
        for setting, value in [("allow-import-from-derivation", "false"), ("builders", ""), ("substituters", ""), ("max-jobs", "0")]:
            self.assertEqual(argv[argv.index(setting) + 1], value)
        self.assertNotIn("flakes", argv)
        self.assertNotIn("build", argv)

    def test_source_metadata_is_bound_to_exact_lock_node(self):
        locked = {"rev": "b" * 40, "narHash": "sha256-" + "A" * 43 + "="}
        lock = {"root": "root", "nodes": {"root": {"inputs": {"nixpkgs": "selected"}}, "selected": {"locked": locked}}}
        source = {"schemaVersion": 1, "source": self.source, "system": "x86_64-linux", "revision": locked["rev"], "narHash": locked["narHash"]}
        self.assertEqual(checked_source(source, lock), (self.source, "x86_64-linux", locked["narHash"]))
        with self.assertRaises(ValueError):
            checked_source(dict(source, revision="c" * 40), lock)

    def test_nar_hash_verification_has_no_live_store(self):
        argv = hash_command("/declared/nix", self.source)
        self.assertEqual(argv[argv.index("--store") + 1], "dummy://")
        self.assertIn("--offline", argv)
        self.assertEqual(argv[-1], self.source)

    def test_failure_retains_fixed_phase_and_status(self):
        error = EvaluationFailure("module-evaluation", "expression-attribute-or-option", 1,
                                  b"error: attribute 'stateHome' missing at /private/input/default.nix:23:1")
        self.assertEqual((error.phase, error.category, error.status),
                         ("module-evaluation", "expression-attribute-or-option", 1))
        self.assertIn("stateHome", error.diagnostic)
        self.assertNotIn("/private", error.diagnostic)
        nar = EvaluationFailure("locked-source-nar", "locked-source-nar-mismatch")
        self.assertNotEqual(error.phase, nar.phase)

    def test_public_diagnostic_removes_paths_controls_and_sensitive_lines(self):
        text = sanitize_diagnostic(b"\x1b[31merror: missing /home/private/example.nix:4\x1b[0m\n"
                                   b"url=https://private.example/path\nuser@example.org\n"
                                   b"access-token=opaque-value\n" + b"x" * 10000)
        for forbidden in ("/home", "private.example", "user@example.org", "opaque-value", "\x1b"):
            self.assertNotIn(forbidden, text)
        self.assertLessEqual(len(text.encode()), 4096)

    def test_error_categories_do_not_include_raw_stderr(self):
        self.assertEqual(failure_category(b"error: syntax error at /arbitrary/path"), "expression-syntax")
        self.assertEqual(failure_category(b"error: dummy store is read-only"), "dummy-store-capability")
        self.assertEqual(failure_category(b"error: no such file"), "declared-input-missing")

    def test_configuration_is_private_and_environment_is_explicit(self):
        environment = evaluator_environment("/private/empty-evaluation-home")
        self.assertEqual(environment, {
            "HOME": "/private/empty-evaluation-home", "PATH": "", "NIX_PATH": "", "NIX_CONFIG": "",
            "NIX_CONF_DIR": "/private/empty-evaluation-home", "NIX_USER_CONF_FILES": ""})
        self.assertNotIn("NIX_REMOTE", environment)
        self.assertNotIn("NIX_PLUGIN_FILES", environment)


if __name__ == "__main__":
    unittest.main()
