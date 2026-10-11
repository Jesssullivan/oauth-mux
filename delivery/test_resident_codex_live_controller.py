"""Public filesystem models; no service, credential or native execution."""
import copy
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import resident_codex_live_controller as controller


class ResidentProfileProducerTest(unittest.TestCase):
    def profile(self, root):
        return controller.ProofProfile(root, "public-test-model",
            {"files": {"bin/codex": {"mode": 0o755}}},
            {"bin/codex": b"public synthetic executable bytes; never executed"})

    def test_existing_profile_is_refused_before_any_write(self):
        with tempfile.TemporaryDirectory(prefix="omux-rp-") as root:
            path = Path(root)
            original = path / "retained-history"
            original.write_bytes(b"public accepted history model")
            with self.assertRaises(Exception):
                self.profile(path)
            self.assertEqual(original.read_bytes(), b"public accepted history model")
            self.assertEqual(sorted(item.name for item in path.iterdir()), ["retained-history"])

    def test_fresh_profile_never_inherits_working_auth_environment(self):
        with tempfile.TemporaryDirectory(prefix="omux-rp-") as root:
            profile = self.profile(Path(root))
            try:
                environment = profile.environment()
                self.assertEqual(environment["CODEX_HOME"], str(Path(root) / "c"))
                self.assertEqual(environment["PATH"], "/nonexistent")
                self.assertNotIn("OPENAI_API_KEY", environment)
                self.assertNotIn("OMUX_ADAPTER_CAPABILITY", environment)
                self.assertFalse((profile.home / "auth.json").exists())
                text = profile.config.read_text()
                self.assertNotIn("[omux_broker]", text)
                self.assertIn('sandbox_mode = "read-only"', text)
                self.assertIn('approval_policy = "never"', text)
            finally:
                profile.close()
            self.assertTrue((Path(root) / "c/config.toml").exists())

    def test_artifact_replacement_is_detected_before_native_execution(self):
        with tempfile.TemporaryDirectory(prefix="omux-rp-") as root:
            profile = self.profile(Path(root))
            try:
                replacement = profile.binary.with_name("replacement")
                replacement.write_bytes(b"public replacement bytes")
                replacement.chmod(0o755)
                os.replace(replacement, profile.binary)
                with self.assertRaises(Exception):
                    profile.recheck()
            finally:
                profile.close()

    def test_no_copied_auth_is_accepted_in_owned_native_home(self):
        with tempfile.TemporaryDirectory(prefix="omux-rp-") as root:
            profile = self.profile(Path(root))
            try:
                (profile.home / "auth.json").write_bytes(b"public forbidden source model")
                with self.assertRaises(Exception):
                    profile.recheck()
            finally:
                profile.close()

    def test_dangling_auth_alias_is_refused_without_reading_its_target(self):
        with tempfile.TemporaryDirectory(prefix="omux-rp-") as root:
            profile = self.profile(Path(root))
            try:
                target = Path(root) / "absent-public-model"
                (profile.home / "auth.json").symlink_to(target)
                self.assertFalse(target.exists())
                with self.assertRaises(ValueError):
                    profile.recheck()
                self.assertFalse(target.exists())
            finally:
                profile.close()

    def test_native_home_replacement_is_refused_even_with_identical_config(self):
        with tempfile.TemporaryDirectory(prefix="omux-rp-") as root:
            profile = self.profile(Path(root))
            try:
                configured = profile.config.read_bytes()
                profile.home.rename(Path(root) / "retained-c")
                profile.home.mkdir(mode=0o700)
                profile.config.write_bytes(configured)
                profile.config.chmod(0o600)
                with self.assertRaises(Exception):
                    profile.recheck()
            finally:
                profile.close()

    def test_symlink_root_does_not_redirect_profile_writes(self):
        with tempfile.TemporaryDirectory(prefix="omux-rp-") as root:
            path = Path(root)
            target = path / "existing"
            target.mkdir(mode=0o700)
            link = path / "alias"
            link.symlink_to(target, target_is_directory=True)
            with self.assertRaises(Exception):
                self.profile(link)
            self.assertEqual(list(target.iterdir()), [])

    def test_bootstrap_setup_failure_closes_only_its_spawned_child(self):
        context = mock.Mock()
        context.remaining.return_value = 100
        process, diagnostics = mock.Mock(), mock.Mock()
        with mock.patch.object(controller.support, "DiscardLog", return_value=diagnostics), \
             mock.patch.object(controller.support, "stop") as stop, \
             mock.patch.object(controller.os, "set_blocking", side_effect=OSError("public failure model")):
            with self.assertRaises(OSError):
                controller.ResidentBootstrap(context, ["/public-candidate"], {}, "/public-work",
                    popen_factory=lambda *args, **kwargs: process)
        stop.assert_called_once_with(process)
        process.stdin.close.assert_called_once()
        process.stdout.close.assert_called_once()
        diagnostics.join.assert_called_once()

    def test_blocked_bootstrap_write_consumes_original_deadline_without_renewal(self):
        bootstrap = controller.ResidentBootstrap.__new__(controller.ResidentBootstrap)
        bootstrap.context = mock.Mock()
        bootstrap.context.remaining.side_effect = [1, 1, 1, ValueError("public expired model")]
        bootstrap.guard_active = True
        bootstrap.process, bootstrap.diagnostics, bootstrap.selector = mock.Mock(), mock.Mock(), mock.Mock()
        bootstrap.process.poll.return_value = None
        writable = mock.MagicMock()
        writable.__enter__.return_value = writable
        writable.select.return_value = [(object(), 1)]
        with mock.patch.object(controller.selectors, "DefaultSelector", return_value=writable), \
             mock.patch.object(controller.os, "write", side_effect=BlockingIOError) as write:
            with self.assertRaises(ValueError):
                bootstrap.send("initialize", {})
        self.assertEqual(bootstrap.context.remaining.call_count, 4)
        self.assertEqual(write.call_count, 1)

    def test_selector_cleanup_failure_still_closes_stdout_and_diagnostics(self):
        bootstrap = controller.ResidentBootstrap.__new__(controller.ResidentBootstrap)
        process, diagnostics, selector = mock.Mock(), mock.Mock(), mock.Mock()
        bootstrap.process, bootstrap.diagnostics, bootstrap.selector = process, diagnostics, selector
        selector.close.side_effect = OSError("public cleanup model")
        with mock.patch.object(controller.support, "stop") as stop:
            with self.assertRaises(OSError):
                bootstrap.close()
        stop.assert_called_once_with(process)
        process.stdin.close.assert_called_once()
        process.stdout.close.assert_called_once()
        diagnostics.join.assert_called_once()
        self.assertIsNone(bootstrap.process)
        self.assertIsNone(bootstrap.selector)
        self.assertIsNone(bootstrap.diagnostics)

    def test_recheck_consumed_allowance_refuses_native_call(self):
        context = mock.Mock()
        context.remaining.side_effect = ValueError("public expired model")
        with mock.patch.object(controller.live, "checked_native_rpc") as native:
            with self.assertRaises(ValueError):
                controller.bounded_native_rpc(context, Path("/public-endpoint"), "status", {})
        context.recheck.assert_called_once()
        native.assert_not_called()

    def native_socket_model(self):
        channel = mock.MagicMock()
        channel.__enter__.return_value = channel
        channel.getsockopt.return_value = controller.live.struct.pack("3i", 314, os.getuid(), os.getgid())
        channel.send.side_effect = lambda packet: len(packet)
        reply = controller.json.dumps({"jsonrpc": "2.0", "id": "00" * 32, "result": {}}).encode()
        channel.recvmsg.return_value = (reply, [], 0, None)
        return channel

    def test_actual_native_helper_refreshes_one_absolute_budget_per_phase(self):
        channel = self.native_socket_model()
        with mock.patch.dict(controller.live.NATIVE_PEERS, {"/public-endpoint": 314}), \
             mock.patch.object(controller.live.socket, "socket", return_value=channel), \
             mock.patch.object(controller.live.os, "urandom", return_value=bytes(32)), \
             mock.patch.object(controller.live.time, "monotonic", side_effect=[10, 11, 12, 13]):
            self.assertEqual(controller.live.checked_native_rpc(
                Path("/public-endpoint"), "status", {}, deadline=14), {})
        self.assertEqual(channel.settimeout.call_args_list, [mock.call(4), mock.call(3), mock.call(2)])

    def test_actual_native_helper_expiry_refuses_next_phase(self):
        channel = self.native_socket_model()
        with mock.patch.dict(controller.live.NATIVE_PEERS, {"/public-endpoint": 314}), \
             mock.patch.object(controller.live.socket, "socket", return_value=channel), \
             mock.patch.object(controller.live.os, "urandom", return_value=bytes(32)), \
             mock.patch.object(controller.live.time, "monotonic", side_effect=[10, 11, 14]):
            with self.assertRaises(Exception):
                controller.live.checked_native_rpc(Path("/public-endpoint"), "status", {}, deadline=14)
        channel.recvmsg.assert_not_called()

    def test_public_pin_join_rejects_mixed_runtime_and_non_integer_sizes(self):
        pin = {"kind": controller.live.FRESH_KIND,
            "archive_sha256": "a" * 64, "archive_bytes": 1,
            "receipt_sha256": "b" * 64, "receipt_bytes": 2,
            "manifest_sha256": "c" * 64, "manifest_bytes": 3}
        for mutation in ("none", "mixed", "bool", "extra"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as root:
                selected, bound = Path(root) / "pin.json", Path(root) / "bound.json"
                selected.write_text(controller.json.dumps(pin, indent=2))
                other = copy.deepcopy(pin)
                if mutation == "mixed": other["archive_sha256"] = "d" * 64
                elif mutation == "bool": other["archive_bytes"] = True
                elif mutation == "extra": other["source_path"] = "/public-forbidden-role"
                bound.write_text(controller.json.dumps(other, separators=(",", ":")))
                context = mock.Mock();context.remaining.return_value = 100
                if mutation == "none":
                    self.assertEqual(controller.qualified_runtime_pin(context, selected, bound=bound), pin)
                else:
                    with self.assertRaises(ValueError):
                        controller.qualified_runtime_pin(context, selected, bound=bound)

    def test_existing_singleton_integration_never_launches_bootstrap_or_install(self):
        context = mock.Mock()
        context.remaining.return_value = 100
        context.control.return_value = {"installed": ["codex"]}
        with mock.patch.object(controller, "ResidentBootstrap") as bootstrap:
            with self.assertRaises(ValueError):
                controller.install_native(context, mock.Mock(), {})
        bootstrap.assert_not_called()
        self.assertEqual(context.control.call_args_list, [mock.call("integrations.status")])
        context.capture_native_capability.assert_not_called()

    def test_terminal_setup_fault_closes_both_owned_pty_fds_before_launch(self):
        for phase in ("selector", "register", "launch"):
            with self.subTest(phase=phase):
                context = mock.Mock();context.remaining.return_value = 100
                selector = mock.Mock()
                if phase == "register": selector.register.side_effect = OSError("public setup fault")
                factory = mock.Mock(side_effect=OSError("public launch fault"))
                with mock.patch.object(controller.pty, "openpty", return_value=(71, 72)), \
                     mock.patch.object(controller.fcntl, "ioctl"), \
                     mock.patch.object(controller.os, "set_blocking"), \
                     mock.patch.object(controller.os, "close") as close, \
                     mock.patch.object(controller.selectors, "DefaultSelector",
                         side_effect=OSError("public selector fault") if phase == "selector" else None,
                         return_value=selector):
                    with self.assertRaises(OSError):
                        controller.ResidentTerminal(context, "/public-runtime", {}, "/public-work",
                            popen_factory=factory)
                self.assertCountEqual(close.call_args_list, [mock.call(71), mock.call(72)])
                if phase != "launch": factory.assert_not_called()

    def test_terminal_selector_cleanup_fault_still_closes_master_and_owns_group(self):
        terminal = controller.ResidentTerminal.__new__(controller.ResidentTerminal)
        terminal.context = mock.Mock();terminal.guard_active = True;terminal.closed = False
        terminal.master = 71;terminal.process = mock.Mock(pid=314)
        terminal.selector = mock.Mock();terminal.selector.close.side_effect = OSError("public cleanup fault")
        with mock.patch.object(controller.os, "waitid") as waitid, \
             mock.patch.object(controller.os, "getpgid", return_value=314), \
             mock.patch.object(controller.os, "killpg") as killpg, \
             mock.patch.object(controller.os, "close") as close:
            with self.assertRaises(OSError):
                terminal.close()
        waitid.assert_called_once()
        killpg.assert_called_once_with(314, controller.signal.SIGKILL)
        terminal.process.wait.assert_called_once_with(timeout=5)
        close.assert_called_once_with(71)
        self.assertTrue(terminal.closed)

    def test_real_rollout_predicate_precedes_rename_and_empty_export_never_qualifies(self):
        for refusal in (False, True):
            with self.subTest(refusal=refusal):
                terminal = mock.Mock();terminal.process.pid = 314
                before = ("public native metadata", (1, 2), b"digest", b"public native rollout")
                metadata = mock.Mock(side_effect=ValueError("no real rollout") if refusal else None,
                    return_value=before)
                with mock.patch.object(controller.tui, "wait_metadata", metadata), \
                     mock.patch.object(controller.tui, "status", return_value={"public": "native identity"}):
                    if refusal:
                        with self.assertRaises(ValueError):
                            controller.materialize_native_history(Path("/public-home"), "public-thread",
                                terminal, Path("/public-endpoint"), {"public": "native identity"})
                    else:
                        self.assertIs(controller.materialize_native_history(Path("/public-home"),
                            "public-thread", terminal, Path("/public-endpoint"),
                            {"public": "native identity"}), before)
                expected = [mock.call("/export omux-native-resume-fixture.md\r")]
                if not refusal: expected.append(mock.call("/rename " + controller.tui.FIXTURE_NAME + "\r"))
                self.assertEqual(terminal.send.call_args_list, expected)
                self.assertEqual(metadata.call_args_list[0], mock.call(Path("/public-home"),
                    "public-thread", terminal, expected_name=None))

    def test_bundled_catalogue_setup_fault_cleans_only_anchored_own_group(self):
        context = mock.Mock();context.remaining.return_value = 100
        process = mock.Mock(pid=314, returncode=None)
        profile, scenario = mock.Mock(), mock.Mock()
        original = controller.support.DEADLINE_SECONDS
        with mock.patch.object(controller.subprocess, "Popen", return_value=process) as launch, \
             mock.patch.object(controller.support, "bounded_private_session",
                 side_effect=OSError("public selector fault")), \
             mock.patch.object(controller.os, "waitid") as waitid, \
             mock.patch.object(controller.os, "getpgid", return_value=314), \
             mock.patch.object(controller.os, "killpg") as killpg:
            with self.assertRaises(OSError):
                controller.prepare_native_profile(context, scenario, profile, {})
        self.assertEqual(launch.call_args.args[0], [str(profile.binary), "debug", "models", "--bundled"])
        self.assertTrue(launch.call_args.kwargs["start_new_session"])
        waitid.assert_called_once()
        killpg.assert_called_once_with(314, controller.signal.SIGKILL)
        process.wait.assert_called_once_with(timeout=5)
        process.stdout.close.assert_called_once()
        process.stderr.close.assert_called_once()
        self.assertEqual(controller.support.DEADLINE_SECONDS, original)

    def test_native_helper_legacy_default_keeps_five_second_phase_bounds(self):
        channel = self.native_socket_model()
        with mock.patch.dict(controller.live.NATIVE_PEERS, {"/public-endpoint": 314}), \
             mock.patch.object(controller.live.socket, "socket", return_value=channel), \
             mock.patch.object(controller.live.os, "urandom", return_value=bytes(32)):
            self.assertEqual(controller.live.checked_native_rpc(Path("/public-endpoint"), "status", {}), {})
        self.assertEqual(channel.settimeout.call_args_list, [mock.call(5), mock.call(5), mock.call(5)])

if __name__ == "__main__":
    unittest.main()
