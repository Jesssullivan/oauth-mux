"""Closed peer-test admission + synthetic kernel metadata; no live qualification."""
from contextlib import ExitStack
import os
from pathlib import Path
import stat
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
import execution_guard as guard
import guard_native_seed_plan_reserved as kernel
import guard_native_peer_qualification_reserved as peer
import guard_resident_native_source_context_metadata_reserved as metadata
import guard_resident_models_reserved as models
import guard_resident_observation as resident


def fixture_ancestor(info, path):
    # Fixture-only sticky /tmp exception; production ancestor checks are unchanged.
    if path == Path("/tmp") and info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o1777:
        return
    kernel.require(stat.S_ISDIR(info.st_mode) and info.st_uid in (0, os.getuid()) and not info.st_mode & 0o022)


class PeerReservationModels(unittest.TestCase):
    def args(self):
        return SimpleNamespace(profile=peer.PROFILE, manager="system", reuse_owned_cache=False,
            source_commit="a" * 40, source_dirty="false", repository_cache=None, nixpkgs_source=None)

    def test_exact_five_tests_and_invalid_vectors_refuse_before_tools(self):
        expected = ["test", "//tools:guard_native_peer_qualification_reserved_test",
            "//:native_peer_bridge_test", "//:native_peer_test", "//:format_test", "//:docs_check"]
        self.assertEqual(peer.ARGUMENTS, expected)
        self.assertTrue(peer.request(self.args(), expected))
        self.assertEqual(peer.selected(peer.PROFILE, expected), {"PrivateNetwork": "yes"})
        invalid = [expected[:-1], ["test", *expected[2:]], ["test", *reversed(expected[1:])],
            expected + [expected[1]], ["build", *expected[1:]], ["run", *expected[1:]],
            expected + ["//:engine_test"], expected + ["--test_arg=untrusted"],
            ["test", "//..."], ["test", kernel.LABEL], metadata.ARGUMENTS, models.ARGUMENTS]
        with patch.object(guard, "immutable", side_effect=AssertionError("tool read")) as tool, \
                patch.object(peer, "Witness", side_effect=AssertionError("resident read")) as witness:
            for arguments in invalid:
                with self.assertRaises(ValueError): peer.request(self.args(), arguments)
                with self.assertRaises(ValueError):
                    guard.main(["--profile", peer.PROFILE, "--manager", "system", "--source-commit",
                        "a" * 40, "--source-dirty", "false", "--", *arguments])
            tool.assert_not_called()
            witness.assert_not_called()

    def test_unrelated_selectors_and_cross_family_admission_refuse(self):
        for name, value in (("manager", "user"), ("reuse_owned_cache", True), ("source_dirty", "true"),
                ("source_commit", "a" * 39), ("resident_manifest", Path("/model/private")),
                ("codex_live_manifest", Path("/model/live")), ("native_mode", "schema"),
                ("native_source_root", Path("/model/compiler")), ("worker", Path("/model/worker")),
                ("repository_cache", Path("/model/cache"))):
            args = self.args()
            setattr(args, name, value)
            with self.assertRaises(ValueError): peer.request(args, peer.ARGUMENTS)
        with patch.object(guard, "immutable", side_effect=AssertionError("tool read")) as tool:
            for options in (["--resident-manifest", "/model/private"], ["--native-mode", "schema"],
                    ["--native-source-root", "/model/compiler"], ["--codex-live-manifest", "/model/live"],
                    ["--reuse-owned-cache"]):
                with self.assertRaises(ValueError):
                    guard.main(["--profile", peer.PROFILE, "--manager", "system", "--source-commit",
                        "a" * 40, "--source-dirty", "false", *options, "--", *peer.ARGUMENTS])
            tool.assert_not_called()
        for helper in (metadata, models):
            with self.assertRaises(ValueError): helper.selected(helper.PROFILE, peer.ARGUMENTS)
            self.assertNotIn(peer.PROFILE, helper.PROFILES)
        for profile in kernel.PROFILES:
            with self.assertRaises(ValueError): kernel.selected(profile, peer.ARGUMENTS)
        self.assertNotIn(peer.PROFILE, kernel.PROFILES)
        self.assertIn(peer.PROFILE, kernel.WORKLOAD_PROFILES)
        args = self.args()
        args.profile = metadata.PROFILE
        self.assertFalse(peer.request(args, peer.ARGUMENTS))

    def test_actual_main_dispatches_real_closed_request_before_any_launch(self):
        original = peer.request
        class AdmissionObserved(Exception): pass
        def observe(args, arguments):
            self.assertTrue(original(args, arguments))
            raise AdmissionObserved()
        with patch.object(peer, "request", side_effect=observe) as request, \
                patch.object(guard, "immutable", side_effect=AssertionError("tool read")) as tool, \
                patch.object(guard, "controller_run", side_effect=AssertionError("controller launch")) as controller, \
                patch.object(guard, "worker", side_effect=AssertionError("worker dispatch")) as worker, \
                patch.object(guard.subprocess, "Popen", side_effect=AssertionError("worker launch")) as launch, \
                patch.object(peer, "Witness", side_effect=AssertionError("resident read")) as witness:
            with self.assertRaises(AdmissionObserved):
                guard.main(["--profile", peer.PROFILE, "--manager", "system", "--source-commit",
                    "a" * 40, "--source-dirty", "false", "--", *peer.ARGUMENTS])
            request.assert_called_once()
            tool.assert_not_called()
            controller.assert_not_called()
            worker.assert_not_called()
            launch.assert_not_called()
            witness.assert_not_called()

    def test_actual_command_constructor_is_fresh_offline_and_standard(self):
        with patch.object(kernel.time, "monotonic_ns", return_value=200 * 10**9):
            command = peer.command(guard.bazel_command, "bazel", Path("/model/epoch"), peer.ARGUMENTS,
                peer.PROFILE, 100 * 10**9, 1300 * 10**9)
        self.assertEqual(command[-5:], peer.ARGUMENTS[1:])
        for value in ("--repository_disable_download", "--repo_contents_cache=", "--lockfile_mode=error",
                "--sandbox_default_allow_network=false", "--remote_executor=", "--remote_cache=",
                "--nocache_test_results", "--output_base=/model/epoch/output-base"):
            self.assertIn(value, command)
        builder = Mock()
        with patch.object(kernel.time, "monotonic_ns", return_value=200 * 10**9):
            for kwargs in ({"output_base": Path("/model/reused")}, {"repository_cache": Path("/model/cache")}):
                with self.assertRaises(ValueError): peer.command(builder, "bazel", Path("/model/epoch"),
                    peer.ARGUMENTS, peer.PROFILE, 100 * 10**9, 1300 * 10**9, **kwargs)
            with self.assertRaises(ValueError): peer.command(builder, "bazel", Path("/model/epoch"),
                peer.ARGUMENTS, "codex-native", 100 * 10**9, 1300 * 10**9)
        builder.assert_not_called()

    def test_original_1200_second_envelope_and_30_second_reserve_never_reset(self):
        entry, deadline = 100 * 10**9, 1300 * 10**9
        self.assertEqual(kernel.RESERVE_NS, 30 * 10**9)
        self.assertEqual(kernel.envelope(entry, deadline), 1270 * 10**9)
        for bad_entry, bad_deadline in ((True, deadline), (entry, deadline + 1), (0, 1200 * 10**9)):
            with self.assertRaises(ValueError): peer.remaining(bad_entry, bad_deadline)
        with patch.object(kernel.time, "monotonic_ns", return_value=entry - 1):
            with self.assertRaises(ValueError): peer.remaining(entry, deadline)
        with patch.object(kernel.time, "monotonic_ns", return_value=1270 * 10**9):
            builder = Mock()
            with self.assertRaises(ValueError): peer.command(builder, "bazel", Path("/model/epoch"),
                peer.ARGUMENTS, peer.PROFILE, entry, deadline)
            builder.assert_not_called()
            self.assertEqual(peer.remaining(entry, deadline, cleanup=True), 30)
        with patch.object(kernel.time, "monotonic_ns", return_value=deadline):
            with self.assertRaises(ValueError): peer.remaining(entry, deadline, cleanup=True)

    def test_actual_verify_dispatch_enforces_worker_and_resident_budget(self):
        for name in ("Witness", "WorkloadWitness", "monitor", "cleanup_retained", "release_worker", "remaining", "properties"):
            self.assertIs(getattr(peer, name), getattr(kernel, name))
        self.assertEqual((peer.MEMORY, peer.TASKS, peer.CPU), (3840 * 1024**2, 480, 190))
        self.assertEqual((resident.RESIDENT_MEMORY, resident.RESIDENT_TASKS, resident.RESIDENT_CPU_PERCENT),
            (256 * 1024**2, 32, 10))
        caps = peer.properties(guard.PROPERTIES)
        self.assertEqual(int(caps["MemoryMax"]) + resident.RESIDENT_MEMORY, 4 * 1024**3)
        self.assertEqual(int(caps["TasksMax"]) + resident.RESIDENT_TASKS, 512)
        self.assertEqual(peer.CPU + resident.RESIDENT_CPU_PERCENT, 200)
        self.assertEqual(caps["MemorySwapMax"], "0")
        self.assertEqual(caps["RemainAfterExit"], "yes")
        self.assertEqual(guard.workload_pids_observation(None, peer.PROFILE).expected_limit, 480)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name, value in guard.CGROUP.items():
                (root / name).write_text({"memory.max": str(peer.MEMORY), "pids.max": "480"}.get(name, value))
            (root / "cpu.max").write_text("190000 100000")
            actual = {**caps, **guard.SANDBOX, "RuntimeMaxUSec": "17s",
                "TemporaryFileSystem": guard.system_masks(profile="standard"),
                "UnsetEnvironment": " ".join(guard.DELEGATION_ENV)}
            guard.verify(actual, root, "system", guard.SANDBOX, peer.PROFILE, runtime_seconds=17)
            for key, value in (("PrivateNetwork", "no"), ("TasksMax", "512"), ("MemoryMax", "4294967296"),
                    ("MemorySwapMax", "1"), ("CPUQuotaPerSecUSec", "2s"), ("RuntimeMaxUSec", "1200s")):
                with self.assertRaises(ValueError): guard.verify({**actual, key: value}, root, "system",
                    guard.SANDBOX, peer.PROFILE, runtime_seconds=17)
            for name, bad in (("memory.max", "4294967296"), ("pids.max", "512"),
                    ("memory.swap.max", "1"), ("cpu.max", "200000 100000")):
                original = (root / name).read_text()
                (root / name).write_text(bad)
                with self.assertRaises(ValueError): guard.verify(actual, root, "system", guard.SANDBOX,
                    peer.PROFILE, runtime_seconds=17)
                (root / name).write_text(original)

    def test_real_resident_constructor_retains_own_pidfd_and_refuses_caps_drift(self):
        with ExitStack() as stack:
            root = Path(stack.enter_context(tempfile.TemporaryDirectory())) / "group"
            root.mkdir(mode=0o700)
            values = {"memory.max": "268435456", "memory.swap.max": "0", "pids.max": "32",
                "cpu.max": "10000 100000", "cgroup.procs": str(os.getpid()),
                "pids.current": "1", "cgroup.events": "populated 1\nfrozen 0"}
            for name, value in values.items(): (root / name).write_text(value + "\n")
            stack.enter_context(patch.object(kernel, "cgroup_path", lambda uid: root))
            stack.enter_context(patch.object(kernel, "ancestor", fixture_ancestor))
            entry = time.monotonic_ns()
            witness = peer.Witness(entry, entry + 1200 * 10**9)
            stack.callback(witness.close)
            self.assertEqual([row[0] for row in witness.processes], [os.getpid()])
            result = witness.complete(0, True, True, True)
            self.assertIs(result["initial_direct_processes_retained"], True)
            self.assertIs(result["resident_signalled"], False)
            self.assertIs(result["installation_qualified"], False)
            (root / "pids.max").write_text("33\n")
            with self.assertRaises(ValueError): witness.observe()
            (root / "pids.max").write_text("32\n")
            for arguments in ((1, True, True, True), (0, False, True, True),
                    (0, True, False, True), (0, True, True, False)):
                with self.assertRaises(ValueError): witness.complete(*arguments)
            with patch.object(kernel.time, "monotonic_ns", return_value=witness.deadline):
                with self.assertRaises(ValueError): witness.complete(0, True, True, True)

    def test_receipt_projection_never_promotes_sdk_compiler_or_continuity(self):
        for verified in (None, False, True):
            row = peer.projection(100 * 10**9, 1300 * 10**9, verified, {"custody_observed": False})
            self.assertEqual(row["scope"], "fixed-native-peer-qualification-reserved-v1")
            self.assertEqual(row["mode"], "native-peer-fixture-tests")
            self.assertIs(row["verified_after_cleanup"], verified)
            self.assertIs(row["peer_test_qualification_requires_matching_outer_success"], True)
            self.assertTrue(all(row[name] is False for name in ("peer_test_qualification", "native_runtime_qualified",
                "sdk_qualified", "compiler_qualified", "schema_qualified", "native_source_finalized", "custody_qualified",
                "health_qualified", "continuity_qualified", "live_qualified", "context_rotation",
                "daemon_context_acquisition", "credential_acquisition", "native_build_qualified")))
        with self.assertRaises(ValueError): peer.projection(100 * 10**9, 1300 * 10**9, 1, {})
        with self.assertRaises(ValueError): peer.projection(100 * 10**9, 1301 * 10**9, True, {})


if __name__ == "__main__":
    unittest.main()
