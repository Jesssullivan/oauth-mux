"""Real dispatcher/constructor and fixture kernel IO; no HM activation proof."""
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
import guard_home_manager_bundle_reserved as hm
import guard_native_seed_plan_reserved as kernel
import guard_resident_observation as resident


def fixture_ancestor(info, path):
    if path == Path("/tmp") and info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o1777:
        return
    kernel.require(stat.S_ISDIR(info.st_mode) and info.st_uid in (0, os.getuid()) and not info.st_mode & 0o022)


class HomeManagerReservationModels(unittest.TestCase):
    def args(self, profile):
        return SimpleNamespace(profile=profile, manager="system", reuse_owned_cache=False,
            source_commit="a" * 40, source_dirty="false", repository_cache=None, nixpkgs_source=None)

    def test_closed_singletons_and_models_refuse_expansion_before_tools(self):
        self.assertEqual(hm.COHORTS[hm.RECONSTRUCTION], ["test", "//tools:home_manager_retained_reconstruction_producer"])
        self.assertEqual(hm.COHORTS[hm.EVALUATION], ["test", "//tools:home_manager_acquired_evaluation"])
        for profile, arguments in hm.COHORTS.items():
            self.assertEqual(hm.selected(profile, arguments), {"PrivateNetwork": "yes"})
            self.assertTrue(hm.request(self.args(profile), arguments))
            for vector in ([], ["run", *arguments[1:]], arguments + ["//:docs_check"],
                    ["test", "//tools:home_manager_acquisition_producer"],
                    ["test", "//tools:home_manager_artifact_producer"]):
                with self.assertRaises(ValueError): hm.selected(profile, vector)
            for key, value in (("manager", "user"), ("reuse_owned_cache", True), ("source_dirty", "true"),
                    ("resident_manifest", "/model/private"), ("native_mode", "compile")):
                args = self.args(profile)
                setattr(args, key, value)
                with self.assertRaises(ValueError): hm.request(args, arguments)

    def test_actual_main_dispatches_closed_request_before_launch_and_resident_reads(self):
        original = hm.request
        class Admitted(Exception): pass
        def admission(args, arguments):
            self.assertTrue(original(args, arguments))
            raise Admitted()
        for profile, arguments in hm.COHORTS.items():
            with patch.object(hm, "request", side_effect=admission) as request, \
                    patch.object(guard, "immutable", side_effect=AssertionError("tool read")) as tools, \
                    patch.object(guard, "controller_run", side_effect=AssertionError("controller launch")) as control, \
                    patch.object(guard.subprocess, "Popen", side_effect=AssertionError("worker launch")) as launch, \
                    patch.object(hm, "Witness", side_effect=AssertionError("resident read")) as witness:
                with self.assertRaises(Admitted):
                    guard.main(["--profile", profile, "--manager", "system", "--source-commit", "a" * 40,
                        "--source-dirty", "false", "--", *arguments])
                request.assert_called_once()
                for boundary in (tools, control, launch, witness): boundary.assert_not_called()

    def test_real_command_constructor_inherits_original_clock_and_offline_fresh_graph(self):
        entry, end = 100 * 10**9, 1300 * 10**9
        for profile, arguments in hm.COHORTS.items():
            with patch.object(kernel.time, "monotonic_ns", return_value=200 * 10**9):
                command = hm.command(guard.bazel_command, "bazel", Path("/model/epoch"), arguments,
                    profile, entry, end)
            self.assertEqual(command[-len(arguments[1:]):], arguments[1:])
            for flag in ("--repository_disable_download", "--repo_contents_cache=", "--nocache_test_results",
                    "--sandbox_default_allow_network=false", "--remote_executor=", "--remote_cache=",
                    "--output_base=/model/epoch/output-base"):
                self.assertIn(flag, command)
            if profile != hm.MODELS:
                for name, value in (("OMUX_HM_ROOT_ENTRY_NS", entry), ("OMUX_HM_ROOT_DEADLINE_NS", end),
                        ("OMUX_HM_RESERVED_PROFILE", profile)):
                    self.assertIn("--test_env=" + name + "=" + str(value), command)
            else:
                self.assertFalse(any(flag.startswith("--test_env=OMUX_HM_") for flag in command))
        with patch.object(kernel.time, "monotonic_ns", return_value=1270 * 10**9):
            builder = Mock()
            with self.assertRaises(ValueError):
                hm.command(builder, "bazel", Path("/model/epoch"), hm.COHORTS[hm.RECONSTRUCTION],
                    hm.RECONSTRUCTION, entry, end)
            builder.assert_not_called()
            self.assertEqual(hm.remaining(entry, end, cleanup=True), 30)

    def test_actual_verify_dispatch_enforces_all_worker_and_resident_caps(self):
        self.assertEqual((hm.MEMORY, hm.TASKS, hm.CPU), (3840 * 1024**2, 480, 190))
        self.assertEqual((resident.RESIDENT_MEMORY, resident.RESIDENT_TASKS, resident.RESIDENT_CPU_PERCENT),
            (256 * 1024**2, 32, 10))
        caps = hm.properties(guard.PROPERTIES)
        self.assertEqual(int(caps["MemoryMax"]) + resident.RESIDENT_MEMORY, 4 * 1024**3)
        self.assertEqual(int(caps["TasksMax"]) + resident.RESIDENT_TASKS, 512)
        self.assertEqual(hm.CPU + resident.RESIDENT_CPU_PERCENT, 200)
        self.assertEqual(caps["MemorySwapMax"], "0")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name, value in guard.CGROUP.items():
                (root / name).write_text({"memory.max": str(hm.MEMORY), "pids.max": "480"}.get(name, value))
            (root / "cpu.max").write_text("190000 100000")
            actual = {**caps, **guard.SANDBOX, "RuntimeMaxUSec": "17s",
                "TemporaryFileSystem": guard.system_masks(profile="standard"),
                "UnsetEnvironment": " ".join(guard.DELEGATION_ENV)}
            for profile in hm.PROFILES:
                self.assertEqual(guard.workload_pids_observation(None, profile).expected_limit, 480)
                guard.verify(actual, root, "system", guard.SANDBOX, profile, runtime_seconds=17)
                for key, value in (("MemoryMax", "4294967296"), ("TasksMax", "512"),
                        ("CPUQuotaPerSecUSec", "2s"), ("MemorySwapMax", "1"),
                        ("RuntimeMaxUSec", "1200s"), ("PrivateNetwork", "no")):
                    with self.assertRaises(ValueError):
                        guard.verify({**actual, key: value}, root, "system", guard.SANDBOX, profile, runtime_seconds=17)
            for name, value in (("memory.max", "4294967296"), ("pids.max", "512"),
                    ("cpu.max", "200000 100000"), ("memory.swap.max", "1")):
                before = (root / name).read_text()
                (root / name).write_text(value)
                with self.assertRaises(ValueError):
                    guard.verify(actual, root, "system", guard.SANDBOX, hm.RECONSTRUCTION, runtime_seconds=17)
                (root / name).write_text(before)

    def test_real_resident_constructor_lifetimes_rechecks_and_unchanged_original_end(self):
        for name in ("Witness", "WorkloadWitness", "monitor", "cleanup_retained", "release_worker", "remaining", "properties"):
            self.assertIs(getattr(hm, name), getattr(kernel, name))
        with ExitStack() as stack:
            root = Path(stack.enter_context(tempfile.TemporaryDirectory())) / "group"
            root.mkdir(mode=0o700)
            for name, value in {"memory.max": "268435456", "memory.swap.max": "0", "pids.max": "32",
                    "cpu.max": "10000 100000", "cgroup.procs": str(os.getpid()), "pids.current": "1",
                    "cgroup.events": "populated 1\nfrozen 0"}.items():
                (root / name).write_text(value + "\n")
            stack.enter_context(patch.object(kernel, "cgroup_path", lambda uid: root))
            stack.enter_context(patch.object(kernel, "ancestor", fixture_ancestor))
            entry = time.monotonic_ns()
            witness = hm.Witness(entry, entry + 1200 * 10**9)
            stack.callback(witness.close)
            self.assertEqual([row[0] for row in witness.processes], [os.getpid()])
            self.assertTrue(witness.complete(0, True, True, True)["initial_direct_processes_retained"])
            (root / "pids.max").write_text("33\n")
            with self.assertRaises(ValueError): witness.observe()
            (root / "pids.max").write_text("32\n")
            for state in ((1, True, True, True), (0, False, True, True), (0, True, False, True), (0, True, True, False)):
                with self.assertRaises(ValueError): witness.complete(*state)
            with patch.object(kernel.time, "monotonic_ns", return_value=witness.deadline):
                with self.assertRaises(ValueError): witness.complete(0, True, True, True)

    def test_reservation_projection_cannot_promote_installation_or_native_proof(self):
        for profile in hm.PROFILES:
            self.assertIn(profile, kernel.WORKLOAD_PROFILES)
            for verified in (None, False, True):
                row = hm.projection(profile, 100 * 10**9, 1300 * 10**9, verified, {})
                self.assertIs(row["verified_after_cleanup"], verified)
                for key in ("activation_qualified", "current_artifact_qualified", "browser_consent_qualified", "continuity_qualified"):
                    self.assertIs(row[key], False)
        with self.assertRaises(ValueError): hm.projection(hm.RECONSTRUCTION, 100 * 10**9, 1301 * 10**9, True, {})


if __name__ == "__main__":
    unittest.main()
