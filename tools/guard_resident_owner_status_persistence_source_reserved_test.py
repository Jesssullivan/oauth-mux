"""Exact source producer admission models; no normal state or producer reads."""
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import Mock, patch
import execution_guard as guard
import guard_native_seed_plan_reserved as kernel
import guard_resident_models_reserved as models
import guard_resident_owner_status_source_reserved as prior
import guard_resident_owner_status_binding_reserved as binding
import guard_resident_owner_status_persistence_source_reserved as source
import guard_resident_observation as resident


class SourceReservationModels(unittest.TestCase):
    def args(self):
        return SimpleNamespace(profile=source.PROFILE, manager="system", reuse_owned_cache=False,
            source_commit="a" * 40, source_dirty="false", repository_cache=None, nixpkgs_source=None)

    def test_exact_three_tests_and_no_cross_family_admission(self):
        expected = ["test", "//tools:guard_resident_owner_status_persistence_source_reserved_test",
            "//tools:codex_owner_status_persistence_source_test", "//tools:codex_owner_status_persistence_source_producer"]
        self.assertEqual(source.ARGUMENTS, expected)
        self.assertTrue(source.request(self.args(), expected))
        invalid = [expected[:-1], ["test", *expected[2:]], ["test", *reversed(expected[1:])], expected + [expected[1]],
            ["build", *expected[1:]], ["run", *expected[1:]], expected + ["//:docs_check"],
            expected + ["--test_arg=untrusted"], models.ARGUMENTS, prior.ARGUMENTS, binding.ARGUMENTS, ["test", kernel.LABEL]]
        with patch.object(guard, "immutable", side_effect=AssertionError("tool read")) as tool, \
                patch.object(source, "Witness", side_effect=AssertionError("resident read")) as witness:
            for arguments in invalid:
                with self.assertRaises(ValueError): source.request(self.args(), arguments)
                with self.assertRaises(ValueError):
                    guard.main(["--profile", source.PROFILE, "--manager", "system", "--source-commit",
                        "a" * 40, "--source-dirty", "false", "--", *arguments])
            tool.assert_not_called()
            witness.assert_not_called()
        with self.assertRaises(ValueError): models.selected(models.PROFILE, expected)
        with self.assertRaises(ValueError): prior.selected(prior.PROFILE, expected)
        with self.assertRaises(ValueError): binding.selected(binding.PROFILE, expected)
        for profile in kernel.PROFILES:
            with self.assertRaises(ValueError): kernel.selected(profile, expected)
        self.assertNotIn(source.PROFILE, models.PROFILES)
        self.assertNotIn(source.PROFILE, prior.PROFILES)
        self.assertNotIn(source.PROFILE, binding.PROFILES)
        self.assertNotIn(source.PROFILE, kernel.PROFILES)
        self.assertIn(source.PROFILE, kernel.WORKLOAD_PROFILES)

    def test_normal_state_runtime_native_and_cache_selectors_refuse(self):
        for name, value in (("manager", "user"), ("reuse_owned_cache", True), ("source_dirty", "true"),
                ("source_commit", "a" * 39), ("resident_manifest", Path("/model/private")),
                ("codex_owner_runtime_directory", Path("/model/runtime")), ("native_mode", "schema"),
                ("codex_fresh_runtime_selection", Path("/model/runtime.json"))):
            args = self.args()
            setattr(args, name, value)
            with self.assertRaises(ValueError): source.request(args, source.ARGUMENTS)
        args = self.args()
        args.profile = models.PROFILE
        self.assertFalse(source.request(args, source.ARGUMENTS))
        with patch.object(guard, "immutable", side_effect=AssertionError("tool read")) as tool:
            for options in (["--resident-manifest", "/model/private"],
                    ["--codex-owner-runtime-directory", "/model/runtime"], ["--reuse-owned-cache"]):
                with self.assertRaises(ValueError):
                    guard.main(["--profile", source.PROFILE, "--manager", "system", "--source-commit",
                        "a" * 40, "--source-dirty", "false", *options, "--", *source.ARGUMENTS])
            tool.assert_not_called()

    def test_offline_fresh_output_and_unchanged_original_deadline(self):
        with patch.object(kernel.time, "monotonic_ns", return_value=200 * 10**9):
            command = source.command(guard.bazel_command, "bazel", Path("/model/epoch"), source.ARGUMENTS,
                source.PROFILE, 100 * 10**9, 1300 * 10**9)
        self.assertEqual(command[-3:], source.ARGUMENTS[1:])
        for value in ("--repository_disable_download", "--repo_contents_cache=", "--lockfile_mode=error",
                "--sandbox_default_allow_network=false", "--remote_executor=", "--remote_cache=",
                "--nocache_test_results", "--output_base=/model/epoch/output-base"):
            self.assertIn(value, command)
        builder = Mock()
        with patch.object(kernel.time, "monotonic_ns", return_value=200 * 10**9):
            with self.assertRaises(ValueError): source.command(builder, "bazel", Path("/model/epoch"),
                source.ARGUMENTS, source.PROFILE, 100 * 10**9, 1300 * 10**9, output_base=Path("/model/reused"))
        builder.assert_not_called()
        with patch.object(kernel.time, "monotonic_ns", return_value=1270 * 10**9):
            with self.assertRaises(ValueError): source.command(builder, "bazel", Path("/model/epoch"),
                source.ARGUMENTS, source.PROFILE, 100 * 10**9, 1300 * 10**9)
            self.assertEqual(source.remaining(100 * 10**9, 1300 * 10**9, cleanup=True), 30)
        with patch.object(kernel.time, "monotonic_ns", return_value=1300 * 10**9):
            with self.assertRaises(ValueError): source.remaining(100 * 10**9, 1300 * 10**9, cleanup=True)

    def test_exact_kernel_lifetime_caps_and_effective_readback(self):
        for name in ("Witness", "WorkloadWitness", "monitor", "cleanup_retained", "release_worker", "remaining"):
            self.assertIs(getattr(source, name), getattr(kernel, name))
        caps = source.properties(guard.PROPERTIES)
        self.assertEqual(int(caps["MemoryMax"]) + resident.RESIDENT_MEMORY, 4 * 1024**3)
        self.assertEqual(int(caps["TasksMax"]) + resident.RESIDENT_TASKS, 512)
        self.assertEqual(source.CPU + resident.RESIDENT_CPU_PERCENT, 200)
        self.assertEqual(caps["CPUQuotaPerSecUSec"], "1.9s")
        self.assertEqual(caps["MemorySwapMax"], "0")
        self.assertEqual(guard.CONTROLLER_TIMEOUT, 15)
        self.assertEqual(guard.workload_pids_observation(None, source.PROFILE).expected_limit, 480)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name, value in guard.CGROUP.items():
                (root / name).write_text({"memory.max": str(source.MEMORY), "pids.max": "480"}.get(name, value))
            (root / "cpu.max").write_text("190000 100000")
            actual = {**caps, **guard.SANDBOX, "RuntimeMaxUSec": "17s",
                "TemporaryFileSystem": guard.system_masks(profile="standard"),
                "UnsetEnvironment": " ".join(guard.DELEGATION_ENV)}
            guard.verify(actual, root, "system", guard.SANDBOX, source.PROFILE, runtime_seconds=17)
            for key, value in (("PrivateNetwork", "no"), ("TasksMax", "512"), ("MemoryMax", "4294967296"),
                    ("CPUQuotaPerSecUSec", "2s"), ("RuntimeMaxUSec", "1200s")):
                with self.assertRaises(ValueError): guard.verify({**actual, key: value}, root, "system",
                    guard.SANDBOX, source.PROFILE, runtime_seconds=17)

    def test_source_projection_never_promotes_schema_compiler_sdk_or_live(self):
        for verified in (None, False, True):
            row = source.projection(100 * 10**9, 1300 * 10**9, verified, {"custody_observed": False})
            self.assertEqual(row["scope"], "fixed-resident-owner-status-persistence-source-reserved-v1")
            self.assertEqual(row["mode"], "source-composition")
            self.assertIs(row["verified_after_cleanup"], verified)
            self.assertTrue(all(row[name] is False for name in ("native_runtime_qualified", "sdk_qualified",
                "compiler_qualified", "schema_qualified", "final_source_qualified", "custody_qualified",
                "health_qualified", "continuity_qualified")))
        with self.assertRaises(ValueError): source.projection(100 * 10**9, 1300 * 10**9, 1, {})
        with self.assertRaises(ValueError): source.projection(100 * 10**9, 1301 * 10**9, True, {})


if __name__ == "__main__":
    unittest.main()
