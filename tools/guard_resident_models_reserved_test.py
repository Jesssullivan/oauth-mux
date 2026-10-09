"""Admission and reservation composition models; never inspect a normal resident."""
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import Mock, patch

import execution_guard as guard
import guard_native_seed_plan_reserved as kernel
import guard_query_registration_reserved as query
import guard_default_archive_reserved as archive
import guard_resident_models_reserved as models
import guard_resident_observation as resident
import guard_owner_runtime_input as retained


class ResidentModelsReservation(unittest.TestCase):
    def args(self):
        return SimpleNamespace(profile=models.PROFILE, manager="system", reuse_owned_cache=False,
            source_commit="a" * 40, source_dirty="false", repository_cache=None, nixpkgs_source=None)

    def test_exact_cohort_excludes_actual_retained_consumers(self):
        expected = ["test", "//delivery:retained_ordinary_native_tui_contract_test",
            "//delivery:native_thread_census_test", "//delivery:native_run_cli_failure_test",
            "//delivery:native_history_diagnostic_test", "//delivery:native_seed_attachment_diagnostic_test",
            "//delivery:native_terminal_failure_test",
            "//tools:codex_owner_runtime_input_test", "//tools:guard_owner_runtime_input_test",
            "//tools:guard_fresh_native_runtime_input_test", "//tools:guard_resident_models_reserved_test",
            "//tools:guard_native_seed_plan_reserved_test", "//tools:execution_guard_test"]
        self.assertEqual(models.ARGUMENTS, expected)
        self.assertTrue(models.request(self.args(), expected))
        self.assertFalse(set(expected[1:]) & retained.CONSUMERS)
        self.assertEqual(models.selected(models.PROFILE, expected), {"PrivateNetwork": "yes"})
        invalid = [expected[:-1], expected + [expected[1]], ["build", *expected[1:]],
            ["run", *expected[1:]], ["test", *reversed(expected[1:])],
            expected + ["//:docs_check"], expected + ["--test_filter=untrusted"]]
        invalid.extend(["test", label] for label in retained.CONSUMERS)
        with patch.object(guard, "immutable", side_effect=AssertionError("tool read")) as tool, \
                patch.object(models, "Witness", side_effect=AssertionError("resident read")) as witness:
            for arguments in invalid:
                with self.assertRaises(ValueError): models.request(self.args(), arguments)
                with self.assertRaises(ValueError):
                    guard.main(["--profile", models.PROFILE, "--manager", "system",
                        "--source-commit", "a" * 40, "--source-dirty", "false", "--", *arguments])
            tool.assert_not_called()
            witness.assert_not_called()

    def test_inputs_cannot_request_normal_state_or_retained_runtime(self):
        cases = (("manager", "user"), ("source_dirty", "true"), ("source_commit", "a" * 39),
            ("reuse_owned_cache", True), ("resident_manifest", Path("/model/normal-state")),
            ("codex_owner_runtime_directory", Path("/model/retained")), ("native_mode", "schema"),
            ("codex_login_manifest", Path("/model/normal-login")), ("site_phase", "build"))
        for name, value in cases:
            args = self.args()
            setattr(args, name, value)
            with self.assertRaises(ValueError): models.request(args, models.ARGUMENTS)
        args = self.args()
        args.profile = "standard"
        self.assertFalse(models.request(args, models.ARGUMENTS))
        with patch.object(guard, "immutable", side_effect=AssertionError("tool read")) as tool:
            for option in (["--resident-manifest", "/model/private"],
                    ["--codex-owner-runtime-directory", "/model/retained"], ["--reuse-owned-cache"]):
                with self.assertRaises(ValueError):
                    guard.main(["--profile", models.PROFILE, "--manager", "system",
                        "--source-commit", "a" * 40, "--source-dirty", "false", *option,
                        "--", *models.ARGUMENTS])
            tool.assert_not_called()

    def test_existing_families_do_not_gain_model_targets(self):
        self.assertNotIn(models.PROFILE, kernel.PROFILES)
        self.assertNotIn(models.PROFILE, query.PROFILES)
        self.assertNotIn(models.PROFILE, archive.PROFILES)
        self.assertIn(models.PROFILE, kernel.WORKLOAD_PROFILES)
        for profile in kernel.PROFILES:
            with self.assertRaises(ValueError): kernel.selected(profile, models.ARGUMENTS)
        with self.assertRaises(ValueError): query.selected(query.PROFILE, models.ARGUMENTS)
        with self.assertRaises(ValueError): archive.selected(archive.PROFILE, models.ARGUMENTS)
        for arguments in (kernel.MODELS, kernel.INTEGRATED_MODELS, query.ARGUMENTS):
            with self.assertRaises(ValueError): models.selected(models.PROFILE, arguments)
        with self.assertRaises(ValueError): retained.finite(models.PROFILE,
            ["test", "//delivery:installed_retained_ordinary_native_tui_test"])

    def test_shared_kernel_budget_and_lifetime_machinery_remains_exact(self):
        for name in ("Witness", "WorkloadWitness", "monitor", "cleanup_retained", "release_worker",
                "properties", "remaining"):
            self.assertIs(getattr(models, name), getattr(kernel, name))
        caps = models.properties(guard.PROPERTIES)
        self.assertEqual(int(caps["MemoryMax"]) + resident.RESIDENT_MEMORY, 4 * 1024**3)
        self.assertEqual(int(caps["TasksMax"]) + resident.RESIDENT_TASKS, 512)
        self.assertEqual(caps["CPUQuotaPerSecUSec"], "1.9s")
        self.assertEqual(caps["MemorySwapMax"], "0")
        self.assertEqual(caps["RemainAfterExit"], "yes")
        self.assertEqual(guard.CONTROLLER_TIMEOUT, 15)
        self.assertEqual(guard.workload_pids_observation(None, models.PROFILE).expected_limit, 480)
        self.assertEqual(models.CPU + resident.RESIDENT_CPU_PERCENT, 200)
        for values in ({"memory.max": "268435457", "memory.swap.max": "0", "pids.max": "32", "cpu.max": "10000 100000"},
                {"memory.max": "268435456", "memory.swap.max": "1", "pids.max": "32", "cpu.max": "10000 100000"},
                {"memory.max": "268435456", "memory.swap.max": "0", "pids.max": "33", "cpu.max": "10000 100000"},
                {"memory.max": "268435456", "memory.swap.max": "0", "pids.max": "32", "cpu.max": "10001 100000"}):
            with self.assertRaises(ValueError): kernel.kernel_bounds(values)

    def test_command_uses_fresh_offline_output_and_original_cutoff(self):
        with patch.object(kernel.time, "monotonic_ns", return_value=200 * 10**9):
            actual = models.command(guard.bazel_command, "bazel", Path("/model/epoch"),
                models.ARGUMENTS, models.PROFILE, 100 * 10**9, 1300 * 10**9)
        self.assertEqual(actual[-len(models.ARGUMENTS[1:]):], models.ARGUMENTS[1:])
        for option in ("--repository_disable_download", "--repo_contents_cache=", "--lockfile_mode=error",
                "--sandbox_default_allow_network=false", "--remote_executor=", "--remote_cache=",
                "--nocache_test_results"):
            self.assertIn(option, actual)
        self.assertIn("--output_base=/model/epoch/output-base", actual)
        builder = Mock()
        with patch.object(kernel.time, "monotonic_ns", return_value=200 * 10**9):
            with self.assertRaises(ValueError): models.command(builder, "bazel", Path("/model/epoch"),
                models.ARGUMENTS, models.PROFILE, 100 * 10**9, 1300 * 10**9, output_base=Path("/model/reused"))
        builder.assert_not_called()
        with patch.object(kernel.time, "monotonic_ns", return_value=1270 * 10**9):
            with self.assertRaises(ValueError): models.command(builder, "bazel", Path("/model/epoch"),
                models.ARGUMENTS, models.PROFILE, 100 * 10**9, 1300 * 10**9)
            self.assertEqual(models.remaining(100 * 10**9, 1300 * 10**9, cleanup=True), 30)
        with patch.object(kernel.time, "monotonic_ns", return_value=1300 * 10**9):
            with self.assertRaises(ValueError): models.remaining(100 * 10**9, 1300 * 10**9, cleanup=True)
        with self.assertRaises(ValueError): models.projection(100 * 10**9, 1301 * 10**9, True, {})

    def test_controller_verifies_reserved_caps_against_synthetic_kernel_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name, value in guard.CGROUP.items():
                (root / name).write_text({"memory.max": str(models.MEMORY), "pids.max": "480"}.get(name, value))
            (root / "cpu.max").write_text("190000 100000\n")
            actual = {**models.properties(guard.PROPERTIES), **guard.SANDBOX, "RuntimeMaxUSec": "17s",
                "TemporaryFileSystem": guard.system_masks(profile="standard"),
                "UnsetEnvironment": " ".join(guard.DELEGATION_ENV)}
            guard.verify(actual, root, "system", guard.SANDBOX, models.PROFILE, runtime_seconds=17)
            for key, value in (("PrivateNetwork", "no"), ("TasksMax", "512"),
                    ("MemoryMax", "4294967296"), ("CPUQuotaPerSecUSec", "2s"), ("RuntimeMaxUSec", "1200s")):
                with self.assertRaises(ValueError):
                    guard.verify({**actual, key: value}, root, "system", guard.SANDBOX,
                        models.PROFILE, runtime_seconds=17)
            for name, value in (("cpu.max", "190001 100000"), ("cpu.max", "189999 100000"),
                    ("pids.max", "481"), ("memory.max", "4026531841"), ("memory.swap.max", "1")):
                prior = (root / name).read_text()
                (root / name).write_text(value)
                with self.assertRaises(ValueError):
                    guard.verify(actual, root, "system", guard.SANDBOX, models.PROFILE, runtime_seconds=17)
                (root / name).write_text(prior)

    def test_projection_preserves_failed_witness_and_does_not_promote_live_claims(self):
        sampled = {"health_observed": False, "custody_observed": False,
            "installation_qualified": False, "resident_signalled": False}
        for verified in (None, False, True):
            receipt = models.projection(100 * 10**9, 1300 * 10**9, verified, sampled)
            self.assertEqual(receipt["scope"], "fixed-resident-models-reserved-v1")
            self.assertIs(receipt["verified_after_cleanup"], verified)
            self.assertEqual(receipt["resident"], sampled)
            self.assertTrue(all(receipt[name] is False for name in
                ("native_runtime_qualified", "sdk_qualified", "continuity_qualified")))
        with self.assertRaises(ValueError): models.projection(100 * 10**9, 1300 * 10**9, 1, sampled)


if __name__ == "__main__":
    unittest.main()
