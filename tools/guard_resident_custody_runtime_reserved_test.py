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
import guard_resident_owner_status_persistence_source_reserved as successor
import guard_resident_custody_runtime_reserved as source
import guard_resident_observation as resident


class SourceReservationModels(unittest.TestCase):
    def test_production_acquisition_units_are_exact_and_refuse_before_external_access(self):
        profile = source.ACQUISITION_UNIT_PROFILE
        expected = ["test", "//tools:guard_resident_custody_runtime_reserved_test",
            "//:native_source_acquisition_test", "//:native_source_consent_test",
            "//:qualified_runtime_delivery_test", "//:native_deployment_arguments_test",
            "//:runtime_selection_producer_test", "//:engine_test",
            "//delivery:nix_codex_runtime_test", "//delivery:nix_codex_deployment_test", "//:docs_check"]
        self.assertEqual(source.COHORTS[profile], expected)
        args = self.args()
        args.profile = profile
        self.assertTrue(source.request(args, expected))
        with patch.object(guard, "immutable", side_effect=AssertionError("tool read")) as tool, \
                patch.object(source, "Witness", side_effect=AssertionError("resident read")) as witness:
            for bad in (expected[:-1], expected + ["//:format_test"],
                    ["test", *reversed(expected[1:])], ["run", *expected[1:]],
                    expected + ["--test_arg=private"], source.ARGUMENTS):
                with self.assertRaises(ValueError):
                    guard.main(["--profile", profile, "--manager", "system", "--source-commit",
                        "a" * 40, "--source-dirty", "false", "--", *bad])
            for option in (["--resident-manifest", "/model/private"], ["--reuse-owned-cache"],
                    ["--codex-fresh-runtime-selection", "/model/private"]):
                with self.assertRaises(ValueError):
                    guard.main(["--profile", profile, "--manager", "system", "--source-commit",
                        "a" * 40, "--source-dirty", "false", *option, "--", *expected])
            tool.assert_not_called()
            witness.assert_not_called()

    def test_production_acquisition_units_keep_original_clock_and_false_authority(self):
        profile = source.ACQUISITION_UNIT_PROFILE
        with patch.object(kernel.time, "monotonic_ns", return_value=200 * 10**9):
            command = source.command(guard.bazel_command, "bazel", Path("/model/epoch"),
                source.COHORTS[profile], profile, 100 * 10**9, 1300 * 10**9)
        self.assertEqual(command[-10:], source.COHORTS[profile][1:])
        for flag in ("--repository_disable_download", "--nocache_test_results",
                "--sandbox_default_allow_network=false", "--remote_executor=", "--remote_cache="):
            self.assertIn(flag, command)
        self.assertEqual(guard.workload_pids_observation(None, profile).expected_limit, 480)
        for verified in (None, False, True):
            row = source.projection(100 * 10**9, 1300 * 10**9, verified, {}, profile)
            self.assertEqual(row["mode"], "isolated-production-acquisition-units")
            self.assertIs(row["verified_after_cleanup"], verified)
            for field in ("source_mutation_requested", "normal_vault_observed", "daemon_transition_performed",
                    "native_runtime_qualified", "sdk_qualified", "compiler_qualified", "schema_qualified",
                    "final_source_qualified", "custody_qualified", "health_qualified", "continuity_qualified"):
                self.assertIs(row[field], False)
        with patch.object(kernel.time, "monotonic_ns", return_value=1270 * 10**9):
            with self.assertRaises(ValueError):
                source.command(Mock(), "bazel", Path("/model/epoch"), source.COHORTS[profile],
                    profile, 100 * 10**9, 1300 * 10**9)
        with self.assertRaises(ValueError):
            source.projection(100 * 10**9, 1301 * 10**9, True, {}, profile)

    def test_deployment_wiring_vector_is_exact_and_rejects_before_tool_reads(self):
        profile = source.DEPLOYMENT_WIRING_PROFILE
        expected = ["test", "//:daemon_test", "//:nix_module_evaluation_test", "//:docs_check"]
        self.assertEqual(source.COHORTS[profile], expected)
        args = self.args()
        args.profile = profile
        self.assertTrue(source.request(args, expected))
        with patch.object(guard, "immutable", side_effect=AssertionError("tool read")) as tool, \
                patch.object(source, "Witness", side_effect=AssertionError("resident read")) as witness:
            for bad in (expected[:-1], expected + ["//:engine_test"],
                    ["test", *reversed(expected[1:])], ["run", *expected[1:]],
                    ["build", *expected[1:]], expected + ["--test_arg=private"],
                    source.COHORTS[source.ACQUISITION_UNIT_PROFILE]):
                with self.assertRaises(ValueError):
                    guard.main(["--profile", profile, "--manager", "system", "--source-commit",
                        "a" * 40, "--source-dirty", "false", "--", *bad])
            for option in (["--resident-manifest", "/model/private"], ["--reuse-owned-cache"],
                    ["--codex-fresh-runtime-selection", "/model/private"]):
                with self.assertRaises(ValueError):
                    guard.main(["--profile", profile, "--manager", "system", "--source-commit",
                        "a" * 40, "--source-dirty", "false", *option, "--", *expected])
            tool.assert_not_called()
            witness.assert_not_called()

    def test_deployment_wiring_clock_source_selector_and_false_authority(self):
        import guard_resident_enrollment_profile as repository
        profile = source.DEPLOYMENT_WIRING_PROFILE
        with patch.object(kernel.time, "monotonic_ns", return_value=200 * 10**9):
            command = source.command(guard.bazel_command, "bazel", Path("/model/epoch"),
                source.COHORTS[profile], profile, 100 * 10**9, 1300 * 10**9,
                repository_cache=repository.REPOSITORY_CACHE, nixpkgs_source=repository.NIXPKGS_SOURCE)
        self.assertEqual(command[-3:], source.COHORTS[profile][1:])
        self.assertIn("--repo_env=OMUX_NIXPKGS_EVALUATION_SOURCE=" + str(repository.NIXPKGS_SOURCE), command)
        for flag in ("--repository_disable_download", "--repo_contents_cache=", "--nocache_test_results",
                "--sandbox_default_allow_network=false", "--remote_executor=", "--remote_cache="):
            self.assertIn(flag, command)
        self.assertEqual(guard.workload_pids_observation(None, profile).expected_limit, 480)
        for verified in (None, False, True):
            row = source.projection(100 * 10**9, 1300 * 10**9, verified, {}, profile)
            self.assertEqual(row["mode"], "isolated-deployment-wiring-units")
            self.assertIs(row["verified_after_cleanup"], verified)
            for field in ("source_mutation_requested", "normal_vault_observed", "daemon_transition_performed",
                    "native_runtime_qualified", "sdk_qualified", "compiler_qualified", "schema_qualified",
                    "final_source_qualified", "custody_qualified", "health_qualified", "continuity_qualified"):
                self.assertIs(row[field], False)
        with patch.object(kernel.time, "monotonic_ns", return_value=1270 * 10**9):
            with self.assertRaises(ValueError):
                source.command(Mock(), "bazel", Path("/model/epoch"), source.COHORTS[profile],
                    profile, 100 * 10**9, 1300 * 10**9)
        with self.assertRaises(ValueError):
            source.projection(100 * 10**9, 1301 * 10**9, True, {}, profile)

    def args(self):
        return SimpleNamespace(profile=source.PROFILE, manager="system", reuse_owned_cache=False,
            source_commit="a" * 40, source_dirty="false", repository_cache=None, nixpkgs_source=None)

    def test_default_source_models_are_finite_and_have_no_live_selection(self):
        expected=["test", "//tools:guard_resident_custody_runtime_reserved_test",
            "//delivery:resident_default_enrollment_contract_test", "//delivery:resident_existing_enrollment_contract_test",
            "//delivery:resident_custody_reopen_contract_test", "//:docs_check"]
        self.assertEqual(source.COHORTS[source.DEFAULT_MODEL_PROFILE],expected)
        row=source.projection(100*10**9,1300*10**9,True,{},source.DEFAULT_MODEL_PROFILE)
        self.assertEqual(row["mode"],"isolated-default-source-models")
        self.assertIs(row["normal_vault_observed"],False)
        self.assertIs(row["source_mutation_requested"],False)
        with self.assertRaises(ValueError): source.selected(source.DEFAULT_MODEL_PROFILE, ["run","//delivery:resident_codex_existing_enrollment"])

    def test_installed_custody_models_have_distinct_exact_offline_vector(self):
        self.assertEqual(source.COHORTS[source.MODEL_PROFILE], ["test",
            "//tools:guard_resident_custody_runtime_reserved_test", "//tools:guard_resident_namespace_profile_test",
            "//tools:guard_resident_owned_update_test", "//:format_test", "//:docs_check"])
        expected=["test", "//tools:guard_resident_custody_runtime_reserved_test",
            "//delivery:resident_custody_reopen_contract_test", "//delivery:resident_owned_lifecycle_contract_test",
            "//:format_test", "//:docs_check"]
        self.assertEqual(source.COHORTS[source.INSTALLED_MODEL_PROFILE],expected)
        args=self.args()
        args.profile=source.INSTALLED_MODEL_PROFILE
        self.assertTrue(source.request(args,expected))
        for name,value in (("resident_manifest",Path("/model/private")),("reuse_owned_cache",True),
                ("native_mode","schema"),("manager","user")):
            bad=SimpleNamespace(**vars(args))
            setattr(bad,name,value)
            with self.assertRaises(ValueError): source.request(bad,expected)
        for bad in (expected[:-1],expected+["//:engine_test"],expected+["--test_arg=untrusted"],
                source.COHORTS[source.MODEL_PROFILE],["build",*expected[1:]]):
            with self.assertRaises(ValueError): source.selected(source.INSTALLED_MODEL_PROFILE,bad)
        row=source.projection(100*10**9,1300*10**9,True,{},source.INSTALLED_MODEL_PROFILE)
        self.assertEqual(row["mode"],"isolated-installed-custody-models")
        self.assertIs(row["source_mutation_requested"],False)
        self.assertIs(row["normal_vault_observed"],False)
        self.assertIs(row["daemon_transition_performed"],False)
        self.assertIs(row["compiler_qualified"],False)

    def test_exact_cohorts_refuse_before_tools_or_resident_reads(self):
        for profile, expected in source.COHORTS.items():
            args = self.args()
            args.profile = profile
            self.assertTrue(source.request(args, expected))
            for bad in (expected[:-1], ["test", *reversed(expected[1:])], expected + [expected[1]],
                    ["build", *expected[1:]], expected + ["--test_arg=untrusted"], prior.ARGUMENTS):
                with patch.object(guard, "immutable", side_effect=AssertionError("tool read")) as tool:
                    with self.assertRaises(ValueError):
                        guard.main(["--profile", profile, "--manager", "system", "--source-commit",
                            "a" * 40, "--source-dirty", "false", "--", *bad])
                    tool.assert_not_called()
            self.assertIn(profile, kernel.WORKLOAD_PROFILES)
            self.assertNotIn(profile, kernel.PROFILES)
        for profile in source.PROFILES:
            for other, arguments in source.COHORTS.items():
                if profile != other:
                    with self.assertRaises(ValueError): source.selected(profile, arguments)

    def test_formatter_exact_paths_and_separate_projection(self):
        expected = ["run", "//:format", "--", "src/engine.zig", "src/vault.zig", "src/control.zig"]
        self.assertEqual(source.COHORTS[source.FORMAT_PROFILE], expected)
        with self.assertRaises(ValueError):
            guard.bazel_command("bazel", Path("/model/epoch"), expected)
        for bad in (expected[:-1], expected + ["src"], expected[:3] + ["src"],
                ["run", "//:format", "--", *reversed(expected[3:])]):
            with self.assertRaises(ValueError): source.selected(source.FORMAT_PROFILE, bad)
        with patch.object(kernel.time, "monotonic_ns", return_value=200 * 10**9):
            command = source.command(guard.bazel_command, "bazel", Path("/model/epoch"), expected,
                source.FORMAT_PROFILE, 100 * 10**9, 1300 * 10**9)
        self.assertEqual(command[-4:], expected[-4:])
        self.assertIn("--repository_disable_download", command)
        row = source.projection(100 * 10**9, 1300 * 10**9, True, {}, source.FORMAT_PROFILE)
        self.assertEqual(row["mode"], "bounded-source-formatting")
        self.assertIs(row["source_mutation_requested"], True)
        self.assertIs(row["isolated_unit_scope"], False)
        self.assertIs(row["daemon_transition_performed"], False)

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
        self.assertEqual(command[-len(source.ARGUMENTS[1:]):], source.ARGUMENTS[1:])
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
            self.assertEqual(row["scope"], "fixed-resident-custody-runtime-reserved-v1")
            self.assertEqual(row["mode"], "isolated-runtime-units")
            self.assertIs(row["isolated_unit_scope"], True)
            self.assertIs(row["verified_after_cleanup"], verified)
            self.assertTrue(all(row[name] is False for name in ("native_runtime_qualified", "sdk_qualified",
                "compiler_qualified", "schema_qualified", "final_source_qualified", "custody_qualified",
                "health_qualified", "continuity_qualified", "normal_vault_observed", "daemon_transition_performed")))
        with self.assertRaises(ValueError): source.projection(100 * 10**9, 1300 * 10**9, 1, {})
        with self.assertRaises(ValueError): source.projection(100 * 10**9, 1301 * 10**9, True, {})


if __name__ == "__main__":
    unittest.main()
