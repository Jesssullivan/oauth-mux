"""Synthetic archive receipts and kernel files; no archive/install/live claim."""
import copy
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch, Mock
import execution_guard as guard
import guard_default_archive_reserved as archive
import guard_native_seed_plan_reserved as kernel
import guard_native_seed_plan_reserved_test as kernel_models
Fixture = kernel_models.Fixture
import guard_resident_owned_update as update

class ArchiveReservationModels(unittest.TestCase):
    def args(self):
        return SimpleNamespace(profile=archive.PROFILE, manager="system", reuse_owned_cache=False,
            source_commit="a"*40, source_dirty="false", repository_cache=None, nixpkgs_source=None)

    def test_exact_build_and_reuse_private_or_mixed_selectors_refuse_before_tool_io(self):
        self.assertTrue(archive.request(self.args(), archive.ARGUMENTS))
        for arguments in (["test", archive.LABEL], ["run", archive.LABEL],
            ["build", "//delivery:development_instance_archive"],
            [*archive.ARGUMENTS, "//:omux"], ["build", "--jobs=3", archive.LABEL]):
            with self.assertRaises(ValueError): archive.request(self.args(), arguments)
        for key, value in (("manager", "user"), ("reuse_owned_cache", True),
            ("source_dirty", "true"), ("resident_manifest", Path("/model/input.json")),
            ("native_mode", "qualification"), ("repository_cache", Path("/model/cache"))):
            args=self.args(); setattr(args, key, value)
            with self.assertRaises(ValueError): archive.request(args, archive.ARGUMENTS)
        with patch.object(guard, "immutable", side_effect=AssertionError("tool IO")) as tools:
            for arguments in (["test", archive.LABEL], ["build", archive.LABEL, "//:omux"]):
                with self.assertRaises(ValueError):
                    guard.main(["--profile", archive.PROFILE, "--manager", "system",
                        "--source-commit", "a"*40, "--source-dirty", "false", "--", *arguments])
            tools.assert_not_called()

    def test_actual_builder_fresh_namespace_source_offline_and_no_test_carrier(self):
        with patch.object(kernel.time, "monotonic_ns", return_value=200*10**9):
            command=archive.command(guard.bazel_command, "bazel", Path("/model/epoch"),
                archive.ARGUMENTS, archive.PROFILE, 100*10**9, 1300*10**9,
                source_commit="a"*40, source_dirty="false")
            self.assertEqual(command[-1], archive.LABEL)
            self.assertEqual(command.count("build"), 1)
            for option in ("--output_base=/model/epoch/output-base", "--repository_disable_download",
                "--repo_contents_cache=", "--disk_cache=", "--remote_cache=", "--remote_executor=",
                "--sandbox_default_allow_network=false", "--lockfile_mode=error",
                "--define=OMUX_SOURCE_COMMIT="+"a"*40, "--define=OMUX_SOURCE_DIRTY=false"):
                self.assertIn(option, command)
            self.assertFalse(any(part.startswith("--test_env=") for part in command))
            with self.assertRaises(ValueError):
                archive.command(guard.bazel_command, "bazel", Path("/model/epoch"), archive.ARGUMENTS,
                    archive.PROFILE, 100*10**9, 1300*10**9, output_base=Path("/old/archive"))
        with patch.object(kernel.time, "monotonic_ns", return_value=1270*10**9):
            with self.assertRaises(ValueError):
                archive.command(guard.bazel_command, "bazel", Path("/model/epoch"),
                    archive.ARGUMENTS, archive.PROFILE, 100*10**9, 1300*10**9)

    def test_actual_caps_and_retained_resident_use_existing_kernel_witness(self):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)
            for name, value in guard.CGROUP.items():
                (root/name).write_text({"memory.max": str(archive.MEMORY), "pids.max": "480"}.get(name, value))
            (root/"cpu.max").write_text("190000 100000\n")
            actual={**archive.properties(guard.PROPERTIES), **guard.SANDBOX, "RuntimeMaxUSec": "17s",
                "TemporaryFileSystem": guard.system_masks(profile="standard"),
                "UnsetEnvironment": " ".join(guard.DELEGATION_ENV)}
            guard.verify(actual, root, "system", guard.SANDBOX, archive.PROFILE, runtime_seconds=17)
            self.assertEqual(guard.workload_pids_observation(None, archive.PROFILE).expected_limit, 480)
            with self.assertRaises(ValueError):
                guard.verify({**actual, "TasksMax": "512"}, root, "system",
                    guard.SANDBOX, archive.PROFILE, runtime_seconds=17)
        with Fixture() as fixture:
            self.assertIs(archive.Witness, kernel.Witness)
            result=fixture.witness.complete(0, True, True, True)
            self.assertIs(result["custody_observed"], False)
            (fixture.root/"memory.max").write_text("268435457\n")
            with self.assertRaises(ValueError): fixture.witness.complete(0, True, True, True)

    def test_archive_worker_has_original_terminal_authority_and_unknown_profiles_refuse(self):
        fixture=kernel_models.ProofWorkerModels()
        witness=fixture.worker()
        witness.alive=Mock(side_effect=[True, False, False])
        now=[0.0]; read=Mock(side_effect=fixture.terminal)
        result=archive.monitor(archive.PROFILE, witness, read, 10, lambda: None,
            clock=lambda: now[0], pause=lambda seconds: now.__setitem__(0, now[0]+seconds))
        self.assertEqual(result, 0)
        read.assert_called_once()
        for profile in ("standard", "default-archive-reserved-unknown"):
            read=Mock()
            with self.assertRaises(ValueError):
                archive.monitor(profile, witness, read, 10, lambda: None, clock=lambda: 0)
            read.assert_not_called()
        witness=fixture.worker(); witness.alive=Mock(return_value=False)
        with self.assertRaises(ValueError):
            archive.monitor(archive.PROFILE, witness,
                lambda: fixture.terminal(InvocationID="b"*32), 10, lambda: None, clock=lambda: 0)
        self.assertNotIn(archive.PROFILE, kernel.PROFILES)
        self.assertEqual(kernel.ARCHIVE_MODELS, ["test", "//tools:guard_default_archive_reserved_test",
            "//tools:guard_resident_owned_update_test", "//tools:execution_guard_test", "//:docs_check"])
        self.assertEqual(kernel.selected(kernel.MODEL_PROFILE, kernel.ARCHIVE_MODELS),
            {"PrivateNetwork": "yes"})
        with self.assertRaises(ValueError):
            kernel.selected(kernel.MODEL_PROFILE, [*kernel.ARCHIVE_MODELS, "//:omux"])
        with self.assertRaises(ValueError):
            archive.selected(archive.PROFILE, kernel.ARCHIVE_MODELS)

    def test_owned_consumer_accepts_only_exact_successful_fresh_reserved_build(self):
        with Fixture() as fixture:
            observed=fixture.witness.complete(0, True, True, True)
            epoch="11111111-1111-4111-8111-111111111111"
            root=Path("/srv/fast-local/jess/state/codex/omux-integrated-execution-20261005")/epoch
            receipt={"id": epoch, "artifact_epoch": epoch, "profile": archive.PROFILE,
                "manager": "system", "verb": "build", "targets": [archive.LABEL], "exit": 0,
                "workload_exit": 0, "descendants_empty": True, "cleanup": {"state": "empty"},
                "controller_failure": None, "cache_reuse_requested": False, "cache_policy": None,
                "cache_key": None, "source_commit": "a"*40, "source_dirty": "false",
                "graph_sha256": "b"*64, "output_base": str(root/"output-base"),
                "limits": archive.properties(guard.PROPERTIES),
                "observed_properties": archive.properties(guard.PROPERTIES),
                "isolation": {"PrivateNetwork": "yes"}, "default_archive_reservation":
                    archive.projection(fixture.witness.entry, fixture.witness.deadline, True, observed)}
            qualification={"path": str(root/"receipt.json"), "sha256": "c"*64,
                "bytes": 1, "source_commit": "a"*40, "graph_sha256": "b"*64}
            self.assertEqual(update.qualification_output(receipt, qualification), root/"output-base")
            for cpu in ("1.900000s", "1900ms", "1900000us"):
                equivalent=copy.deepcopy(receipt)
                equivalent["observed_properties"]["CPUQuotaPerSecUSec"]=cpu
                self.assertEqual(update.qualification_output(equivalent, qualification), root/"output-base")
            for cpu in ("1900001us", "1899999us", True, 1900000, "2s"):
                bad=copy.deepcopy(receipt); bad["observed_properties"]["CPUQuotaPerSecUSec"]=cpu
                with self.assertRaises(ValueError): update.qualification_output(bad, qualification)
            tighter=copy.deepcopy(receipt)
            tighter["default_archive_reservation"]["resident"]["kernel_bounds"]["pids.max"]="1"
            tighter["default_archive_reservation"]["resident"]["initial_direct_process_count"]=1
            self.assertEqual(update.qualification_output(tighter, qualification), root/"output-base")
            tighter["default_archive_reservation"]["resident"]["initial_direct_process_count"]=2
            with self.assertRaises(ValueError): update.qualification_output(tighter, qualification)
            # The existing historical standard reader remains a distinct branch.
            old=copy.deepcopy(receipt); old["profile"]="standard"; old.pop("default_archive_reservation")
            self.assertEqual(update.qualification_output(old, qualification), root/"output-base")
            for section, key, value in ((None, "cache_reuse_requested", True),
                (None, "workload_exit", 1), (None, "output_base", str(root.parent/"old/output-base")),
                (None, "graph_sha256", "d"*64), ("default_archive_reservation", "verified_after_cleanup", False),
                ("default_archive_reservation", "original_entry_monotonic_ns", True),
                ("default_archive_reservation", "original_deadline_monotonic_ns", fixture.witness.deadline+1),
                ("default_archive_reservation", "archive_installed", True),
                ("observed_properties", "MemoryMax", "4294967296"), ("isolation", "PrivateNetwork", "no")):
                bad=copy.deepcopy(receipt)
                (bad if section is None else bad[section])[key]=value
                with self.subTest(section=section, key=key), self.assertRaises(ValueError):
                    update.qualification_output(bad, qualification)
            for key, value in (("observations", True), ("initial_direct_processes_retained", False),
                ("custody_observed", True), ("whole_host_reservation", True)):
                bad=copy.deepcopy(receipt); bad["default_archive_reservation"]["resident"][key]=value
                with self.assertRaises(ValueError): update.qualification_output(bad, qualification)

if __name__ == "__main__":
    unittest.main()

