"""Exact N10 admission and owned worker models; no source or native proof."""
from pathlib import Path
from types import SimpleNamespace
import os
import tempfile
import unittest
from unittest.mock import Mock, patch

import execution_guard as guard
import guard_native_seed_plan_reserved as kernel
import guard_native_file_writer_source_reserved as source
import guard_resident_native_source_acquisition_source_reserved as ninth
import guard_native_acquisition_inputs_reserved as native
import guard_resident_observation as resident


class FileWriterReservationModels(unittest.TestCase):
    def args(self):
        return SimpleNamespace(profile=source.PROFILE, manager="system", reuse_owned_cache=False,
            source_commit="a" * 40, source_dirty="false", repository_cache=None, nixpkgs_source=None)

    def test_exact_three_targets_refuse_cross_family_before_tool_or_resident_reads(self):
        expected = ["test", "//tools:codex_native_source_file_writer_test",
            "//tools:codex_native_source_file_writer_producer",
            "//tools:codex_native_source_file_writer_metadata_producer"]
        self.assertEqual(source.ARGUMENTS, expected)
        self.assertTrue(source.request(self.args(), expected))
        invalid = [expected[:-1], ["test", *expected[2:]], ["test", *reversed(expected[1:])],
            expected + [expected[1]], ["build", *expected[1:]], ["run", *expected[1:]],
            expected + ["//:docs_check"], expected + ["--test_arg=untrusted"], ninth.ARGUMENTS,
            ["test", "//tools:codex_native_carrier_sdk_export_producer"],
            ["test", "//tools:codex_native_carrier_compilation_producer"],
            ["test", "//tools:codex_native_carrier_runtime_package"],
            ["test", "//tools:codex_acquisition_direct_native_tui_test"],
            ["test", "//delivery:codex_device_acquisition_component_test"]]
        with patch.object(guard, "immutable", side_effect=AssertionError("tool read")) as tool, \
                patch.object(source, "Witness", side_effect=AssertionError("resident read")) as witness:
            for arguments in invalid:
                with self.subTest(arguments=arguments):
                    with self.assertRaises(ValueError): source.request(self.args(), arguments)
                    with self.assertRaises(ValueError):
                        guard.main(["--profile", source.PROFILE, "--manager", "system", "--source-commit",
                            "a" * 40, "--source-dirty", "false", "--", *arguments])
            tool.assert_not_called(); witness.assert_not_called()
        with self.assertRaises(ValueError): ninth.selected(ninth.PROFILE, expected)
        for profile in kernel.PROFILES:
            with self.assertRaises(ValueError): kernel.selected(profile, expected)
        for profile in native.PROFILES:
            with self.assertRaises(ValueError): native.selected(profile, expected)
        self.assertNotIn(source.PROFILE, kernel.PROFILES)
        self.assertNotIn(source.PROFILE, kernel.WORKLOAD_PROFILES)
        self.assertNotIn(source.PROFILE, ninth.PROFILES)
        self.assertNotIn(source.PROFILE, native.PROFILES)
        args = self.args(); args.profile = ninth.PROFILE
        self.assertFalse(source.request(args, expected))

    def test_unrelated_native_resident_cache_and_unclean_source_options_refuse(self):
        for name,value in (("manager","user"),("reuse_owned_cache",True),("source_dirty","true"),
                ("source_commit","a" * 39),("source_commit",True),
                ("resident_manifest",Path("/model/private")),("codex_live_manifest",Path("/model/live")),
                ("codex_owner_runtime_directory",Path("/model/runtime")),("native_mode","schema"),
                ("codex_fresh_runtime_selection",Path("/model/runtime.json"))):
            args = self.args(); setattr(args,name,value)
            with self.subTest(name=name),self.assertRaises(ValueError): source.request(args,source.ARGUMENTS)
        with patch.object(guard,"immutable",side_effect=AssertionError("tool read")) as tool:
            for options in (["--resident-manifest","/model/private"], ["--codex-live-manifest","/model/live"],
                    ["--codex-owner-runtime-directory","/model/runtime"], ["--reuse-owned-cache"]):
                with self.assertRaises(ValueError):
                    guard.main(["--profile",source.PROFILE,"--manager","system","--source-commit",
                        "a" * 40,"--source-dirty","false",*options,"--",*source.ARGUMENTS])
            tool.assert_not_called()
        args = self.args();args.repository_cache = Path("/model/cache")
        with self.assertRaises(ValueError):source.request(args,source.ARGUMENTS)

    def test_actual_bazel_command_forwards_one_original_clock_and_offline_fresh_action(self):
        entry,deadline = 100 * 10**9,1300 * 10**9
        with patch.object(kernel.time,"monotonic_ns",return_value=200 * 10**9):
            command = source.command(guard.bazel_command,"bazel",Path("/model/epoch"),source.ARGUMENTS,
                source.PROFILE,entry,deadline)
            self.assertEqual(source.runtime_seconds(entry,deadline),840)
        self.assertEqual(command[-3:],source.ARGUMENTS[1:])
        expected = ["--repository_disable_download","--repo_contents_cache=","--lockfile_mode=error",
            "--sandbox_default_allow_network=false","--remote_executor=","--remote_cache=",
            "--nocache_test_results","--output_base=/model/epoch/output-base","--test_timeout=840",
            "--test_env="+source.MODE+"="+source.PROFILE,
            "--test_env="+source.ENTRY+"="+str(entry),"--test_env="+source.DEADLINE+"="+str(deadline)]
        for option in expected:self.assertIn(option,command)
        for variable in (source.MODE,source.ENTRY,source.DEADLINE):
            self.assertEqual(len([v for v in command if v.startswith("--test_env="+variable+"=")]),1)
        self.assertFalse(any(v.startswith("--test_env=OMUX_NATIVE_SEED_") for v in command))
        builder = Mock()
        with patch.object(kernel.time,"monotonic_ns",return_value=200 * 10**9):
            with self.assertRaises(ValueError):source.command(builder,"bazel",Path("/model/epoch"),source.ARGUMENTS,
                source.PROFILE,entry,deadline,output_base=Path("/model/reused"))
            with self.assertRaises(ValueError):source.command(builder,"bazel",Path("/model/epoch"),source.ARGUMENTS,
                source.PROFILE,entry,deadline+1)
        builder.assert_not_called()
        with patch.object(kernel.time,"monotonic_ns",return_value=1260 * 10**9):
            self.assertEqual(source.runtime_seconds(entry,deadline),10)
        with patch.object(kernel.time,"monotonic_ns",return_value=1270 * 10**9):
            with self.assertRaises(ValueError):source.runtime_seconds(entry,deadline)
            self.assertEqual(source.remaining(entry,deadline,cleanup=True),30)
        with patch.object(kernel.time,"monotonic_ns",return_value=1300 * 10**9):
            with self.assertRaises(ValueError):source.remaining(entry,deadline,cleanup=True)

    def test_effective_readback_keeps_resident_reserve_swap_and_action_caps(self):
        for name in ("Witness","cleanup_retained","remaining","properties"):
            self.assertIs(getattr(source,name),getattr(kernel,name))
        self.assertIs(source.WorkloadWitness.__bases__[0],kernel.WorkloadWitness)
        caps = source.properties(guard.PROPERTIES)
        self.assertEqual(int(caps["MemoryMax"])+resident.RESIDENT_MEMORY,4*1024**3)
        self.assertEqual(int(caps["TasksMax"])+resident.RESIDENT_TASKS,512)
        self.assertEqual(source.CPU+resident.RESIDENT_CPU_PERCENT,200)
        self.assertEqual(caps["CPUQuotaPerSecUSec"],"1.9s")
        self.assertEqual(caps["MemorySwapMax"],"0")
        self.assertEqual(guard.workload_pids_observation(None,source.PROFILE).expected_limit,480)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name,value in guard.CGROUP.items():
                (root/name).write_text({"memory.max":str(source.MEMORY),"pids.max":"480"}.get(name,value))
            (root/"cpu.max").write_text("190000 100000")
            actual = {**caps,**guard.SANDBOX,"RuntimeMaxUSec":"17s",
                "TemporaryFileSystem":guard.system_masks(profile="standard"),
                "UnsetEnvironment":" ".join(guard.DELEGATION_ENV)}
            guard.verify(actual,root,"system",guard.SANDBOX,source.PROFILE,runtime_seconds=17)
            for key,value in (("PrivateNetwork","no"),("TasksMax","512"),("MemoryMax","4294967296"),
                    ("CPUQuotaPerSecUSec","2s"),("MemorySwapMax","1"),("RuntimeMaxUSec","841s")):
                with self.assertRaises(ValueError):guard.verify({**actual,key:value},root,"system",
                    guard.SANDBOX,source.PROFILE,runtime_seconds=17)
            with self.assertRaises(ValueError):guard.verify({**actual,"RuntimeMaxUSec":"841s"},root,
                "system",guard.SANDBOX,source.PROFILE,runtime_seconds=841)
            for seconds in (None,True,0,17.0):
                with self.assertRaises(ValueError):guard.verify(actual,root,"system",guard.SANDBOX,
                    source.PROFILE,runtime_seconds=seconds)

    def worker(self):
        worker = source.WorkloadWitness.__new__(source.WorkloadWitness)
        worker.unit = "omux-execution-12345678-1234-1234-1234-123456789abc.service"
        worker.invocation = "a"*32;worker.pid = 123
        return worker

    def terminal(self,worker):
        return {"Id":worker.unit,"InvocationID":worker.invocation,"ExecMainPID":str(worker.pid),
            "MainPID":"0","ActiveState":"active","SubState":"exited","RemainAfterExit":"yes",
            "ExecMainCode":"1","ExecMainStatus":"0","Result":"success"}

    def test_owned_worker_constructor_refuses_other_profiles_before_process_observation(self):
        with patch.object(kernel,"open_chain",side_effect=AssertionError("cgroup read")) as chain, \
                patch.object(kernel.os,"pidfd_open",side_effect=AssertionError("pidfd read")) as pidfd:
            for profile in (ninth.PROFILE,"standard","native-sdk-carrier-package-reserved"):
                with self.assertRaises(ValueError):source.WorkloadWitness(profile,100*10**9,1300*10**9,
                    object(),{},123,456)
            chain.assert_not_called();pidfd.assert_not_called()
        self.assertTrue(self.worker().admitted_profile(source.PROFILE))
        self.assertFalse(self.worker().admitted_profile(ninth.PROFILE))

    def test_monitor_requires_exact_worker_and_original_terminal_identity(self):
        worker = self.worker();worker.alive = Mock(return_value=False)
        actual = self.terminal(worker);readback = Mock(return_value=actual);iteration = Mock()
        self.assertEqual(source.monitor(source.PROFILE,worker,readback,200,iteration,
            clock=lambda:100,pause=Mock()),0)
        self.assertEqual(worker.alive.call_count,2);readback.assert_called_once();iteration.assert_called_once()
        for key,value in (("Id","other.service"),("InvocationID","b"*32),("ExecMainPID","999")):
            with self.assertRaises(ValueError):worker.terminal({**actual,key:value})
        self.assertEqual(worker.terminal({**actual,"Result":"exit-code"}),125)
        with self.assertRaises(ValueError):source.monitor(ninth.PROFILE,worker,readback,200,iteration,
            clock=lambda:100,pause=Mock())
        with self.assertRaises(ValueError):source.monitor(source.PROFILE,kernel.WorkloadWitness.__new__(kernel.WorkloadWitness),
            readback,200,iteration,clock=lambda:100,pause=Mock())
        self.assertEqual(source.monitor(source.PROFILE,worker,Mock(side_effect=AssertionError("late manager")),
            100,Mock(side_effect=AssertionError("late iteration")),clock=lambda:100,pause=Mock()),124)

    def test_cleanup_wrong_owner_refuses_before_stop_authority_and_keeps_frozen_bounds(self):
        worker = self.worker();actual = self.terminal(worker)
        worker.check_directory = Mock(return_value=True);worker.check_bounds = Mock(return_value={"frozen":True})
        worker.bounds = {"frozen":True};worker.entry = 100*10**9;worker.deadline = 1300*10**9;worker.pidfd = -1
        worker.pin = SimpleNamespace(path=Path("/sys/fs/cgroup/system.slice")/worker.unit,observe=lambda:"empty")
        actual.update(ControlGroup="/system.slice/"+worker.unit)
        with patch.object(kernel.time,"monotonic_ns",return_value=200*10**9), \
                patch.object(kernel.poll,"select",return_value=([-1],[],[])):
            for key,value in (("Id","other.service"),("InvocationID","b"*32),("ExecMainPID","999"),
                    ("RemainAfterExit","no")):
                with self.assertRaises(ValueError):worker.authorize_cleanup({**actual,key:value})
            worker.check_directory.assert_not_called();worker.check_bounds.assert_not_called()
            worker.authorize_cleanup(actual)
        self.assertEqual(worker.check_directory.call_count,2);worker.check_bounds.assert_called_once()
        self.assertEqual(worker.bounds,{"frozen":True})

    def test_release_failure_and_wrong_family_cannot_promote_cleanup(self):
        self.assertTrue(source.release_worker(None))
        worker = self.worker();worker.close = Mock()
        self.assertTrue(source.release_worker(worker));worker.close.assert_called_once()
        worker.close = Mock(side_effect=OSError("modeled close failure"))
        self.assertFalse(source.release_worker(worker))
        with self.assertRaises(ValueError):source.release_worker(kernel.WorkloadWitness.__new__(kernel.WorkloadWitness))

    def test_release_closes_actual_owned_descriptors_and_detaches_before_fault(self):
        worker = self.worker();left,right = os.pipe()
        worker.resources = [left,right];worker.chain = [];worker.directory = None
        try:
            self.assertTrue(source.release_worker(worker))
            self.assertEqual(worker.resources,[]);self.assertEqual(worker.chain,[])
            for fd in (left,right):
                with self.assertRaises(OSError):os.fstat(fd)
            self.assertTrue(source.release_worker(worker))
        finally:
            for fd in worker.resources:os.close(fd)
        worker = self.worker();left,right = os.pipe();os.close(right)
        worker.resources = [left,right];worker.chain = [];worker.directory = None
        try:
            self.assertFalse(source.release_worker(worker))
            self.assertEqual(worker.resources,[])
            with self.assertRaises(OSError):os.fstat(left)
            self.assertTrue(source.release_worker(worker))
        finally:
            for fd in worker.resources:os.close(fd)

    def test_failed_cleanup_or_evidence_never_qualifies_resident_completion(self):
        witness = source.Witness.__new__(source.Witness)
        witness.observe = Mock(side_effect=AssertionError("unqualified completion observation"))
        for result,cleaned,evidence,unchanged in ((0,False,True,True),(0,True,False,True),
                (0,True,True,False),(125,True,True,True),(False,True,True,True)):
            with self.assertRaises(ValueError):witness.complete(result,cleaned,evidence,unchanged)
        witness.observe.assert_not_called()
        row = source.projection(100*10**9,1300*10**9,False,{"resident_signalled":False})
        self.assertIs(row["verified_after_cleanup"],False)

    def test_receipt_never_promotes_native_provider_or_ordinary_authority(self):
        for verified in (None,False,True):
            row = source.projection(100*10**9,1300*10**9,verified,{"resident_signalled":False})
            self.assertIs(row["verified_after_cleanup"],verified)
            self.assertEqual(row["mode"],"tenth-file-writer-source-composition")
            self.assertEqual(row["action_cap_seconds"],840)
            self.assertTrue(all(value is False for name,value in row.items() if name.endswith("_qualified")))
            self.assertIs(row["native_source_finalized"],False)
        with self.assertRaises(ValueError):source.projection(100*10**9,1300*10**9,1,{})
        with self.assertRaises(ValueError):source.projection(100*10**9,1301*10**9,True,{})


if __name__ == "__main__":unittest.main()
