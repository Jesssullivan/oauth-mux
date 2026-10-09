"""Synthetic kernel files + real own pidfd; no installed/runtime qualification."""
from contextlib import ExitStack
import copy
import json
import os
from pathlib import Path
import stat
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch
import execution_guard as guard
import guard_native_seed_plan_reserved as reserved
import guard_resident_observation as resident

# Fixture-only /tmp sticky exception. All other ancestors and nofollow walking
# retain production custody; production open_directory is unchanged.
def fixture_ancestor(info,path):
    if path==Path("/tmp") and info.st_uid==0 and stat.S_IMODE(info.st_mode)==0o1777:
        return
    reserved.require(stat.S_ISDIR(info.st_mode) and info.st_uid in (0,os.getuid()) and not info.st_mode&0o022)

class Fixture:
    def __init__(self):
        self.stack=ExitStack()
        self.parent=Path(self.stack.enter_context(tempfile.TemporaryDirectory()))
        self.middle=self.parent/"middle";self.middle.mkdir(mode=0o700)
        self.root=self.middle/"group"; self.root.mkdir(mode=0o700)
        values={"memory.max":"268435456","memory.swap.max":"0","pids.max":"32",
            "cpu.max":"10000 100000","cgroup.procs":str(os.getpid()),
            "pids.current":"1","cgroup.events":"populated 1\nfrozen 0"}
        for name,value in values.items(): (self.root/name).write_text(value+"\n")
        self.stack.enter_context(patch.object(reserved,"cgroup_path",lambda uid:self.root))
        self.stack.enter_context(patch.object(reserved,"ancestor",fixture_ancestor))
        entry=time.monotonic_ns()
        self.witness=reserved.Witness(entry,entry+1200*10**9)
        self.stack.callback(self.witness.close)
    def __enter__(self):return self
    def __exit__(self,*args):return self.stack.__exit__(*args)

class ReservationModels(unittest.TestCase):
    def args(self,profile=reserved.PROFILE):
        return SimpleNamespace(profile=profile,manager="system",reuse_owned_cache=False,
            source_commit="a"*40,source_dirty="false",repository_cache=None,nixpkgs_source=None)

    def test_closed_selectors_and_unrelated_inputs_refuse_before_guard_tools(self):
        self.assertTrue(reserved.request(self.args(),["test",reserved.LABEL]))
        self.assertTrue(reserved.request(self.args(reserved.MODEL_PROFILE),list(reserved.MODELS)))
        self.assertTrue(reserved.request(self.args(reserved.MODEL_PROFILE),list(reserved.RECOVERY_MODELS)))
        self.assertTrue(reserved.request(self.args(reserved.MODEL_PROFILE),list(reserved.QUERY_MODELS)))
        self.assertFalse(reserved.request(self.args("standard"),["test","//:docs_check"]))
        for profile,args in ((reserved.PROFILE,["test",reserved.LABEL,"//:docs_check"]),
            (reserved.PROFILE,["run",reserved.LABEL]),
            (reserved.MODEL_PROFILE,["test",reserved.LABEL]),
            (reserved.MODEL_PROFILE,list(reversed(reserved.MODELS))),
            (reserved.MODEL_PROFILE,list(reversed(reserved.QUERY_MODELS))),
            (reserved.MODEL_PROFILE,reserved.QUERY_MODELS+["//:engine_test"]),
            (reserved.PROFILE,list(reserved.QUERY_MODELS))):
            with self.assertRaises(ValueError): reserved.request(self.args(profile),args)
        for key,value in (("manager","user"),("reuse_owned_cache",True),("source_dirty","true"),
            ("native_mode","schema"),("resident_manifest",Path("/model/input.json")),
            ("codex_owner_runtime_directory",Path("/model/retained")),("repository_cache",Path("/model/cache"))):
            args=self.args(); setattr(args,key,value)
            with self.assertRaises(ValueError): reserved.request(args,["test",reserved.LABEL])
        with patch.object(guard,"immutable",side_effect=AssertionError("tool read")) as tools:
            for parts in (["--manager","user"],["--reuse-owned-cache"]):
                with self.assertRaises(ValueError):
                    guard.main(["--profile",reserved.PROFILE,"--manager","system","--source-commit","a"*40,
                        "--source-dirty","false",*parts,"--","test",reserved.LABEL])
            tools.assert_not_called()

    def test_integrated_model_cohort_requires_all_eleven_in_exact_order_before_tools(self):
        expected=["test","//tools:guard_native_seed_plan_reserved_test",
            "//tools:guard_query_registration_reserved_test","//tools:guard_default_archive_reserved_test",
            "//tools:guard_resident_owned_update_test","//tools:codex_query_registration_test",
            "//tools:codex_protocol_history_query_tools_test","//tools:codex_protocol_history_metadata_test",
            "//tools:codex_protocol_history_sdk_export_test","//tools:native_flake_seed_plan_carrier_test",
            "//tools:execution_guard_test","//:docs_check"]
        self.assertEqual(reserved.INTEGRATED_MODELS,expected)
        self.assertTrue(reserved.request(self.args(reserved.MODEL_PROFILE),expected))
        for cohort in (reserved.MODELS,reserved.RECOVERY_MODELS,reserved.QUERY_MODELS,
                reserved.ARCHIVE_MODELS,reserved.REGISTRATION_MODELS,reserved.REGISTRATION_RESERVED_MODELS):
            self.assertTrue(reserved.request(self.args(reserved.MODEL_PROFILE),list(cohort)))
        invalid=[list(reversed(expected)),expected[:-1],expected+["//:engine_test"],
            expected+[expected[1]],expected+["--test_filter=untrusted"],
            ["run",*expected[1:]],["test","//tools:codex_query_registration_producer"],
            ["test","//tools:codex_query_registration_reserved_producer"],
            ["test",reserved.LABEL]]
        swapped=list(expected);swapped[1],swapped[2]=swapped[2],swapped[1];invalid.append(swapped)
        for label in ("//tools:codex_query_registration_producer",
                "//tools:codex_query_registration_reserved_producer",reserved.LABEL):
            replaced=list(expected);replaced[2]=label;invalid.append(replaced)
        for arguments in invalid:
            with self.assertRaises(ValueError):reserved.request(self.args(reserved.MODEL_PROFILE),arguments)
        with self.assertRaises(ValueError):reserved.request(self.args(reserved.PROFILE),expected)
        with patch.object(guard,"immutable",side_effect=AssertionError("unexpected tool IO")) as tools:
            for arguments in invalid:
                with self.assertRaises(ValueError):
                    guard.main(["--profile",reserved.MODEL_PROFILE,"--manager","system",
                        "--source-commit","a"*40,"--source-dirty","false","--",*arguments])
            for options in (["--manager","user"],["--reuse-owned-cache"]):
                with self.assertRaises(ValueError):
                    guard.main(["--profile",reserved.MODEL_PROFILE,"--manager","system",
                        "--source-commit","a"*40,"--source-dirty","false",*options,"--",*expected])
            tools.assert_not_called()

    def test_integrated_model_command_keeps_exact_targets_original_cutoff_and_caps(self):
        with patch.object(reserved.time,"monotonic_ns",return_value=200*10**9):
            actual=reserved.command(guard.bazel_command,"bazel",Path("/model/epoch"),
                reserved.INTEGRATED_MODELS,reserved.MODEL_PROFILE,100*10**9,1300*10**9)
        self.assertEqual(actual[-11:],reserved.INTEGRATED_MODELS[1:])
        for flag in ("--repository_disable_download","--repo_contents_cache=","--lockfile_mode=error",
                "--sandbox_default_allow_network=false","--remote_executor=","--remote_cache=",
                "--nocache_test_results"):
            self.assertIn(flag,actual)
        for marker in (reserved.MODE,reserved.ENTRY,reserved.DEADLINE):
            self.assertFalse(any(flag.startswith("--test_env="+marker+"=") for flag in actual))
        self.assertEqual(reserved.properties(guard.PROPERTIES)["MemoryMax"],"4026531840")
        self.assertEqual(reserved.properties(guard.PROPERTIES)["TasksMax"],"480")
        self.assertEqual(reserved.properties(guard.PROPERTIES)["CPUQuotaPerSecUSec"],"1.9s")
        self.assertEqual(reserved.envelope(100*10**9,1300*10**9),1270*10**9)
        with patch.object(reserved.time,"monotonic_ns",return_value=1270*10**9):
            with self.assertRaises(ValueError):
                reserved.command(guard.bazel_command,"bazel",Path("/model/epoch"),
                    reserved.INTEGRATED_MODELS,reserved.MODEL_PROFILE,100*10**9,1300*10**9)
        builder=Mock()
        with patch.object(reserved.time,"monotonic_ns",return_value=200*10**9):
            with self.assertRaises(ValueError):
                reserved.command(builder,"bazel",Path("/model/epoch"),
                    reserved.INTEGRATED_MODELS+["//tools:codex_query_registration_reserved_producer"],
                    reserved.MODEL_PROFILE,100*10**9,1300*10**9)
        builder.assert_not_called()

    def test_registration_model_cohort_is_exact_ordered_and_not_collector_authority(self):
        expected=["test","//tools:codex_query_registration_test",
            "//tools:codex_protocol_history_query_tools_test",
            "//tools:codex_protocol_history_metadata_test","//tools:codex_protocol_history_sdk_export_test",
            "//tools:native_flake_seed_plan_carrier_test","//:docs_check"]
        self.assertEqual(reserved.REGISTRATION_MODELS,expected)
        self.assertTrue(reserved.request(self.args(reserved.MODEL_PROFILE),expected))
        for cohort in (reserved.MODELS,reserved.RECOVERY_MODELS,reserved.QUERY_MODELS,reserved.ARCHIVE_MODELS):
            self.assertTrue(reserved.request(self.args(reserved.MODEL_PROFILE),list(cohort)))
        invalid=[list(reversed(expected)),expected+["//:engine_test"],expected[:-1],
            ["test","//tools:codex_query_registration_producer"],expected+["//tools:codex_query_registration_producer"],
            ["run",*expected[1:]],["test",*expected[1:],expected[1]]]
        swapped=list(expected);swapped[1],swapped[2]=swapped[2],swapped[1];invalid.append(swapped)
        for arguments in invalid:
            with self.assertRaises(ValueError):reserved.request(self.args(reserved.MODEL_PROFILE),arguments)
        with self.assertRaises(ValueError):reserved.request(self.args(reserved.PROFILE),expected)
        with patch.object(guard,"immutable",side_effect=AssertionError("unexpected tool IO")) as tools:
            for arguments in invalid:
                with self.assertRaises(ValueError):
                    guard.main(["--profile",reserved.MODEL_PROFILE,"--manager","system",
                        "--source-commit","a"*40,"--source-dirty","false","--",*arguments])
            tools.assert_not_called()

    def test_registration_model_command_keeps_reserved_clock_and_offline_caps(self):
        with patch.object(reserved.time,"monotonic_ns",return_value=200*10**9):
            actual=reserved.command(guard.bazel_command,"bazel",Path("/model/epoch"),
                reserved.REGISTRATION_MODELS,reserved.MODEL_PROFILE,100*10**9,1300*10**9)
        self.assertEqual(actual[-6:],reserved.REGISTRATION_MODELS[1:])
        for flag in ("--repository_disable_download","--repo_contents_cache=","--lockfile_mode=error",
                "--sandbox_default_allow_network=false","--remote_executor=","--remote_cache="):
            self.assertIn(flag,actual)
        self.assertFalse(any(flag.startswith("--test_env="+reserved.MODE+"=") for flag in actual))
        self.assertEqual(reserved.properties(guard.PROPERTIES)["MemoryMax"],"4026531840")
        self.assertEqual(reserved.properties(guard.PROPERTIES)["TasksMax"],"480")
        self.assertEqual(reserved.properties(guard.PROPERTIES)["CPUQuotaPerSecUSec"],"1.9s")
        with patch.object(reserved.time,"monotonic_ns",return_value=1270*10**9):
            with self.assertRaises(ValueError):
                reserved.command(guard.bazel_command,"bazel",Path("/model/epoch"),
                    reserved.REGISTRATION_MODELS,reserved.MODEL_PROFILE,100*10**9,1300*10**9)

    def test_actual_standard_command_preserves_offline_veto_and_original_envelope(self):
        with patch.object(reserved.time,"monotonic_ns",return_value=200*10**9):
            command=reserved.command(guard.bazel_command,"/nix/store/model/bin/bazel",Path("/model/epoch"),
                ["test",reserved.LABEL],reserved.PROFILE,100*10**9,1300*10**9,
                source_commit="a"*40,source_dirty="false")
            self.assertEqual(command[-1],reserved.LABEL)
            for flag in ("--batch","--nosystem_rc","--nohome_rc","--noworkspace_rc",
                "--repository_disable_download","--repo_contents_cache=","--disk_cache=",
                "--remote_cache=","--remote_executor=","--sandbox_default_allow_network=false",
                "--lockfile_mode=error","--nocache_test_results",
                "--test_env="+reserved.MODE+"="+reserved.PROFILE,
                "--test_env="+reserved.ENTRY+"=100000000000",
                "--test_env="+reserved.DEADLINE+"=1300000000000"):
                self.assertIn(flag,command)
            self.assertEqual(sum(option.startswith("--output_base=") for option in command),1)
            self.assertIn("--output_base=/model/epoch/output-base",command)
            cohort=reserved.command(guard.bazel_command,"bazel",Path("/model/epoch"),
                reserved.MODELS,reserved.MODEL_PROFILE,100*10**9,1300*10**9)
            self.assertEqual(cohort[-len(reserved.MODELS)+1:],reserved.MODELS[1:])
            self.assertFalse(any(option.startswith("--test_env="+reserved.MODE+"=") for option in cohort))
        with patch.object(reserved.time,"monotonic_ns",return_value=1270*10**9):
            with self.assertRaises(ValueError):
                reserved.command(guard.bazel_command,"bazel",Path("/model/epoch"),
                    ["test",reserved.LABEL],reserved.PROFILE,100*10**9,1300*10**9)

    def test_real_effective_caps_private_network_cpu_and_pids_are_selected(self):
        for profile in reserved.PROFILES:
            with tempfile.TemporaryDirectory() as temporary:
                root=Path(temporary)
                for name,value in guard.CGROUP.items():
                    (root/name).write_text({"memory.max":str(reserved.MEMORY),"pids.max":"480"}.get(name,value))
                (root/"cpu.max").write_text("190000 100000\n")
                actual={**reserved.properties(guard.PROPERTIES),**guard.SANDBOX,
                    "RuntimeMaxUSec":"17s","TemporaryFileSystem":guard.system_masks(profile="standard"),
                    "UnsetEnvironment":" ".join(guard.DELEGATION_ENV)}
                guard.verify(actual,root,"system",guard.SANDBOX,profile,runtime_seconds=17)
                observation=guard.workload_pids_observation(None,profile)
                self.assertEqual(observation.expected_limit,480)
                (root/"pids.current").write_text("1\n");(root/"pids.events").write_text("max 0\n")
                pin=guard.CgroupPin(root)
                try:
                    observation.sample(pin,"baseline")
                    self.assertEqual(observation.baseline["pids_limit"],"verified480")
                finally:pin.close()
                for key,value in (("PrivateNetwork","no"),("TasksMax","512"),("MemoryMax","4294967296"),
                    ("CPUQuotaPerSecUSec","2s"),("RuntimeMaxUSec","1200s")):
                    with self.assertRaises(ValueError):
                        guard.verify({**actual,key:value},root,"system",guard.SANDBOX,profile,runtime_seconds=17)
                for name,value in (("cpu.max","190001 100000"),("cpu.max","189999 100000"),
                    ("pids.max","481"),("memory.max","4026531841"),("memory.swap.max","1")):
                    prior=(root/name).read_text(); (root/name).write_text(value)
                    with self.assertRaises(ValueError):
                        guard.verify(actual,root,"system",guard.SANDBOX,profile,runtime_seconds=17)
                    (root/name).write_text(prior)

    def test_real_fixture_retains_own_pidfd_and_full_final_predicates(self):
        with Fixture() as fixture:
            self.assertEqual(len(fixture.witness.processes),1)
            result=fixture.witness.complete(0,True,True,True)
            self.assertTrue(result["initial_direct_processes_retained"])
            for name in ("installation_qualified","health_observed","custody_observed",
                "whole_host_reservation","resident_signalled","descendant_process_inventory"):
                self.assertIs(result[name],False)
            for arguments in ((True,True,True,True),(1,True,True,True),(0,False,True,True),
                (0,True,False,True),(0,True,True,False)):
                with self.assertRaises(ValueError): fixture.witness.complete(*arguments)
            with patch.object(reserved.time,"monotonic_ns",return_value=fixture.witness.deadline):
                with self.assertRaises(ValueError): fixture.witness.complete(0,True,True,True)

    def test_actual_kernel_drift_empty_process_and_namespace_identity_refuse(self):
        with Fixture() as fixture:
            for name,value in (("memory.max","268435457"),("memory.swap.max","1"),("pids.max","33"),
                ("cpu.max","10001 100000"),("cpu.max","9000 100000"),
                ("cgroup.procs",""),("cgroup.events","populated 0"),("pids.current","33")):
                prior=(fixture.root/name).read_text(); (fixture.root/name).write_text(value+"\n")
                with self.assertRaises(ValueError):fixture.witness.observe()
                (fixture.root/name).write_text(prior)
            with patch.object(reserved,"process",return_value=("changed",)):
                with self.assertRaises(ValueError):fixture.witness.observe()
            with patch.object(reserved.poll,"select",return_value=([fixture.witness.processes[0][1]],[],[])):
                with self.assertRaises(ValueError):fixture.witness.observe()

    def test_same_named_path_replaced_cgroup_is_not_retained_budget(self):
        with Fixture() as fixture:
            fixture.root.rename(fixture.parent/"old-group")
            fixture.root.mkdir(mode=0o700)
            with self.assertRaises(ValueError):fixture.witness.observe()


    def test_same_group_transplanted_through_replaced_ancestor_refuses(self):
        with Fixture() as fixture:
            old=fixture.parent/"old-middle"
            fixture.middle.rename(old);fixture.middle.mkdir(mode=0o700)
            (old/"group").rename(fixture.root)
            self.assertEqual(resident.stable(fixture.root.stat()),fixture.witness.identity)
            with self.assertRaises(ValueError):fixture.witness.observe()

    def test_close_fault_independently_drains_directory_after_pidfd(self):
        with Fixture() as fixture:
            witness=fixture.witness; directory=witness.directory; pidfd=witness.processes[0][1]
            original=os.close; calls=[]
            def close(fd):
                calls.append(fd)
                if fd==pidfd: raise OSError("synthetic close")
                original(fd)
            with patch.object(resident.os,"close",side_effect=close):
                with self.assertRaises(OSError):witness.close()
            self.assertEqual(witness.resources,[])
            self.assertIn(directory,calls)
            with self.assertRaises(OSError):os.fstat(directory)
            original(pidfd)
            witness.close()
            with self.assertRaises(ValueError):witness.observe()

    def test_fixed_named_path_and_strict_bounded_kernel_tuple(self):
        self.assertEqual(str(reserved.cgroup_path(1000)),
            "/sys/fs/cgroup/user.slice/user-1000.slice/user@1000.service/app.slice/ai.xoxd.omux.service")
        for uid in (True,0,-1,"1000"):
            with self.assertRaises(ValueError):reserved.cgroup_path(uid)
        good={"memory.max":"268435456","memory.swap.max":"0","pids.max":"32","cpu.max":"10000 100000"}
        self.assertEqual(reserved.kernel_bounds(good),good)
        for key,value in (("cpu.max","max 100000"),("cpu.max","0 100000"),
            ("cpu.max","10000 0"),("cpu.max","10001 100000"),("pids.max","0"),
            ("pids.max","032"),("memory.max","max"),("memory.swap.max","1")):
            with self.assertRaises(ValueError):reserved.kernel_bounds({**good,key:value})


class ProofWorkerModels(unittest.TestCase):
    UNIT="omux-execution-11111111-1111-1111-1111-111111111111.service"

    def worker(self):
        witness=reserved.WorkloadWitness.__new__(reserved.WorkloadWitness)
        witness.unit,witness.invocation,witness.pid=self.UNIT,"a"*32,1234
        return witness

    def terminal(self, **changes):
        return {"Id":self.UNIT,"InvocationID":"a"*32,"ExecMainPID":"1234",
            "ActiveState":"inactive","Result":"success","ExecMainCode":"1","ExecMainStatus":"0",
            "MainPID":"0","RemainAfterExit":"yes",**changes}

    def test_only_closed_query_cohort_uses_standard_command_without_native_inputs(self):
        self.assertEqual(reserved.QUERY_MODELS,["test","//tools:codex_protocol_history_query_tools_test",
            "//tools:codex_protocol_history_metadata_test","//tools:codex_protocol_history_sdk_export_test",
            "//tools:native_flake_seed_plan_carrier_test","//:docs_check"])
        with patch.object(reserved.time,"monotonic_ns",return_value=200*10**9):
            command=reserved.command(guard.bazel_command,"bazel",Path("/model/epoch"),
                reserved.QUERY_MODELS,reserved.MODEL_PROFILE,100*10**9,1300*10**9)
        self.assertEqual(command[-5:],reserved.QUERY_MODELS[1:])
        self.assertIn("--repository_disable_download",command)
        self.assertFalse(any(option.startswith("--test_env="+reserved.MODE+"=") for option in command))

    def test_live_worker_has_no_manager_poll_and_one_bound_terminal_read(self):
        for profile in reserved.PROFILES:
            witness=self.worker()
            witness.alive=Mock(side_effect=[True,True,False,False])
            now=[0.0];samples=[];reads=[]
            def pause(seconds): now[0]+=seconds
            def read(): reads.append(now[0]);return self.terminal()
            result=reserved.monitor(profile,witness,read,10,lambda:samples.append(now[0]),
                clock=lambda:now[0],pause=pause)
            self.assertEqual(result,0)
            self.assertEqual(reads,[1.0])
            self.assertEqual(samples,[0.0,0.5,1.0])
            self.assertEqual(witness.alive.call_count,4)

    def test_exit_never_supplies_success_or_adopts_other_epoch(self):
        witness=self.worker();witness.alive=Mock(return_value=False)
        for changes,expected in (({"Result":"signal"},125),({"ExecMainStatus":"7"},7),
            ({"ExecMainCode":"2","ExecMainStatus":"15","Result":"signal"},15),
            ({"ExecMainCode":"2"},125),({"ExecMainCode":"3"},125),
            ({"ActiveState":"activating"},125),({"ActiveState":"failed","ExecMainStatus":"9"},9)):
            self.assertEqual(reserved.monitor(reserved.PROFILE,witness,
                lambda:self.terminal(**changes),10,lambda:None,clock=lambda:0),expected)
        for changes in ({"Id":"foreign.service"},{"InvocationID":"b"*32},{"ExecMainPID":"1235"},
            {"ExecMainStatus":"not-an-integer"},{"ExecMainStatus":False},
            {"ExecMainStatus":"256"},{"ExecMainCode":"0"},{"ExecMainCode":True},
            {"MainPID":"1235"},{"RemainAfterExit":"no"}):
            with self.assertRaises(ValueError):
                reserved.monitor(reserved.PROFILE,witness,lambda:self.terminal(**changes),
                    10,lambda:None,clock=lambda:0)

    def test_original_deadline_live_expiry_late_terminal_and_query_fault(self):
        witness=self.worker();witness.alive=Mock(return_value=True)
        now=[0.0];read=Mock()
        def pause(seconds):now[0]+=seconds
        self.assertEqual(reserved.monitor(reserved.MODEL_PROFILE,witness,read,0.75,
            lambda:None,clock=lambda:now[0],pause=pause),124)
        read.assert_not_called();self.assertEqual(now[0],0.75)
        witness.alive=Mock(return_value=False)
        for status in ("0","3"):
            now[0]=0
            def late():now[0]=1;return self.terminal(ExecMainStatus=status)
            self.assertEqual(reserved.monitor(reserved.PROFILE,witness,late,1,
                lambda:None,clock=lambda:now[0]),124)
        with self.assertRaises(OSError):
            reserved.monitor(reserved.PROFILE,witness,Mock(side_effect=OSError("fixed model")),
                1,lambda:None,clock=lambda:0)
        for profile,candidate in (("standard",witness),(reserved.PROFILE,Mock())):
            with self.assertRaises(ValueError):
                reserved.monitor(profile,candidate,read,1,lambda:None,clock=lambda:0)

    def test_actual_held_fixture_caps_replacement_and_process_identity(self):
        # Synthetic cgroup files, real own pidfd/proc identity. Only proc membership
        # and privilege metadata are mocked because this test is not a service worker.
        with Fixture() as fixture:
            fixture.witness.close()
            for name,value in (("memory.max",str(reserved.MEMORY)),("pids.max","480"),
                ("cpu.max","190000 100000"),("memory.oom.group","1")):
                (fixture.root/name).write_text(value+"\n")
            pin=guard.CgroupPin(fixture.root)
            fixture.stack.callback(pin.close)
            path=Path("/sys/fs/cgroup/system.slice")/self.UNIT
            proxy=SimpleNamespace(path=path,identity=pin.identity,observe=pin.observe)
            entry=time.monotonic_ns()
            actual={"Id":self.UNIT,"InvocationID":"a"*32,"ActiveState":"active",
                "MainPID":str(os.getpid()),"ExecMainPID":str(os.getpid()),
                "ControlGroup":"/system.slice/"+self.UNIT,"RemainAfterExit":"yes"}
            with patch.object(reserved,"open_chain",lambda selected: reserved_open(fixture.root)), \
                    patch.object(reserved.WorkloadWitness,"check_process",return_value=None):
                witness=reserved.WorkloadWitness(reserved.PROFILE,entry,entry+1200*10**9,
                    proxy,actual,os.getpid(),resident.start_ticks(os.getpid()))
                fixture.stack.callback(witness.close)
                self.assertTrue(witness.alive())
                owned={**actual,"MainPID":"0","SubState":"exited"}
                post={**owned,"LoadState":"loaded","ActiveState":"inactive","SubState":"dead"}
                with patch.object(reserved.poll,"select",return_value=([witness.pidfd],[],[])):
                    # Original worker has exited, but owned descendants may remain.
                    # At the actual work cutoff cleanup still uses only original D.
                    with patch.object(reserved.time,"monotonic_ns",
                            return_value=witness.deadline-reserved.RESERVE_NS):
                        witness.authorize_cleanup(owned)
                    for key,value in (("ControlGroup",""),("ControlGroup","/foreign")):
                        stop=Mock()
                        summary=reserved.cleanup_retained(deadline=15,
                            readback=Mock(return_value={**owned,key:value}),authorize=witness.authorize_cleanup,
                            stop=stop,observe=pin.observe,clock=lambda:0)
                        self.assertEqual(summary["ownership"],"refused");stop.assert_not_called()
                    prior=(fixture.root/"cpu.max").read_text()
                    (fixture.root/"cpu.max").write_text("180000 100000\n")
                    stop=Mock()
                    summary=reserved.cleanup_retained(deadline=15,readback=Mock(return_value=owned),
                        authorize=witness.authorize_cleanup,stop=stop,observe=pin.observe,clock=lambda:0)
                    self.assertEqual(summary["ownership"],"refused");stop.assert_not_called()
                    (fixture.root/"cpu.max").write_text(prior)
                    calls=[]
                    def stop(timeout,deadline):
                        calls.append((timeout,deadline))
                        (fixture.root/"cgroup.events").write_text("populated 0\n")
                        (fixture.root/"cgroup.procs").write_text("\n")
                    summary=reserved.cleanup_retained(deadline=15,
                        readback=Mock(side_effect=[owned,post]),authorize=witness.authorize_cleanup,
                        stop=stop,observe=pin.observe,clock=lambda:0)
                    self.assertEqual(summary["state"],"empty");self.assertEqual(len(calls),1)
                    # A failed test result remains failed after positively owned cleanup.
                    (fixture.root/"cgroup.events").write_text("populated 1\n")
                    (fixture.root/"cgroup.procs").write_text(str(os.getpid())+"\n")
                    failed={**owned,"LoadState":"loaded","ActiveState":"failed","SubState":"failed",
                        "ExecMainCode":"1","ExecMainStatus":"3","Result":"exit-code"}
                    self.assertEqual(witness.terminal(failed),3)
                    calls.clear()
                    reads=Mock(side_effect=[failed,failed])
                    summary=reserved.cleanup_retained(deadline=15,readback=reads,
                        authorize=witness.authorize_cleanup,stop=stop,observe=pin.observe,clock=lambda:0)
                    self.assertEqual(summary["state"],"empty");self.assertEqual(len(calls),1)
                    self.assertEqual(reads.call_count,2)
                    self.assertEqual(summary["post_stop"]["predicate"],"owned-failed-terminal-predicate-passed")
                    self.assertEqual(witness.terminal(failed),3)
                    (fixture.root/"cgroup.events").write_text("populated 1\n")
                    (fixture.root/"cgroup.procs").write_text(str(os.getpid())+"\n")
                for name,value in (("memory.max",str(reserved.MEMORY+1)),("pids.max","481"),
                    ("cpu.max","190001 100000"),("memory.swap.max","1"),("memory.oom.group","0"),
                    ("cgroup.procs",""),("cgroup.events","populated 0")):
                    prior=(fixture.root/name).read_text();(fixture.root/name).write_text(value+"\n")
                    with self.assertRaises(ValueError):witness.alive()
                    (fixture.root/name).write_text(prior)
                with patch.object(reserved,"process",return_value=("different",)):
                    with self.assertRaises(ValueError):witness.alive()
                with patch.object(reserved.poll,"select",return_value=([witness.pidfd],[],[])):
                    self.assertFalse(witness.alive())  # Exit readiness still carries no status.
                    fixture.root.rename(fixture.parent/"retired-group")
                    fixture.root.mkdir(mode=0o700)
                    with self.assertRaises(ValueError):witness.alive()

    def test_pidfd_capture_failure_closes_every_adopted_ancestor(self):
        with Fixture() as fixture:
            fixture.witness.close()
            chain=reserved.open_chain(fixture.root)
            proxy=SimpleNamespace(path=Path("/sys/fs/cgroup/system.slice")/self.UNIT,
                identity=chain[-1][2][:2])
            actual={"Id":self.UNIT,"InvocationID":"a"*32,"ActiveState":"active",
                "MainPID":"1234","ExecMainPID":"1234","ControlGroup":"/system.slice/"+self.UNIT,"RemainAfterExit":"yes"}
            entry=time.monotonic_ns()
            with patch.object(reserved,"open_chain",return_value=chain), \
                    patch.object(reserved.os,"pidfd_open",side_effect=OSError("capture fault")):
                with self.assertRaises(OSError):
                    reserved.WorkloadWitness(reserved.PROFILE,entry,entry+1200*10**9,
                        proxy,actual,1234,"1")
            for _,fd,_ in chain:
                with self.assertRaises(OSError):os.fstat(fd)

    def test_fixed_proc_metadata_join_and_capability_drift(self):
        witness=self.worker()
        witness.pid=os.getpid()
        witness.pin=SimpleNamespace(path=Path("/sys/fs/cgroup/system.slice")/self.UNIT)
        cgroup=("0::/system.slice/"+self.UNIT+"\n").encode()
        status=("Uid:\t"+" ".join([str(os.getuid())]*4)+"\nGid:\t"+
            " ".join([str(os.getgid())]*4)+"\nNoNewPrivs:\t1\nCapEff:\t0000\n"+
            "CapPrm:\t0000\nCapAmb:\t0000\n").encode()
        def check(first,second):
            with patch.object(reserved.os,"open",return_value=99), \
                    patch.object(reserved.os,"read",side_effect=[first,b"",second,b""]), \
                    patch.object(reserved.os,"close") as close:
                witness.check_process()
                self.assertEqual(close.call_count,2)
        check(cgroup,status)
        for first,second in ((b"0::/foreign\n",status),(cgroup,status.replace(b"NoNewPrivs:\t1",b"NoNewPrivs:\t0")),
            (cgroup,status.replace(b"CapEff:\t0000",b"CapEff:\t0001")),
            (cgroup,status.replace(b"Uid:\t",b"Uid:\t99999 "))):
            with self.assertRaises(ValueError):check(first,second)


    def test_retained_exit_requires_original_pidfd_and_exact_terminal_substate(self):
        witness=self.worker()
        good=self.terminal(ActiveState="active",SubState="exited",MainPID="0",RemainAfterExit="yes")
        self.assertEqual(witness.terminal(good),0)
        for key,value in (("MainPID","1234"),("SubState","running"),("RemainAfterExit","no")):
            with self.assertRaises(ValueError):witness.terminal({**good,key:value})
        witness.pidfd=42
        witness.entry=time.monotonic_ns();witness.deadline=witness.entry+1200*10**9
        witness.check_directory=Mock(return_value=True);witness.check_bounds=Mock()
        witness.pin=SimpleNamespace(path=Path("/sys/fs/cgroup/system.slice")/self.UNIT,
            observe=Mock(return_value="empty"))
        good={**good,"ControlGroup":"/system.slice/"+self.UNIT}
        with patch.object(reserved.poll,"select",return_value=([42],[],[])):
            witness.authorize_cleanup(good)
            for key,value in (("InvocationID","b"*32),("ExecMainPID","99"),
                ("ControlGroup","/foreign"),("SubState","running")):
                with self.assertRaises(ValueError):witness.authorize_cleanup({**good,key:value})
            witness.pin.observe.return_value="changed"
            with self.assertRaises(ValueError):witness.authorize_cleanup(good)
        witness.pin.observe.return_value="empty"
        with patch.object(reserved.poll,"select",return_value=([],[],[])):
            with self.assertRaises(ValueError):witness.authorize_cleanup(good)

    def test_empty_retained_unit_still_requires_owned_stop_and_postread(self):
        owned=self.terminal(ActiveState="active",SubState="exited",MainPID="0",RemainAfterExit="yes")
        post={**owned,"ActiveState":"inactive","SubState":"dead","LoadState":"loaded"}
        for final in (post,{**post,"LoadState":"not-found","InvocationID":"","ExecMainPID":"0"}):
            reads=Mock(side_effect=[owned,final]);authorize=Mock();stop=Mock()
            summary=reserved.cleanup_retained(deadline=15,readback=reads,authorize=authorize,
                stop=stop,observe=Mock(return_value="empty"),clock=lambda:0)
            expected=reserved.post_stop_projection(final,(owned["Id"],owned["InvocationID"],owned["ExecMainPID"]))
            expected["original_cgroup_state"]="empty"
            self.assertEqual(summary,{"state":"empty","stop":"succeeded","ownership":"verified",
                "readback_attempts":2,"post_stop":expected})
            stop.assert_called_once();authorize.assert_called_once_with(owned)
        for changes in ({"ActiveState":"active"},{"InvocationID":"b"*32},{"ExecMainPID":"5678"},
            {"MainPID":"1234"}):
            summary=reserved.cleanup_retained(deadline=15,
                readback=Mock(side_effect=[owned,{**post,**changes}]),authorize=Mock(),stop=Mock(),
                observe=lambda:"empty",clock=lambda:0)
            self.assertEqual(summary["state"],"unproved")

    def test_retained_cleanup_foreign_or_changed_never_signals_and_late_refuses(self):
        owned=self.terminal(ActiveState="active",SubState="exited",MainPID="0",RemainAfterExit="yes")
        stop=Mock()
        summary=reserved.cleanup_retained(deadline=15,readback=Mock(return_value=owned),
            authorize=Mock(side_effect=ValueError("foreign")),stop=stop,
            observe=lambda:"empty",clock=lambda:0)
        self.assertEqual(summary["ownership"],"refused");stop.assert_not_called()
        read=Mock()
        summary=reserved.cleanup_retained(deadline=15,readback=read,authorize=Mock(),
            stop=stop,observe=lambda:"changed",clock=lambda:0)
        read.assert_not_called();stop.assert_not_called()
        now=[0]
        def late(timeout,deadline):now[0]=deadline;return owned
        summary=reserved.cleanup_retained(deadline=15,readback=late,authorize=Mock(),stop=stop,
            observe=lambda:"empty",clock=lambda:now[0])
        self.assertEqual(summary["state"],"deadline-exhausted");stop.assert_not_called()

    def test_worker_release_fault_is_refusal_before_success_and_fallback_idempotent(self):
        witness=self.worker()
        witness.resources,witness.chain,witness.directory=[99],[],99
        with patch.object(resident,"close_owned_resources",side_effect=OSError("owned close")):
            self.assertIs(reserved.release_worker(witness),False)
        self.assertEqual(witness.resources,[]);self.assertIsNone(witness.directory)
        self.assertIs(reserved.release_worker(witness),True)
        self.assertIs(reserved.release_worker(None),True)
        with self.assertRaises(ValueError):reserved.release_worker(Mock())


    def test_actual_post_stop_diagnostic_names_failure_without_relaxing_acceptance(self):
        owned=self.terminal(ActiveState="active",SubState="exited",MainPID="0",RemainAfterExit="yes")
        post={**owned,"ActiveState":"inactive","SubState":"dead","LoadState":"loaded"}
        failures=(({"LoadState":"loaded","InvocationID":""},"invocation-mismatch"),
            ({"ExecMainPID":"0"},"exec-main-pid-mismatch"),({"Id":"foreign"},"unit-id-mismatch"),
            ({"ActiveState":"failed","SubState":"failed"},"not-inactive"),({"SubState":"exited"},"not-dead"),
            ({"MainPID":"987654321"},"main-pid-not-zero"))
        for changes,predicate in failures:
            read=Mock(side_effect=[owned,{**post,**changes}]);observe=Mock(return_value="empty")
            summary=reserved.cleanup_retained(deadline=15,readback=read,authorize=Mock(),stop=Mock(),
                observe=observe,clock=lambda:0)
            self.assertEqual(summary["state"],"unproved")
            self.assertEqual(summary["post_stop"]["predicate"],predicate)
            if changes.get("ActiveState")=="failed":
                self.assertEqual(summary["post_stop"]["ActiveState"],"failed")
                self.assertEqual(summary["post_stop"]["SubState"],"failed")
            self.assertEqual(summary["post_stop"]["original_cgroup_state"],"not-observed")
            self.assertEqual(read.call_count,2)
            self.assertEqual(observe.call_count,2)
        for original in ("populated","changed","unproved","empty","absent"):
            summary=reserved.cleanup_retained(deadline=15,readback=Mock(side_effect=[owned,post]),
                authorize=Mock(),stop=Mock(),observe=Mock(side_effect=["empty","empty",original]),clock=lambda:0)
            self.assertEqual(summary["post_stop"]["original_cgroup_state"],original)
            self.assertEqual(summary["state"],"empty" if original in ("empty","absent") else "unproved")
        summary=reserved.cleanup_retained(deadline=15,
            readback=Mock(side_effect=[owned,OSError("unprinted transport detail")]),
            authorize=Mock(),stop=Mock(),observe=lambda:"empty",clock=lambda:0)
        self.assertEqual(summary["state"],"unproved")
        self.assertEqual(summary["post_stop"]["predicate"],"post-read-failed")


    def test_failed_terminal_cleanup_requires_unchanged_nonzero_exit_and_successful_owned_stop(self):
        owned=self.terminal(LoadState="loaded",ActiveState="failed",SubState="failed",
            ExecMainStatus="3",Result="exit-code")
        for original in ("empty","absent"):
            stop=Mock();read=Mock(side_effect=[owned,owned])
            summary=reserved.cleanup_retained(deadline=15,readback=read,authorize=Mock(),stop=stop,
                observe=Mock(side_effect=["empty","empty",original]),clock=lambda:0)
            self.assertEqual(summary["state"],"empty")
            self.assertEqual(summary["post_stop"]["predicate"],"owned-failed-terminal-predicate-passed")
            self.assertEqual(summary["post_stop"]["original_cgroup_state"],original)
            stop.assert_called_once();self.assertEqual(read.call_count,2)
            self.assertEqual(self.worker().terminal(owned),3)
            reservation=reserved.Witness.__new__(reserved.Witness)
            reservation.observe=Mock()
            with self.assertRaises(ValueError):reservation.complete(3,True,True,True)
            reservation.observe.assert_not_called()
        for original in ("populated","changed","unproved"):
            summary=reserved.cleanup_retained(deadline=15,readback=Mock(side_effect=[owned,owned]),
                authorize=Mock(),stop=Mock(),observe=Mock(side_effect=["empty","empty",original]),clock=lambda:0)
            self.assertEqual(summary["state"],"unproved")
            self.assertEqual(summary["post_stop"]["predicate"],"original-group-not-empty")
        summary=reserved.cleanup_retained(deadline=15,readback=Mock(side_effect=[owned,owned]),
            authorize=Mock(),stop=Mock(side_effect=OSError("unprinted")),observe=lambda:"empty",clock=lambda:0)
        self.assertEqual(summary["state"],"unproved")
        self.assertEqual(summary["stop"],"unresolved")

    def test_failed_terminal_cleanup_refuses_incomplete_changed_or_other_terminal_outcomes(self):
        owned=self.terminal(LoadState="loaded",ActiveState="failed",SubState="failed",
            ExecMainStatus="3",Result="exit-code")
        changes=({"ExecMainCode":None},{"ExecMainCode":"2","Result":"signal"},
            {"Result":"timeout"},{"Result":"success"},{"ExecMainStatus":"0"},
            {"ExecMainStatus":False},{"ExecMainStatus":3},{"ExecMainStatus":"03"},
            {"ExecMainStatus":"256"},{"ExecMainStatus":"+3"},{"ExecMainStatus":"4"},
            {"ExecMainCode":True},{"LoadState":"not-found"},{"RemainAfterExit":"no"},
            {"ActiveState":"active"},{"SubState":"dead"},{"MainPID":"1234"},
            {"InvocationID":"b"*32},{"ExecMainPID":"5678"},{"Id":"foreign"})
        for bad in changes:
            with self.subTest(bad=bad):
                read=Mock(side_effect=[owned,{**owned,**bad}]);observe=Mock(return_value="empty")
                summary=reserved.cleanup_retained(deadline=15,readback=read,authorize=Mock(),
                    stop=Mock(),observe=observe,clock=lambda:0)
                self.assertEqual(summary["state"],"unproved")
                self.assertEqual(summary["post_stop"]["original_cgroup_state"],"not-observed")
                self.assertEqual(read.call_count,2);self.assertEqual(observe.call_count,2)
        # A later valid failed report cannot repair an unqualified original result.
        for bad in changes[:12]:
            summary=reserved.cleanup_retained(deadline=15,
                readback=Mock(side_effect=[{**owned,**bad},owned]),authorize=Mock(),stop=Mock(),
                observe=lambda:"empty",clock=lambda:0)
            self.assertEqual(summary["state"],"unproved")
        stop=Mock()
        summary=reserved.cleanup_retained(deadline=15,readback=Mock(return_value=owned),
            authorize=Mock(side_effect=ValueError("original ownership refused")),stop=stop,
            observe=lambda:"empty",clock=lambda:0)
        self.assertEqual(summary["ownership"],"refused");stop.assert_not_called()

    def test_failed_terminal_cleanup_requires_original_exited_worker_and_original_cutoff(self):
        witness=self.worker();witness.pidfd=42
        witness.entry=time.monotonic_ns();witness.deadline=witness.entry+1200*10**9
        witness.check_directory=Mock(return_value=True);witness.check_bounds=Mock()
        witness.pin=SimpleNamespace(path=Path("/sys/fs/cgroup/system.slice")/self.UNIT,
            observe=Mock(return_value="empty"))
        owned=self.terminal(LoadState="loaded",ActiveState="failed",SubState="failed",
            ExecMainStatus="3",Result="exit-code",ControlGroup="/system.slice/"+self.UNIT)
        with patch.object(reserved.poll,"select",return_value=([],[],[])):
            stop=Mock()
            summary=reserved.cleanup_retained(deadline=15,readback=Mock(return_value=owned),
                authorize=witness.authorize_cleanup,stop=stop,observe=lambda:"empty",clock=lambda:0)
            self.assertEqual(summary["ownership"],"refused");stop.assert_not_called()
        now=[0];reads=[]
        def read(timeout,deadline):
            reads.append((timeout,deadline))
            if len(reads)==2:now[0]=deadline
            return owned
        observe=Mock(return_value="empty")
        summary=reserved.cleanup_retained(deadline=15,readback=read,authorize=Mock(),stop=Mock(),
            observe=observe,clock=lambda:now[0])
        self.assertEqual(summary["state"],"deadline-exhausted")
        self.assertEqual(summary["post_stop"]["predicate"],"original-deadline-exhausted")
        self.assertEqual(observe.call_count,2);self.assertEqual(len(reads),2)

    def test_post_stop_projection_is_closed_bounded_and_never_reflects_metadata(self):
        identity=(self.UNIT,"a"*32,"1234")
        raw={"Id":"unsupported-unit-value","InvocationID":"unsupported-invocation-value",
            "ExecMainPID":"unsupported-pid-value","MainPID":"99999999999999999999999",
            "LoadState":"unsupported-load-value","ActiveState":"unsupported-active-value",
            "SubState":"unsupported-sub-value","Environment":"unsupported-environment-value"}
        value=reserved.post_stop_projection(raw,identity)
        self.assertEqual(set(value),{"schema_version","scope","LoadState","ActiveState","SubState",
            "MainPID","Id_matches","InvocationID_matches","ExecMainPID_matches",
            "original_cgroup_state","predicate"})
        for name in ("Id_matches","InvocationID_matches","ExecMainPID_matches"):
            self.assertIs(type(value[name]),bool);self.assertIs(value[name],False)
        for name in ("LoadState","ActiveState","SubState","MainPID"):
            self.assertEqual(value[name],"other")
        encoded=json.dumps(value,sort_keys=True)
        self.assertLess(len(encoded),1024)
        self.assertNotIn("unsupported",encoded)
        for pid in (None,False,0,[],{}):
            value=reserved.post_stop_projection({**raw,"MainPID":pid},identity)
            self.assertIn(value["MainPID"],("missing","other"))

class ReservedFailureDiagnosticModels(unittest.TestCase):
    def worker(self):
        witness = reserved.WorkloadWitness.__new__(reserved.WorkloadWitness)
        witness.entry, witness.deadline = 100 * 10**9, 1300 * 10**9
        witness.directory, witness.pidfd, witness.pid, witness.worker = 10, 11, 1234, (1, 2, 3)
        witness.bounds = {}
        witness.check_directory = Mock(return_value=True)
        witness.check_bounds = Mock(return_value={})
        witness.check_process = Mock()
        witness.read = Mock(return_value="1234")
        witness.pin = SimpleNamespace(observe=Mock(return_value="populated"))
        return witness

    def test_missing_proc_without_ready_original_pidfd_remains_fail_closed_with_exact_phase(self):
        witness = self.worker()
        with patch.object(reserved.time, "monotonic_ns", return_value=200 * 10**9), \
                patch.object(reserved.poll, "select", return_value=([], [], [])) as readiness, \
                patch.object(reserved, "process", side_effect=FileNotFoundError(2, "private path")) as proc:
            with self.assertRaises(reserved.ReservationOSError) as rejected:
                witness.alive()  # Real helper; one original-pidfd recheck still refuses.
        self.assertEqual(reserved.diagnostic_projection(rejected.exception),
            {"phase": "worker-proc-identity", "errno": "ENOENT"})
        self.assertEqual(readiness.call_count, 2)
        proc.assert_called_once_with(1234)
        witness.check_process.assert_not_called()
        witness.pin.observe.assert_not_called()
        self.assertNotIn("private", str(rejected.exception))
        self.assertIn("reserved_phase=worker-proc-identity; reserved_errno=ENOENT",
            guard.rejection_diagnostic(rejected.exception, "private-epoch"))

    def test_real_security_helper_tags_oserror_without_reading_other_proc_fields(self):
        witness = self.worker()
        with patch.object(reserved.os, "open", side_effect=OSError(13, "private proc")) as opened:
            with self.assertRaises(reserved.ReservationOSError) as rejected:
                reserved.WorkloadWitness.check_process(witness)
        self.assertEqual(opened.call_count, 1)
        self.assertEqual(reserved.diagnostic_projection(rejected.exception),
            {"phase": "worker-proc-security", "errno": "EACCES"})

    def test_real_monitor_tags_terminal_readback_and_never_invents_terminal_success(self):
        witness = self.worker()
        witness.alive = Mock(return_value=False)
        terminal = Mock(side_effect=OSError(5, "private unit"))
        with self.assertRaises(reserved.ReservationOSError) as rejected:
            reserved.monitor(reserved.PROFILE, witness, terminal, 1, lambda: None, clock=lambda: 0)
        self.assertEqual(reserved.diagnostic_projection(rejected.exception),
            {"phase": "terminal-manager-readback", "errno": "EIO"})
        self.assertEqual(witness.alive.call_count, 1)
        terminal.assert_called_once_with()

    def test_real_resident_helper_and_completion_keep_first_failure_and_closed_projection(self):
        witness = reserved.Witness.__new__(reserved.Witness)
        witness.entry, witness.deadline, witness.directory = 100 * 10**9, 1300 * 10**9, 10
        witness.check_directory = Mock(side_effect=OSError(9, "private directory"))
        with patch.object(reserved.time, "monotonic_ns", return_value=200 * 10**9):
            with self.assertRaises(reserved.ReservationOSError) as rejected:
                witness.complete(0, True, True, True)
        self.assertEqual(reserved.diagnostic_projection(rejected.exception),
            {"phase": "resident-sample", "errno": "EBADF"})
        self.assertIsNone(reserved.diagnostic_projection(OSError(2, "private arbitrary")))
        error = reserved.ReservationOSError("private phase", 123456)
        self.assertEqual(reserved.diagnostic_projection(error), {"phase": "unknown", "errno": "other"})
        self.assertEqual(reserved.diagnostic_projection(reserved.ReservationValueError("terminal-result")),
            {"phase": "terminal-result", "errno": "none"})
        self.assertNotIn("private", json.dumps(reserved.diagnostic_projection(error)))

class VerifiedProcExitModels(unittest.TestCase):
    UNIT = ProofWorkerModels.UNIT
    def worker(self):
        witness = ReservedFailureDiagnosticModels.worker(self)
        witness.unit = ProofWorkerModels.UNIT
        witness.invocation = "a" * 32
        return witness

    def test_ready_original_pidfd_returns_only_exit_readiness_after_anchored_custody(self):
        witness = self.worker()
        with patch.object(reserved.time, "monotonic_ns", return_value=200 * 10**9), \
                patch.object(reserved.poll, "select", side_effect=[([], [], []), ([11], [], [])]) as readiness, \
                patch.object(reserved, "process", side_effect=FileNotFoundError(2, "private")) as proc:
            self.assertFalse(witness.alive())
        self.assertEqual(readiness.call_args_list, [unittest.mock.call([11], [], [], 0)] * 2)
        self.assertEqual(witness.check_directory.call_args_list,
            [unittest.mock.call(False), unittest.mock.call(True), unittest.mock.call(True)])
        self.assertEqual(witness.check_bounds.call_count, 2)
        proc.assert_called_once_with(1234)
        witness.check_process.assert_not_called()
        witness.read.assert_not_called()

    def test_other_errno_phase_or_unfrozen_caps_never_take_exit_path(self):
        cases = (OSError(5, "private"), reserved.ReservationOSError("worker-cgroup-bounds", 2))
        for error in cases:
            witness = self.worker()
            with patch.object(reserved.time, "monotonic_ns", return_value=200 * 10**9), \
                    patch.object(reserved.poll, "select", return_value=([], [], [])) as readiness, \
                    patch.object(reserved, "process", side_effect=error):
                with self.assertRaises(reserved.ReservationOSError): witness.alive()
            self.assertEqual(readiness.call_count, 1)
            self.assertEqual(witness.check_directory.call_count, 1)
        witness = self.worker()
        witness.bounds = None
        with patch.object(reserved.time, "monotonic_ns", return_value=200 * 10**9), \
                patch.object(reserved.poll, "select", return_value=([], [], [])) as readiness, \
                patch.object(reserved, "process", side_effect=FileNotFoundError(2, "private")):
            with self.assertRaises(reserved.ReservationOSError): witness.alive()
        self.assertEqual(readiness.call_count, 1)

    def test_process_identity_mismatch_never_rechecks_pidfd(self):
        witness = self.worker()
        with patch.object(reserved.time, "monotonic_ns", return_value=200 * 10**9), \
                patch.object(reserved.poll, "select", return_value=([], [], [])) as readiness, \
                patch.object(reserved, "process", return_value=(999, 2, 3)):
            with self.assertRaises(reserved.ReservationValueError): witness.alive()
        self.assertEqual(readiness.call_count, 1)

    def test_ordinary_ready_path_has_no_extra_poll_or_proc_read(self):
        witness = self.worker()
        with patch.object(reserved.time, "monotonic_ns", return_value=200 * 10**9), \
                patch.object(reserved.poll, "select", return_value=([11], [], [])) as readiness, \
                patch.object(reserved, "process", side_effect=AssertionError("unexpected proc read")) as proc:
            self.assertFalse(witness.alive())
        self.assertEqual(readiness.call_count, 1)
        self.assertEqual(witness.check_bounds.call_count, 1)
        self.assertEqual(witness.check_directory.call_count, 2)
        proc.assert_not_called()

    def test_ready_exit_does_not_tolerate_custody_or_actual_cap_drift(self):
        witness = self.worker()
        witness.check_directory.side_effect = [True, ValueError("drift")]
        with patch.object(reserved.time, "monotonic_ns", return_value=200 * 10**9), \
                patch.object(reserved.poll, "select", side_effect=[([], [], []), ([11], [], [])]), \
                patch.object(reserved, "process", side_effect=FileNotFoundError(2, "private")):
            with self.assertRaises(reserved.ReservationValueError): witness.alive()
        witness = self.worker()
        values = {"memory.max": str(reserved.MEMORY), "memory.swap.max": "0",
            "pids.max": str(reserved.TASKS), "cpu.max": "190000 100000", "memory.oom.group": "1"}
        witness.bounds = dict(values)
        reads = []
        def read(name):
            reads.append(name)
            return str(reserved.MEMORY + 1) if name == "memory.max" and len(reads) > 5 else values[name]
        witness.read = Mock(side_effect=read)
        witness.check_bounds = reserved.WorkloadWitness.check_bounds.__get__(witness)
        with patch.object(reserved.time, "monotonic_ns", return_value=200 * 10**9), \
                patch.object(reserved.poll, "select", side_effect=[([], [], []), ([11], [], [])]), \
                patch.object(reserved, "process", side_effect=FileNotFoundError(2, "private")):
            with self.assertRaises(reserved.ReservationValueError) as rejected: witness.alive()
        self.assertEqual(reserved.diagnostic_projection(rejected.exception)["phase"], "worker-cgroup-bounds")

    def test_real_monitor_still_requires_exact_terminal_manager_and_preserves_failed_exit(self):
        base = ProofWorkerModels.terminal(self)
        cases = (({}, 0), ({"Result": "exit-code"}, 125),
            ({"ActiveState": "failed", "SubState": "failed", "Result": "exit-code", "ExecMainStatus": "3"}, 3))
        for changes, expected in cases:
            witness = self.worker()
            query = Mock(return_value={**base, **changes})
            with patch.object(reserved.time, "monotonic_ns", return_value=200 * 10**9), \
                    patch.object(reserved.poll, "select", side_effect=[([], [], []), ([11], [], []), ([11], [], [])]), \
                    patch.object(reserved, "process", side_effect=FileNotFoundError(2, "private")):
                actual = reserved.monitor(reserved.PROFILE, witness, query, 1, lambda: None, clock=lambda: 0)
            self.assertEqual(actual, expected)
            query.assert_called_once_with()
        for changes in ({"Id": "wrong"}, {"InvocationID": "b" * 32}, {"ExecMainPID": "9999"}):
            witness = self.worker()
            with patch.object(reserved.time, "monotonic_ns", return_value=200 * 10**9), \
                    patch.object(reserved.poll, "select", side_effect=[([], [], []), ([11], [], []), ([11], [], [])]), \
                    patch.object(reserved, "process", side_effect=FileNotFoundError(2, "private")):
                with self.assertRaises(reserved.ReservationValueError):
                    reserved.monitor(reserved.PROFILE, witness, lambda: {**base, **changes}, 1,
                        lambda: None, clock=lambda: 0)

class TerminalConfirmedProcExitModels(unittest.TestCase):
    UNIT = ProofWorkerModels.UNIT
    worker = VerifiedProcExitModels.worker

    def run_missing(self, actual, readiness, *, readback_error=None, clock=None):
        witness = self.worker()
        query = Mock(side_effect=readback_error) if readback_error else Mock(return_value=actual)
        with patch.object(reserved.time, "monotonic_ns", return_value=200 * 10**9), \
                patch.object(reserved.poll, "select", side_effect=readiness) as polled, \
                patch.object(reserved, "process", side_effect=FileNotFoundError(2, "private proc")):
            try:
                result = reserved.monitor(reserved.PROFILE, witness, query, 1, lambda: None,
                    clock=clock or (lambda: 0), pause=Mock(side_effect=AssertionError("unexpected wait")))
            except (reserved.ReservationOSError, reserved.ReservationValueError) as error:
                result = error
        return witness, query, polled, result

    def test_ready_after_one_terminal_query_uses_original_manager_exit_and_frozen_custody(self):
        base = ProofWorkerModels.terminal(self)
        for changes, expected in (({}, 0),
                ({"ActiveState": "failed", "SubState": "failed", "Result": "exit-code", "ExecMainStatus": "3"}, 3),
                ({"ActiveState": "failed", "SubState": "failed", "Result": "exit-code", "ExecMainStatus": "125"}, 125)):
            witness, query, polled, result = self.run_missing({**base, **changes},
                [([], [], []), ([], [], []), ([11], [], [])])
            self.assertEqual(result, expected)
            self.assertEqual(witness.proc_exit_confirmation, "verified-terminal")
            self.assertFalse(witness.proc_exit_pending)
            query.assert_called_once_with()
            self.assertEqual(polled.call_count, 3)
            self.assertEqual(witness.check_bounds.call_count, 2)
            witness.check_process.assert_not_called()
            witness.read.assert_not_called()

    def test_active_wrong_identity_and_false_success_refuse_before_third_pidfd_poll(self):
        base = ProofWorkerModels.terminal(self)
        for changes in ({"ActiveState": "active", "SubState": "running", "MainPID": "1234"},
                {"Id": "wrong"}, {"InvocationID": "b" * 32}, {"ExecMainPID": "9999"},
                {"Result": "exit-code"}, {"ActiveState": "activating"}):
            witness, query, polled, result = self.run_missing({**base, **changes},
                [([], [], []), ([], [], [])])
            self.assertIsInstance(result, reserved.ReservationValueError)
            self.assertEqual(reserved.diagnostic_projection(result)["proc_exit_confirmation"], "manager-terminal-refused")
            self.assertEqual(witness.proc_exit_confirmation, "manager-terminal-refused")
            query.assert_called_once_with()
            self.assertEqual(polled.call_count, 2)

    def test_notready_query_error_deadline_and_other_proc_errors_still_refuse(self):
        base = ProofWorkerModels.terminal(self)
        witness, query, polled, result = self.run_missing(base,
            [([], [], []), ([], [], []), ([], [], [])])
        self.assertIsInstance(result, reserved.ReservationValueError)
        self.assertEqual(reserved.diagnostic_projection(result), {"phase": "proc-exit-readiness", "errno": "none",
            "proc_exit_confirmation": "pidfd-not-ready"})
        self.assertEqual(polled.call_count, 3)
        query.assert_called_once_with()
        witness, query, polled, result = self.run_missing(base, [([], [], []), ([], [], [])],
            readback_error=OSError(5, "private unit"))
        self.assertEqual(reserved.diagnostic_projection(result), {"phase": "terminal-manager-readback", "errno": "EIO",
            "proc_exit_confirmation": "manager-query-refused"})
        self.assertEqual(polled.call_count, 2)
        times = iter((0, 0, 0, 1))  # loop, iteration, pre-query, post-query original cutoff.
        witness, query, polled, result = self.run_missing(base, [([], [], []), ([], [], [])],
            clock=lambda: next(times))
        self.assertEqual(result, 124)
        self.assertEqual(witness.proc_exit_confirmation, "deadline-refused")
        self.assertEqual(polled.call_count, 2)
        query.assert_called_once_with()
        for error in (OSError(13, "private"), reserved.ReservationOSError("worker-cgroup-bounds", 2)):
            witness = self.worker()
            query = Mock(side_effect=AssertionError("unexpected manager read"))
            with patch.object(reserved.time, "monotonic_ns", return_value=200 * 10**9), \
                    patch.object(reserved.poll, "select", return_value=([], [], [])) as polled, \
                    patch.object(reserved, "process", side_effect=error):
                with self.assertRaises(reserved.ReservationOSError):
                    reserved.monitor(reserved.PROFILE, witness, query, 1, lambda: None, clock=lambda: 0)
            self.assertEqual(polled.call_count, 1)
            query.assert_not_called()

    def test_ready_after_query_custody_drift_and_unconsumed_confirmation_refuse(self):
        witness = self.worker()
        witness.check_directory.side_effect = [True, ValueError("private drift")]
        query = Mock(return_value=ProofWorkerModels.terminal(self))
        with patch.object(reserved.time, "monotonic_ns", return_value=200 * 10**9), \
                patch.object(reserved.poll, "select", side_effect=[([], [], []), ([], [], []), ([11], [], [])]), \
                patch.object(reserved, "process", side_effect=FileNotFoundError(2, "private")):
            with self.assertRaises(reserved.ReservationValueError) as rejected:
                reserved.monitor(reserved.PROFILE, witness, query, 1, lambda: None, clock=lambda: 0)
        self.assertEqual(reserved.diagnostic_projection(rejected.exception)["proc_exit_confirmation"], "custody-refused")
        self.assertNotIn("private", guard.rejection_diagnostic(rejected.exception, "private-epoch"))
        self.assertIn("proc_exit_confirmation=custody-refused", guard.rejection_diagnostic(rejected.exception, "private-epoch"))
        query.reset_mock()
        with self.assertRaises(reserved.ReservationValueError): witness.confirm_proc_exit(query, 1, lambda: 0)
        query.assert_not_called()
        witness = self.worker()
        caps = {"memory.max": str(reserved.MEMORY), "memory.swap.max": "0",
            "pids.max": str(reserved.TASKS), "cpu.max": "190000 100000", "memory.oom.group": "1"}
        witness.bounds = dict(caps)
        reads = []
        def read(name):
            reads.append(name)
            return "481" if name == "pids.max" and len(reads) > 5 else caps[name]
        witness.read = Mock(side_effect=read)
        witness.check_bounds = reserved.WorkloadWitness.check_bounds.__get__(witness)
        query = Mock(return_value=ProofWorkerModels.terminal(self))
        with patch.object(reserved.time, "monotonic_ns", return_value=200 * 10**9), \
                patch.object(reserved.poll, "select", side_effect=[([], [], []), ([], [], []), ([11], [], [])]), \
                patch.object(reserved, "process", side_effect=FileNotFoundError(2, "private")):
            with self.assertRaises(reserved.ReservationValueError) as rejected:
                reserved.monitor(reserved.PROFILE, witness, query, 1, lambda: None, clock=lambda: 0)
        self.assertEqual(reserved.diagnostic_projection(rejected.exception),
            {"phase": "worker-cgroup-bounds", "errno": "none", "proc_exit_confirmation": "custody-refused"})
        query.assert_called_once_with()

# Keep the actual production walker captured before per-constructor injection.
reserved_open=reserved.open_chain

if __name__=="__main__":
    unittest.main()
