"""Synthetic kernel files + real own pidfd; no installed/runtime qualification."""
from contextlib import ExitStack
import copy
import os
from pathlib import Path
import stat
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import patch
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
        self.assertFalse(reserved.request(self.args("standard"),["test","//:docs_check"]))
        for profile,args in ((reserved.PROFILE,["test",reserved.LABEL,"//:docs_check"]),
            (reserved.PROFILE,["run",reserved.LABEL]),
            (reserved.MODEL_PROFILE,["test",reserved.LABEL]),
            (reserved.MODEL_PROFILE,list(reversed(reserved.MODELS)))):
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

if __name__=="__main__":
    unittest.main()
