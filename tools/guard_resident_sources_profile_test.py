"""Provider-free models of the fixed installed-launch boundary, not live UI proof."""
import copy
import os
from pathlib import Path
import subprocess
import time
import tempfile
import stat
from types import SimpleNamespace
import unittest
from unittest import mock
import guard_resident_sources_profile as source
import guard_resident_dispatch as dispatch
import guard_resident_observation as resident
import execution_guard

EPOCH="11111111-1111-4111-8111-111111111111"
HOME=Path("/home/model-user")

def manifest():
    paths=resident.fixed_paths(HOME)
    return {"schema_version":1,"scope":source.SCOPE,"action_epoch":EPOCH,
        "resident":{"ownership":"omux-installation",**{key:str(value) for key,value in paths.items()},
            "archive_sha256":"1"*64,"executable_sha256":"2"*64,
            "executable_path":str(paths["prefix"]/"lib/omux/libexec/omuxd.bin"),"pid":42,"start_ticks":17,
            "installation":{"archive":{"path":str(resident.PUBLIC_ROOTS[0]/EPOCH/"output-base/execroot/_main/bazel-out/k8-fastbuild/bin/delivery/default_instance_archive.tar.gz"),"sha256":"1"*64,"bytes":42},
                "manifest_sha256":"3"*64,"qualification":{"path":str(resident.PUBLIC_ROOTS[0]/EPOCH/"receipt.json"),"sha256":"4"*64,"bytes":42},
                "source_commit":"5"*40,"graph_sha256":"6"*64}},
        "seat":{"host":{"machineIdSha256":"7"*64,"bootIdSha256":"8"*64,"uid":os.getuid()},
            "seat":{"sessionId":"1","seatId":"seat0","uid":os.getuid()},
            "operatorTerminal":"/dev/tty1","sourceSocket":"/run/user/"+str(os.getuid())+"/wayland-0",
            "compositorSnapshot":{"device":1,"inode":2,"uid":os.getuid(),"mode":0o600,"pid":43,"start_ticks":18}},
        "component":{"component_sha256":"9"*64,"install_sha256":"a"*64,"producer_sha256":"b"*64},
        "host_systemctl":None}

def args(**changes):
    value=dict(profile=source.PROFILE,manager="system",arguments=["run",source.LABEL],
        resident_manifest=Path("/srv/model-input/input.json"),resident_epoch=EPOCH,
        resident_producer_sha256="1"*64,resident_observer_sha256="2"*64,
        resident_runtime_selection=None,resident_runtime_sha256=None,resident_runtime_bytes=None,resident_native_version=None,
        reuse_owned_cache=False,source_commit="3"*40,source_dirty="false",repository_cache=None,nixpkgs_source=None)
    value.update(changes)
    return SimpleNamespace(**value)

class Child:
    pid=4242
    def __init__(self, status=0):self.returncode=None;self.status=status
    def terminate(self):self.terminated=True
    def kill(self):self.killed=True
    def poll(self):return self.returncode
    def wait(self,timeout):
        if timeout<=0:raise AssertionError("renewed/expired timeout")
        self.returncode=self.status
        return self.returncode

class SourcesTest(unittest.TestCase):
    def test_exact_closed_manifest_reuses_real_default_install_schema(self):
        value=manifest()
        self.assertIs(source.manifest_schema(value,HOME,EPOCH),value)
        self.assertNotIn("native_context",value)
        self.assertEqual(value["resident"]["runtime_state"],str(HOME/".local/state/omux"))

    def test_manifest_rejects_other_purpose_caller_paths_missing_or_typed_roles(self):
        for mutate in (lambda v:v.update(scope="resident-continuity"),
                       lambda v:v.update(native_context={}),
                       lambda v:v["resident"].update(ownership="home-manager"),
                       lambda v:v["resident"].update(prefix="/tmp/elsewhere"),
                       lambda v:v["seat"]["host"].update(uid=True),
                       lambda v:v["seat"].update(operatorTerminal="/tmp/tty"),
                       lambda v:v["component"].update(extra="0"*64),
                       lambda v:v.update(host_systemctl={"sha256":"0"*64,"bytes":True})):
            value=manifest();mutate(value)
            with self.subTest(value=value),self.assertRaises(ValueError):source.manifest_schema(value,HOME,EPOCH)

    def test_exact_dispatch_no_generic_run_or_native_authority(self):
        value=args()
        self.assertIs(dispatch.select(value,value.arguments),source)
        self.assertEqual(source.finite(value.arguments,"system",value.resident_manifest,False),
            {"PrivateNetwork":"no","ProtectSystem":"strict","PrivateTmp":"yes","PrivatePIDs":"no"})
        for changes in ({"manager":"user"},{"reuse_owned_cache":True},{"resident_runtime_selection":Path("/srv/retired")},
                        {"codex_login_manifest":Path("/srv/private/input.json")},{"source_dirty":"true"},{"resident_epoch":"not-epoch"}):
            value=args(**changes)
            with self.subTest(changes=changes),self.assertRaises(ValueError):dispatch.select(value,value.arguments)
        for arguments in (["run","//clients/linux:control"],["run",source.LABEL,"--socket","/tmp/other"],
                          ["test",source.LABEL],["run","//delivery:native_account_login"]):
            value=args(arguments=arguments)
            with self.subTest(arguments=arguments),self.assertRaises(ValueError):dispatch.select(value,arguments)

    def test_actual_workload_pids_diagnostic_matches_sources_complementary_limit(self):
        observation=execution_guard.workload_pids_observation(source,source.PROFILE)
        self.assertEqual(observation.expected_limit,480)
        self.assertEqual(execution_guard.workload_pids_observation(source,"standard").expected_limit,512)
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            for name,value in (("pids.current","480\n"),("pids.max","480\n"),("pids.events","max 0\n")):
                (root/name).write_text(value)
            pin=execution_guard.CgroupPin(root)
            try:
                observation.sample(pin,"baseline")
                self.assertEqual(observation.baseline["limit"],480)
                self.assertTrue(observation.observed_at_or_over_verified_limit)
            finally:pin.close()

    def test_real_builder_keeps_exact_offline_input_pair_and_new_profile(self):
        admission=SimpleNamespace(manifest=Path("/srv/model-input/input.json"),facts={"scope":source.PROFILE},
            environment=lambda:{"OMUX_RESIDENT_SOURCES_DEADLINE_NS":"123"})
        run=resident.PUBLIC_ROOTS[0]/EPOCH
        for cache,nixpkgs in ((None,None),(dispatch.REPOSITORY_CACHE,dispatch.NIXPKGS)):
            command=dispatch.command(execution_guard.bazel_command,"/nix/store/model-bazel/bin/bazel",
                run,["run",source.LABEL],admission,source_commit="1"*40,source_dirty="false",
                repository_cache=cache,nixpkgs_source=nixpkgs)
            self.assertIn("run",command)
            self.assertEqual(command.count(source.LABEL),1)
            self.assertIn("--repository_disable_download",command)
            self.assertNotIn("--disable_download",command)
            self.assertIn("--spawn_strategy=linux-sandbox",command)
            self.assertEqual("--repo_contents_cache=" in command,cache is not None)
            self.assertIn("--run_env=OMUX_RESIDENT_SOURCES_DEADLINE_NS=123",command)
        with self.assertRaises(ValueError):
            dispatch.command(execution_guard.bazel_command,"/nix/store/model-bazel/bin/bazel",run,
                ["run",source.LABEL],admission,source_commit="1"*40,source_dirty="false",repository_cache=dispatch.REPOSITORY_CACHE)

    def test_effective_leaf_bind_is_suffix_free_only_and_component_all_readonly(self):
        admission=source.Admission.__new__(source.Admission)
        admission.run=resident.PUBLIC_ROOTS[0]/EPOCH
        admission.bindings=lambda:["/srv/in:/omux-resident-sources-inputs",
            "/run/user/1000/bus:/run/user/1000/bus:norbind",
            "/home/user/component:/home/user/component"]
        admission.writable_binding=lambda:"/home/user/source:/home/user/source"
        actual={"BindReadOnlyPaths":"/srv/in:/omux-resident-sources-inputs:rbind /run/user/1000/bus:/run/user/1000/bus /home/user/component:/home/user/component:rbind",
                "BindPaths":"/home/user/source:/home/user/source:rbind "+str(admission.run)+":"+str(admission.run)+":rbind"}
        admission.verify_bindings(actual,admission.run)
        for old,new in (("/run/user/1000/bus:/run/user/1000/bus","/run/user/1000/bus:/run/user/1000/bus:rbind"),
                        ("/srv/in:/omux-resident-sources-inputs:rbind","/srv/in:/omux-resident-sources-inputs"),
                        ("/home/user/component:/home/user/component:rbind","/home/user/component:/home/user/component")):
            bad=dict(actual);bad["BindReadOnlyPaths"]=bad["BindReadOnlyPaths"].replace(old,new)
            with self.assertRaises(ValueError):admission.verify_bindings(bad,admission.run)
        bad=dict(actual);bad["BindPaths"]+=" /home/user/component:/home/user/component:rbind"
        with self.assertRaises(ValueError):admission.verify_bindings(bad,admission.run)

    def context(self):
        return SimpleNamespace(home=HOME,launcher=HOME/".local/share/omux/bin/omux-control",
            endpoint=Path(source.DESTINATION)/"wayland.sock",work_deadline=time.monotonic_ns()+10**9,
            deadline=time.monotonic_ns()+31*10**9,recheck=mock.Mock())

    def test_launch_uses_packaged_normal_entry_no_automation_or_output(self):
        context=self.context();child=Child()
        popen=mock.Mock(return_value=child)
        result=source.launch(context,popen)
        argv=popen.call_args.args[0];kw=popen.call_args.kwargs
        self.assertEqual(argv,[str(context.launcher)])
        self.assertEqual((kw["stdin"],kw["stdout"],kw["stderr"]),(subprocess.DEVNULL,)*3)
        self.assertTrue(kw["start_new_session"])
        self.assertEqual(kw["env"],source.gui_environment(HOME,context.endpoint))
        self.assertEqual(result,source.launch_projection(0))
        self.assertFalse(result["enrollment_verified"])
        self.assertFalse(result["usable_grant_verified"])
        self.assertGreaterEqual(context.recheck.call_count,2)

    def test_gui_environment_strips_auth_remote_manager_native_and_loader_selectors(self):
        with mock.patch.dict(os.environ,{"CODEX_HOME":"/private","OMUX_SOCKET":"/private/sock",
              "SYSTEMD_BUS_ADDRESS":"tcp:remote","LD_PRELOAD":"/private","SSH_AUTH_SOCK":"/private/agent","HTTPS_PROXY":"remote"}):
            env=source.gui_environment(HOME,Path("/srv/input/wayland.sock"))
        self.assertFalse(set(env)&{"CODEX_HOME","OMUX_SOCKET","SYSTEMD_BUS_ADDRESS","SYSTEMD_HOST","SYSTEMD_MACHINE",
            "DBUS_SYSTEM_BUS_ADDRESS","LD_PRELOAD","LD_LIBRARY_PATH","SSH_AUTH_SOCK","HTTPS_PROXY"})
        self.assertEqual(env["XDG_STATE_HOME"],str(HOME/".local/state"))
        self.assertEqual(env["OMUX_INSTANCE"],"default")
        self.assertEqual(env["QT_QPA_PLATFORM"],"wayland")

    def test_expired_original_work_clock_never_constructs_child(self):
        context=self.context();context.work_deadline=time.monotonic_ns()-1
        popen=mock.Mock()
        with self.assertRaises(ValueError):source.launch(context,popen)
        popen.assert_not_called()

    def test_post_constructor_custody_failure_still_terminates_and_reaps_owned_child(self):
        context=self.context();context.recheck.side_effect=[None,ValueError("custody-lost")]
        child=Child();popen=mock.Mock(return_value=child)
        with self.assertRaises(ValueError):source.launch(context,popen)
        self.assertTrue(child.terminated)
        self.assertEqual(child.returncode,0)

    def test_nonzero_controls_exit_does_not_publish_success(self):
        with self.assertRaises(ValueError):source.launch(self.context(),mock.Mock(return_value=Child(7)))

    def test_guard_completion_refuses_before_collecting_for_unclean_or_wrong_producer(self):
        admission=source.Admission.__new__(source.Admission)
        admission.action_epoch=EPOCH
        admission.context={"producer_source_sha256":"1"*64}
        for status,cleaned,epoch,producer in ((True,True,EPOCH,"1"*64),(0,False,EPOCH,"1"*64),
                                            (0,True,EPOCH,"2"*64),(0,True,"other","1"*64)):
            with self.assertRaises(ValueError):admission.completed(status,cleaned,epoch,producer,"3"*64)
            self.assertFalse(getattr(admission,"collecting",False))

    def test_cleanup_fault_does_not_skip_later_owned_resources(self):
        first,second=mock.Mock(),mock.Mock()
        second.close.side_effect=OSError("close-failed")
        with self.assertRaises(OSError):source.close_items((first,second))
        first.close.assert_called_once();second.close.assert_called_once()

    def test_reused_metadata_close_fault_detaches_and_closes_both_actual_descriptors(self):
        value=resident.PinnedMetadata.__new__(resident.PinnedMetadata)
        value.fd,value.parent=100,101
        def close(fd):
            if fd==101:raise OSError("held-close-fault")
        with mock.patch.object(resident.os,"close",side_effect=close) as closed, self.assertRaises(OSError):
            value.close()
        self.assertEqual([c.args[0] for c in closed.call_args_list],[101,100])
        self.assertIsNone(value.fd)
        self.assertIsNone(value.parent)

    def test_reused_installation_close_fault_still_releases_next_public_witness(self):
        value=resident.InstallationWitness.__new__(resident.InstallationWitness)
        first,second=mock.Mock(),mock.Mock()
        second.close.side_effect=OSError("held-close-fault")
        value.resources=[first,second]
        with self.assertRaises(OSError):value.close()
        self.assertEqual(value.resources,[])
        first.close.assert_called_once()
        second.close.assert_called_once()

    def test_expired_cleanup_still_signals_only_the_constructor_owned_child(self):
        context=self.context()
        context.deadline=time.monotonic_ns()-1
        context.recheck.side_effect=[None,ValueError("custody-lost")]
        child=Child()
        with self.assertRaises(ValueError):source.launch(context,mock.Mock(return_value=child))
        self.assertTrue(child.terminated)
        self.assertTrue(child.killed)
        self.assertIsNone(child.returncode)

    def test_parent_terminate_fault_still_kills_and_reaps_without_a_new_clock(self):
        child=Child()
        child.terminate=mock.Mock(side_effect=OSError("term-failed"))
        original=child.wait
        def wait(timeout):
            if not hasattr(child,"killed"):raise subprocess.TimeoutExpired("owned-controls",timeout)
            return original(timeout)
        child.wait=mock.Mock(side_effect=wait)
        with self.assertRaises(OSError):source.cleanup_child(child,time.monotonic_ns()+10**9)
        child.terminate.assert_called_once()
        self.assertTrue(child.killed)
        self.assertEqual(child.returncode,0)

    def test_parent_wait_fault_still_escalates_and_reaps_without_clearing_failure(self):
        child=Child()
        original=child.wait
        child.wait=mock.Mock(side_effect=[subprocess.TimeoutExpired("owned-controls",5),0])
        with self.assertRaises(subprocess.TimeoutExpired):source.cleanup_child(child,time.monotonic_ns()+10**9)
        self.assertTrue(child.terminated)
        self.assertTrue(child.killed)
        self.assertEqual(child.wait.call_count,2)
        self.assertTrue(all(0<c.kwargs["timeout"]<=1 for c in child.wait.call_args_list))

    def test_poll_fault_does_not_skip_owned_terminate_kill_and_reap(self):
        child=Child()
        child.poll=mock.Mock(side_effect=OSError("poll-failed"))
        child.wait=mock.Mock(return_value=0)
        with self.assertRaises(OSError):source.cleanup_child(child,time.monotonic_ns()+10**9)
        self.assertTrue(child.terminated)
        self.assertTrue(child.killed)
        self.assertEqual(child.wait.call_count,2)

    def test_component_absence_is_explicit_both_roles_and_cannot_adopt_partial_install(self):
        value=manifest()
        value["component"]=None
        self.assertIs(source.manifest_schema(value,HOME,EPOCH),value)
        witness=source.ComponentWitness.__new__(source.ComponentWitness)
        parent=SimpleNamespace(fd=100,recheck=mock.Mock())
        witness.deadline=time.monotonic_ns()+10**9
        witness.resources=[parent]
        witness.missing=[(parent,"omux-acquisition"),(parent,"codex")]
        witness.tree=witness.lease=None
        with mock.patch.object(source.os,"stat",side_effect=FileNotFoundError):witness.recheck()
        for failure in (PermissionError,lambda *args,**kwargs:SimpleNamespace(st_mode=0o700)):
            with mock.patch.object(source.os,"stat",side_effect=failure),self.assertRaises((PermissionError,ValueError)):
                witness.recheck()

    def test_already_exited_child_is_never_signalled_during_cleanup(self):
        child=Child()
        context=self.context()
        child.returncode=0
        source.launch(context,mock.Mock(return_value=child))
        self.assertFalse(hasattr(child,"terminated"))
        self.assertFalse(hasattr(child,"killed"))

    def test_closed_projection_refuses_numeric_booleans_and_extra_evidence(self):
        for key in source.launch_projection(0):
            value=source.launch_projection(0)
            value[key]=int(value[key])
            with self.subTest(key=key),self.assertRaises(ValueError):source.validate_projection(value)
        value=source.launch_projection(0)
        value["account_count"]=2
        with self.assertRaises(ValueError):source.validate_projection(value)
        self.assertIs(source.validate_projection(value:=source.launch_projection(0)),value)

    def test_base_state_parent_keeps_ancestor_custody_without_private_mode_override(self):
        value=source.SourceParent.__new__(source.SourceParent)
        base=HOME/".local/state"
        value.rows=[(base,100,"base"),(base/"omux-native-sources",101,"sources"),
            (base/"omux-native-sources/codex",102,"codex")]
        value.captures=[]
        with mock.patch.object(source.resident,"open_directory",side_effect=[200,201,202]) as opened, \
             mock.patch.object(source.os,"fstat",side_effect=["base","base","sources","sources","codex","codex"]), \
             mock.patch.object(source.resident,"stable",side_effect=lambda row:row),mock.patch.object(source.os,"close"):
            value.recheck()
        self.assertEqual([c.args[1] for c in opened.call_args_list],[False,True,True])

    def test_real_owned_0755_state_base_and_private_source_children(self):
        # Fixture boundary is a newly owned temporary root. Only its outside
        # ancestry is exempt; every child walk is nofollow and physically held.
        with tempfile.TemporaryDirectory() as name:
            root=Path(name)
            (root/".local/state").mkdir(parents=True,mode=0o755)
            os.chmod(root/".local",0o700)
            os.chmod(root/".local/state",0o755)
            root_id=resident.stable(root.stat(follow_symlinks=False))
            def fixture_open(path,private=False):
                self.assertEqual(resident.stable(root.stat(follow_symlinks=False)),root_id)
                parts=Path(path).relative_to(root).parts
                fd=os.open(root,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
                try:
                    for part in parts:
                        child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=fd)
                        os.close(fd);fd=child
                        info=os.fstat(fd)
                        self.assertEqual(info.st_uid,os.getuid())
                        self.assertFalse(stat.S_IMODE(info.st_mode)&0o022)
                    if private:self.assertEqual(stat.S_IMODE(os.fstat(fd).st_mode),0o700)
                    return fd
                except BaseException:os.close(fd);raise
            class Capture:
                def __init__(self,path,mode=None):
                    self.fd=fixture_open(path,mode==0o700)
                    self.path=Path(path)
                    self.mode=mode
                    self.fence=resident.stable(os.fstat(self.fd))
                def recheck(self):
                    fd=fixture_open(self.path,self.mode==0o700)
                    try:self.assert_same(fd)
                    finally:os.close(fd)
                def assert_same(self,fd):
                    if resident.stable(os.fstat(fd))!=self.fence or resident.stable(os.fstat(self.fd))!=self.fence:
                        raise ValueError("fixture-directory-replaced")
                def close(self):
                    fd,self.fd=self.fd,None
                    if fd is not None:os.close(fd)
            with mock.patch.object(source.component,"Directory",side_effect=Capture), \
                 mock.patch.object(source.resident,"open_directory",side_effect=fixture_open):
                value=source.SourceParent(root)
                try:
                    value.recheck()
                    self.assertEqual(stat.S_IMODE((root/".local/state").stat().st_mode),0o755)
                    self.assertEqual(stat.S_IMODE(value.path.stat().st_mode),0o700)
                    self.assertEqual(stat.S_IMODE(value.path.parent.stat().st_mode),0o700)
                finally:value.close()

    def test_parent_metadata_capture_is_rechecked_and_closes_on_refusal(self):
        value=source.SourceParent.__new__(source.SourceParent)
        first,second=mock.Mock(),mock.Mock()
        second.recheck.side_effect=ValueError("ancestor-replaced")
        value.captures=[first,second]
        value.rows=[]
        with self.assertRaises(ValueError):value.recheck()
        first.recheck.assert_called_once()
        second.recheck.assert_called_once()

    def test_ready_is_actual_protocol_custody_health_not_a_gui_claim(self):
        observer=mock.Mock()
        deadline=time.monotonic_ns()+10**9
        with mock.patch.object(source.continuity,"control_request",return_value={"protocol_version":2,
              "status":"ready","custody_available":True}) as request:
            source.healthy(observer,deadline)
        request.assert_called_once_with(observer,"system.health",{},deadline=deadline)
        for result in ({"protocol_version":2,"status":"vault_locked","custody_available":False},
                       {"protocol_version":True,"status":"ready","custody_available":True},
                       {"protocol_version":2,"status":"ready","custody_available":False}):
            with mock.patch.object(source.continuity,"control_request",return_value=result),self.assertRaises(ValueError):
                source.healthy(observer,deadline)

    def test_original_clock_bounds_runtime_inside_budget_and_keeps_reserve(self):
        admission=source.Admission.__new__(source.Admission)
        admission.deadline_ns=1200*10**9
        with mock.patch.object(source.time,"monotonic_ns",return_value=100*10**9):
            self.assertEqual(admission.runtime_seconds(),1070)
        with mock.patch.object(source.time,"monotonic_ns",return_value=1170*10**9):
            with self.assertRaises(ValueError):admission.runtime_seconds()

if __name__=="__main__":unittest.main()
