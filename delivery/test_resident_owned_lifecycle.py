"""Offline closed-role lifecycle sequence and refusal models; no live service claim."""
import copy
from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path
import stat
import time
import unittest
from unittest import mock
import resident_owned_lifecycle as lifecycle

class LifecycleContract(unittest.TestCase):
    def test_lightweight_start_delegates_exact_existing_contract_after_strict_permission_validation(self):
        import resident_owned_start
        home=Path("/home/jess")
        value={"schema_version":1,"ownership":"omux-installation","action":"start-existing","instance":"default",
            **{key:str(path) for key,path in lifecycle.guard.fixed_paths(home).items()},
            "native_context":None,"permissions":{"connect_source":False,"activate_service":True,"restart_daemon":False},
            "start":{"archive_path":"/public/qualified-archive"}}
        environment={"HOME":str(home),"XDG_RUNTIME_DIR":"/omux-resident-inputs"}
        bounded,remaining=mock.Mock(),mock.Mock()
        deadline=time.monotonic_ns()+120*10**9
        systemctl=Path("/declared/systemctl")
        result={"control_plane_ready":True,"vault_locked":True,"custody_available":False}
        with mock.patch.object(lifecycle.owned,"start_pins",return_value=value["start"]), \
                mock.patch.object(resident_owned_start,"execute_start",return_value=result) as delegate, \
                mock.patch.object(lifecycle.owned,"OwnedFirstStart",side_effect=AssertionError("no separate lifecycle witness")), \
                mock.patch.object(lifecycle.pack,"read_bundle",side_effect=AssertionError("only delegate verifies archive")):
            self.assertIs(lifecycle.execute_existing(systemctl,value,environment,bounded,remaining,deadline),result)
            delegate.assert_called_once_with(Path(value["start"]["archive_path"]),systemctl,value,
                environment,bounded,remaining,deadline)
            for key,field in (("connect_source",True),("activate_service",False),("restart_daemon",True)):
                bad=copy.deepcopy(value)
                bad["permissions"][key]=field
                with self.assertRaises(ValueError):
                    lifecycle.execute_existing(systemctl,bad,environment,bounded,remaining,deadline)
            self.assertEqual(delegate.call_count,1)
        bounded.assert_not_called()

    def invoke(self,action,*,health_change=None,native_launch=False,changed_identity=False,unknown_state=False,inactive_change=None,populated=False):
        home=Path("/home/jess")
        payload,manifest_raw=b"public software archive",b"public software manifest"
        selection={"archive_path":"/public/archive","archive_bytes":len(payload),
            "archive_sha256":hashlib.sha256(payload).hexdigest(),"manifest_sha256":hashlib.sha256(manifest_raw).hexdigest()}
        permissions={"connect_source":False,"activate_service":False,"restart_daemon":False}
        if action == "stop-idle-owned":
            permissions["stop_service"]=True
        value={"schema_version":1,"ownership":"omux-installation","action":action,"instance":"default",
            **{key:str(path) for key,path in lifecycle.guard.fixed_paths(home).items()},
            "native_context":None,"permissions":permissions,"start":selection}
        unit="ai.xoxd.omux.service"
        uid=os.getuid()
        group="/user.slice/user-"+str(uid)+".slice/user@"+str(uid)+".service/app.slice/"+unit
        executable=str(Path(value["prefix"])/"bin/omuxd")
        values={"LoadState":"loaded","ActiveState":"active","SubState":"running","MainPID":"10",
            "ControlGroup":group,"FragmentPath":value["service_path"],"UnitFileState":"enabled",
            "Slice":"app.slice","ExecStart":"{ path="+executable+" ; argv[]="+executable+" --state-dir "+value["runtime_state"]+" ; ignore_errors=no ; pid=10 ; status=0/0 }",
            "DropInPaths":"","NeedDaemonReload":"no","MemoryMax":"268435456","MemorySwapMax":"0",
            "TasksMax":"32","CPUQuotaPerSecUSec":"100ms"}
        if action == "observe-inactive":
            values.update(ActiveState="inactive",SubState="dead",MainPID="0",ControlGroup="")
            if inactive_change:
                values.update(inactive_change)
        health={"protocol_version":2,"status":"vault_locked","custody_available":False,"metadata_loaded":False,
            "provider_access":False,"live_handoff_proven":False,"recovery_action":"unlock_platform_vault_then_restart_daemon"}
        if health_change:
            health.update(health_change)
        handshake={"protocol_version":2,"service":"omuxd","channel":"control","custody_available":False,
            "capabilities":{"credential_free_control":True,"native_launch":native_launch,"live_handoff_proven":False}}
        self.commands=[]
        stopped=False
        inspected=False
        witness=mock.Mock()
        if unknown_state:
            witness.pristine.side_effect=[None,ValueError("closed synthetic changed-state refusal")]
        def bounded(command,environment,data=None):
            nonlocal stopped,inspected
            self.commands.append(command)
            if "show" in command:
                output=dict(values)
                if stopped:
                    output.update(ActiveState="inactive",SubState="dead",MainPID="0",ControlGroup="")
                elif changed_identity and inspected:
                    output["MainPID"]="11"
                return "\n".join(key+"="+field for key,field in output.items()).encode()
            if "stop" in command:
                self.assertEqual(action,"stop-idle-owned")
                self.assertEqual(command[-2:],["stop",unit])
                self.assertFalse(stopped)
                stopped=True
                return b""
            self.assertEqual(command[-3],"rpc")
            self.assertEqual(command[-1],"-")
            self.assertEqual(data,b"{}")
            self.assertIn(command[-2],("system.health","system.handshake"))
            inspected=True
            result=health if command[-2] == "system.health" else handshake
            return json.dumps({"jsonrpc":"2.0","id":1,"result":result}).encode()
        def process(pid):
            if stopped:
                raise FileNotFoundError()
            return (pid,20,30,40)
        peer=((1,2,stat.S_IFSOCK|0o600,uid,os.getgid()),10,20)
        caps={"memory.max":"268435456","memory.swap.max":"0","pids.max":"32","cpu.max":"10000 100000"}
        with ExitStack() as stack:
            for target,name,options in (
                (lifecycle.owned,"start_pins",{"return_value":selection}),
                (lifecycle.pack,"read_bundle",{"return_value":payload}),
                (lifecycle.pack,"verify_bundle",{"return_value":({}, {"release-manifest.json":manifest_raw})}),
                (lifecycle.owned,"OwnedFirstStart",{"return_value":witness}),
                (lifecycle.owned,"OwnedInactiveObservation",{"return_value":witness}),
                (lifecycle.guard,"resolve_owned_unit_fragment",{"return_value":Path(value["service_path"])}),
                (lifecycle.resident,"process_identity",{"side_effect":process}),
                (lifecycle.resident,"cgroup_observation",{"return_value":(caps,(50,60))}),
                (lifecycle.guard,"socket_witness",{"return_value":peer}),
                (lifecycle.guard,"start_ticks",{"return_value":20}),
                (lifecycle.owned,"inactive_cgroup",{"side_effect":ValueError("synthetic populated refusal")} if populated else {"return_value":{"unit_cgroup_absent":True}}),
                (lifecycle.os,"listdir",{"return_value":[]})):
                stack.enter_context(mock.patch.object(target,name,**options))
            try:
                return lifecycle.execute_existing(Path("/public/systemctl"),value,
                    {"HOME":str(home),"XDG_RUNTIME_DIR":"/omux-resident-inputs"},bounded,
                    lambda maximum=20:maximum,time.monotonic_ns()+120*10**9)
            finally:
                witness.close.assert_called_once_with()

    def test_main_reads_actual_private_manifest_and_dispatches_strict_inactive_action(self):
        # Real private_manifest/default validator and canonical guard schema.
        # Only the fixed namespace alias is mapped to a synthetic owned directory;
        # no host manager, software archive or daemon method is invoked.
        import io
        import tempfile
        from contextlib import redirect_stdout
        home=Path("/home/jess")
        epoch="11111111-1111-4111-8111-111111111111"
        receipts=home/".local/state/omux-execution-20261005"
        selection={"archive_path":str(receipts/epoch/"output-base"/lifecycle.owned.ARCHIVE_RELATIVE),
            "archive_sha256":"a"*64,"archive_bytes":1,"manifest_sha256":"b"*64,
            "qualification":{"path":str(receipts/epoch/"receipt.json"),"sha256":"c"*64,"bytes":1,
                             "source_commit":"d"*40,"graph_sha256":"e"*64}}
        value={"schema_version":1,"ownership":"omux-installation","action":"observe-inactive","instance":"default",
            **{key:str(path) for key,path in lifecycle.guard.fixed_paths(home).items()},
            "native_context":None,"permissions":{"connect_source":False,"activate_service":False,"restart_daemon":False},
            "start":selection}
        real_open,real_stat=os.open,os.stat
        with tempfile.TemporaryDirectory(dir=Path.home()) as temporary:
            namespace=Path(temporary)
            namespace.chmod(0o700)
            path=namespace/"input.json"
            path.write_text(json.dumps(value))
            path.chmod(0o600)
            information=namespace.stat()
            def opened(name,flags,*args,**kwargs):
                if str(name) == "omux-resident-inputs":
                    return real_open(namespace,flags)
                return real_open(name,flags,*args,**kwargs)
            def named(name,*args,**kwargs):
                if str(name) == "omux-resident-inputs":
                    return real_stat(namespace,follow_symlinks=False)
                return real_stat(name,*args,**kwargs)
            environment={"HOME":str(home),"OMUX_RESIDENT_ENROLLMENT_MANIFEST":lifecycle.resident.MANIFEST,
                "OMUX_RESIDENT_NAMESPACE_ID":str(information.st_dev)+":"+str(information.st_ino),
                "OMUX_RESIDENT_ORIGINAL_DEADLINE_NS":str(time.monotonic_ns()+120*10**9)}
            output={"service_active":False,"main_pid_zero":True,"unit_cgroup_empty":True}
            with mock.patch.dict(os.environ,environment,clear=True), \
                    mock.patch.object(lifecycle.sys,"argv",["resident-owned-lifecycle",lifecycle.__file__]), \
                    mock.patch.object(lifecycle.resident,"DEADLINE_NS",0), \
                    mock.patch.object(lifecycle.resident.os,"open",side_effect=opened), \
                    mock.patch.object(lifecycle.resident.os,"stat",side_effect=named), \
                    mock.patch.object(lifecycle,"execute_existing",return_value=output) as execute, \
                    redirect_stdout(io.StringIO()) as stdout:
                self.assertEqual(lifecycle.main(),0)
                self.assertEqual(json.loads(stdout.getvalue()),output)
                received=execute.call_args.args
                self.assertEqual(received[1],value)
                self.assertEqual(received[2]["HOME"],str(home))
                self.assertEqual(received[2]["DBUS_SESSION_BUS_ADDRESS"],"unix:path=/omux-resident-inputs/bus")
                self.assertEqual(received[-1],int(environment["OMUX_RESIDENT_ORIGINAL_DEADLINE_NS"]))
                execute.reset_mock()
                for changes in ({"action":"observe-inactive-extra"},{"native_context":{"application":"codex"}},
                                {"permissions":{**value["permissions"],"activate_service":True}},
                                {"start":{**selection,"qualification":{**selection["qualification"],"source_commit":"bad"}}}):
                    path.write_text(json.dumps({**value,**changes}))
                    with self.subTest(changes=changes),self.assertRaises(ValueError):
                        lifecycle.main()
                    execute.assert_not_called()

    def test_inactive_observation_uses_only_two_fixed_show_calls_and_no_health_or_mutation(self):
        result=self.invoke("observe-inactive")
        self.assertFalse(result["service_active"] or result["custody_available"]
            or result["service_mutation_requested"] or result["enrollment_verified"])
        self.assertTrue(result["main_pid_zero"] and result["unit_cgroup_absent"])
        self.assertEqual(len(self.commands),2)
        self.assertTrue(all(command[1:4] == ["--user","--quiet","show"]
            and command[-1] == "ai.xoxd.omux.service" for command in self.commands))

    def test_inactive_observation_refuses_active_nonzero_foreign_caps_or_populated_cgroup(self):
        for changes in ({"ActiveState":"active"},{"SubState":"running"},{"MainPID":"2"},
                {"MainPID":"00"},{"ControlGroup":"/foreign"},{"MemoryMax":"268435457"},
                {"TasksMax":"33"},{"CPUQuotaPerSecUSec":"101ms"},{"UnitFileState":"disabled"},
                {"DropInPaths":"/foreign.conf"},{"NeedDaemonReload":"yes"}):
            with self.subTest(changes=changes),self.assertRaises(ValueError):
                self.invoke("observe-inactive",inactive_change=changes)
            self.assertTrue(all("show" in command for command in self.commands))
        with self.assertRaises(ValueError):
            self.invoke("observe-inactive",populated=True)
        self.assertTrue(all("show" in command for command in self.commands))

    def test_observation_is_mutation_free_and_locked_custody_truth_is_preserved(self):
        result=self.invoke("observe-existing")
        self.assertTrue(result["service_active"] and result["vault_locked"])
        self.assertFalse(result["service_mutation_requested"] or result["custody_available"]
            or result["account_counts_observed"] or result["enrollment_verified"])
        self.assertTrue(all("show" in command or command[-3:] == ["rpc","system.health","-"] for command in self.commands))

    def test_explicit_locked_idle_stop_is_single_named_stop_and_confirms_process_exit(self):
        result=self.invoke("stop-idle-owned")
        self.assertTrue(result["owned_idle_stop_verified"] and result["custody_never_loaded"])
        self.assertFalse(result["service_active"] or result["custody_available"] or result["account_counts_observed"])
        self.assertEqual(sum("stop" in command for command in self.commands),1)
        self.assertTrue(all("show" in command or "stop" in command or command[-3] == "rpc" for command in self.commands))

    def test_stop_refuses_loaded_custody_provider_authority_native_admission_or_changed_process(self):
        for changes in ({"health_change":{"custody_available":True}},
                {"health_change":{"provider_access":True}}, {"health_change":{"metadata_loaded":True}},
                {"native_launch":True},{"changed_identity":True},{"unknown_state":True}):
            with self.subTest(changes=changes),self.assertRaises(ValueError):
                self.invoke("stop-idle-owned",**changes)
            self.assertFalse(any("stop" in command for command in self.commands))

if __name__ == "__main__":
    unittest.main()
