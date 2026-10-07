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

    def invoke(self,action,*,health_change=None,native_launch=False,changed_identity=False,unknown_state=False):
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
                (lifecycle.guard,"resolve_owned_unit_fragment",{"return_value":Path(value["service_path"])}),
                (lifecycle.resident,"process_identity",{"side_effect":process}),
                (lifecycle.resident,"cgroup_observation",{"return_value":(caps,(50,60))}),
                (lifecycle.guard,"socket_witness",{"return_value":peer}),
                (lifecycle.guard,"start_ticks",{"return_value":20}),
                (lifecycle.owned,"inactive_cgroup",{"return_value":{"unit_cgroup_absent":True}}),
                (lifecycle.os,"listdir",{"return_value":[]})):
                stack.enter_context(mock.patch.object(target,name,**options))
            try:
                return lifecycle.execute_existing(Path("/public/systemctl"),value,
                    {"HOME":str(home),"XDG_RUNTIME_DIR":"/omux-resident-inputs"},bounded,
                    lambda maximum=20:maximum,time.monotonic_ns()+120*10**9)
            finally:
                witness.close.assert_called_once_with()

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
