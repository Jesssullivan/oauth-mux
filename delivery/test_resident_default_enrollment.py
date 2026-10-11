"""Isolated daemon-default enrollment predicates; no vault/profile/provider IO."""
import copy
import json
import os
import stat
import unittest
from contextlib import ExitStack
from types import SimpleNamespace
from unittest import mock
import resident_default_enrollment as default
import resident_existing_enrollment as entry

SOURCE="a"*64
ACCOUNT="b"*64
GRANT="c"*64

def manifest():
    home=default.Path("/home/jess")
    return {"schema_version":1,"ownership":"omux-installation","action":"enroll-default-existing","instance":"default",
        **{key:str(path) for key,path in default.guard.fixed_paths(home).items()},"native_context":None,
        "permissions":{"connect_source":True,"activate_service":False,"restart_daemon":False},
        "existing_archive":{"archive_path":"/public/qualified"}}

def state(status="completed"):
    return {"revision":3,"custody_available":True,
        "sources":[{"id":SOURCE,"provider":"codex","label":"Fixture native source","kind":"native_store","status":"connected","authorized_at":1,"authorized_until":None}],
        "accounts":[{"id":ACCOUNT,"source_ids":[SOURCE],"lifecycle":"active","identity":{"provider":"codex","verified":True}}],
        "grants":[{"id":GRANT,"source_id":SOURCE,"account_id":ACCOUNT,"credential_kind":"oauth_access","ownership":"external","status":"ready","audience":"https://chatgpt.com","purposes":["request","account_read"],"provider_expires_at":1000,"custody_expires_at":1000,"generation":1}],
        "jobs":[{"id":"reconcile-"+SOURCE,"kind":"enrollment","operation_generation":7,"status":status}]}

class DefaultContract(unittest.TestCase):
    def test_permission_and_carrier_are_explicit_and_old_context_preserved(self):
        value=manifest()
        with mock.patch.object(default.owned,"start_pins",return_value=value["existing_archive"]):
            default.guard.manifest_schema(value,default.Path("/home/jess"))
            default.guard.carrier_purpose(default.guard.EXISTING_ENROLLMENT_LABEL,value["action"],True)
            for field,change in (("native_context",{}),("ownership","home-manager")):
                bad=copy.deepcopy(value);bad[field]=change
                with self.assertRaises(ValueError): default.guard.manifest_schema(bad,default.Path("/home/jess"))
            for key in value["permissions"]:
                bad=copy.deepcopy(value);bad["permissions"][key]=not bad["permissions"][key]
                with self.assertRaises(ValueError): default.guard.manifest_schema(bad,default.Path("/home/jess"))
            old=copy.deepcopy(value);old["action"]="enroll-existing";old["native_context"]={"application":"codex","provenance":"authorized-working-native-context","codex_home":"/authorized/native"}
            old["permissions"]["restart_daemon"]=True
            default.guard.manifest_schema(old,default.Path("/home/jess"))
        for label in (default.guard.LABEL,default.guard.LIFECYCLE_LABEL):
            with self.assertRaises(ValueError): default.guard.carrier_purpose(label,value["action"],True)
    def test_existing_carrier_routes_default_without_host_metadata_or_old_restart_delegate(self):
        value=manifest();environment={"HOME":"/home/jess","XDG_RUNTIME_DIR":"/fixture"}
        original=entry.resident.DEADLINE_NS
        try:
            with mock.patch.dict(os.environ,{"HOME":"/home/jess"}), \
                    mock.patch.object(entry.owned,"start_pins",return_value=value["existing_archive"]), \
                    mock.patch.object(entry.resident,"original_deadline",return_value=1300*10**9), \
                    mock.patch.object(entry.resident,"controller_environment",return_value=environment), \
                    mock.patch.object(entry.resident,"execute",side_effect=AssertionError("no old path reader/restart")), \
                    mock.patch.object(default,"execute",return_value={"outcome":"fixture"}) as delegate:
                self.assertEqual(entry.execute_existing(default.Path("/declared/systemctl"),default.Path("/declared/session-probe"),value),{"outcome":"fixture"})
                self.assertEqual(entry.resident.DEADLINE_NS,1300*10**9)
                delegate.assert_called_once_with(default.Path("/declared/systemctl"),value,environment,entry.resident.bounded,entry.resident.remaining,1300*10**9)
        finally:
            entry.resident.DEADLINE_NS=original

    def test_default_resolution_never_guesses_existing_native_source_from_label(self):
        empty={**state(),"sources":[],"accounts":[],"grants":[],"jobs":[]}
        self.assertEqual(default.fresh_default(empty),3)
        for status in ("connected","detached","disconnected"):
            bad=state();bad["sources"][0]["status"]=status
            with self.assertRaises(ValueError): default.fresh_default(bad)
    def test_admitted_generation_is_explicit_not_inferred(self):
        reply={"status":"verifying_identity","operation_id":"reconcile-"+SOURCE,"operation_generation":7,"admitted_revision":3}
        self.assertEqual(default.admitted(reply,SOURCE),(reply["operation_id"],7,3))
        for key,change in (("operation_generation",True),("operation_generation",0),("operation_id","other"),("admitted_revision",-1)):
            bad={**reply,key:change}
            with self.assertRaises(ValueError): default.admitted(bad,SOURCE)
    def test_progress_requires_exact_generation_and_verified_external_valid_authority(self):
        outcome,facts=default.progress(state(),SOURCE,"reconcile-"+SOURCE,7,3,10)
        self.assertEqual(outcome,"verified");self.assertEqual(facts["account_handle"],ACCOUNT)
        for section,key,change in (("jobs","operation_generation",8),("accounts","lifecycle","paused"),
                ("grants","ownership","daemon"),("grants","custody_expires_at",10),("grants","status","unavailable")):
            bad=state();bad[section][0][key]=change
            with self.assertRaises(ValueError): default.progress(bad,SOURCE,"reconcile-"+SOURCE,7,3,10)
        bad=state();bad["accounts"][0]["identity"]["verified"]=False
        with self.assertRaises(ValueError): default.progress(bad,SOURCE,"reconcile-"+SOURCE,7,3,10)
        bad=state();bad["accounts"].append(copy.deepcopy(bad["accounts"][0]))
        with self.assertRaises(ValueError): default.progress(bad,SOURCE,"reconcile-"+SOURCE,7,3,10)
    def test_pending_failure_and_detachment_never_invent_verified_identity(self):
        self.assertEqual(default.progress(state("running"),SOURCE,"reconcile-"+SOURCE,7,3,10),("pending",None))
        self.assertEqual(default.progress(state("failed"),SOURCE,"reconcile-"+SOURCE,7,3,10),("identity_verification_failed",None))
        bad=state();bad["sources"][0]["status"]="detached"
        self.assertEqual(default.progress(bad,SOURCE,"reconcile-"+SOURCE,7,3,10),("source_detached",None))
    def test_pending_wait_expires_original_bound_without_retry_or_clock_reset(self):
        channel=mock.Mock();channel.read.return_value=state("running")
        remaining=mock.Mock()
        with mock.patch.object(default.time,"monotonic_ns",side_effect=[100*10**9,100*10**9,100*10**9,200*10**9]), \
                mock.patch.object(default.time,"time",return_value=10),mock.patch.object(default.time,"sleep") as sleep:
            with self.assertRaises(ValueError):
                default.await_authority(channel,SOURCE,"reconcile-"+SOURCE,7,3,200*10**9,remaining)
            sleep.assert_not_called()
        channel.read.assert_called_once_with("state.snapshot")
        self.assertEqual(remaining.call_count,2)

    def test_terminal_reply_crossing_fixed_local_poll_bound_is_not_accepted(self):
        channel=mock.Mock();channel.read.return_value=state("completed")
        with mock.patch.object(default.time,"monotonic_ns",side_effect=[100*10**9,100*10**9,220*10**9]):
            with self.assertRaises(ValueError):
                default.await_authority(channel,SOURCE,"reconcile-"+SOURCE,7,3,500*10**9,mock.Mock())
        channel.read.assert_called_once_with("state.snapshot")

    def test_wire_omits_profile_and_credentials_and_preserves_old_channel_methods(self):
        channel=object.__new__(default.Channel);channel.deadline=1300*10**9;channel.serial=0
        channel.peer="private-fixture";channel.identity=mock.Mock(return_value=channel.peer);channel.timeout=mock.Mock(return_value=1)
        channel.connection=mock.Mock();channel.connection.recv.return_value=b'{"jsonrpc":"2.0","id":1,"result":{"status":"authorized"}}\n'
        with mock.patch.object(default.time,"monotonic_ns",return_value=100*10**9):
            default.mutation(channel,"source.connect",{"kind":"native_store","provider":"codex","label":"Authorized native account"},3)
        sent=json.loads(channel.connection.sendall.call_args.args[0])
        self.assertEqual(set(sent["params"]),{"kind","provider","label","expected_revision","operation_id"})
        self.assertEqual(sent["params"]["expected_revision"],3)
        self.assertRegex(sent["params"]["operation_id"],r"^[0-9a-f]{64}$")
        channel.connection.sendall.assert_called_once()
        old=object.__new__(default.custody.Channel)
        with self.assertRaises(ValueError): old.rpc("source.connect",{})
        with self.assertRaises(ValueError): old.rpc("custody.reopen",{"extra":"forbidden"})
        for bad in ({"source_path":"/guessed/auth.json"},{"access_token":"fixture-private-body"}):
            with self.assertRaises(ValueError): channel.rpc("source.connect",{**sent["params"],**bad})
        with self.assertRaises(ValueError): channel.rpc("accounts.importNative",{})

class ExecuteContract(unittest.TestCase):
    def invoke(self,*,failed=False,drift=False,locked=False,ambiguous=False):
        value=manifest();value["existing_archive"]["archive_sha256"]="d"*64
        uid=os.getuid();exe=str(default.Path(value["prefix"])/"bin/omuxd")
        values={"LoadState":"loaded","ActiveState":"active","SubState":"running","MainPID":"10",
            "ControlGroup":f"/user.slice/user-{uid}.slice/user@{uid}.service/app.slice/ai.xoxd.omux.service",
            "FragmentPath":value["service_path"],"UnitFileState":"enabled","Slice":"app.slice",
            "ExecStart":"{ path="+exe+" ; argv[]="+exe+" --state-dir "+value["runtime_state"]+" ; ignore_errors=no ; pid=10 ; status=0/0 }",
            "DropInPaths":"","NeedDaemonReload":"no","MemoryMax":"268435456","MemorySwapMax":"0","TasksMax":"32","CPUQuotaPerSecUSec":"100ms","InvocationID":"e"*32,"NRestarts":"0"}
        commands=[]
        def bounded(command,environment):
            commands.append(command)
            self.assertEqual(command[:4],["/declared/systemctl","--user","--quiet","show"])
            current={**values,"InvocationID":"f"*32} if drift and len(commands) >= 4 else values
            return "\n".join(k+"="+v for k,v in current.items()).encode()
        health={"protocol_version":2,"status":"vault_locked" if locked else "ready","custody_available":not locked,"metadata_loaded":not locked,"account_count":None if locked else 0,"live_handoff_proven":False,"provider_access":False,"recovery_action":"unlock_platform_vault_then_reopen_custody"}
        handshake={"protocol_version":2,"service":"omuxd","channel":"control","custody_available":not locked,"capabilities":{"custody_reopen":True,"credential_free_control":True,"live_handoff_proven":False}}
        empty={**state(),"sources":[],"accounts":[],"grants":[],"jobs":[]}
        initial=state() if ambiguous else empty
        terminal=state("failed" if failed else "completed")
        if failed: terminal["accounts"],terminal["grants"]=[],[]
        after_source={**state(),"accounts":[],"grants":[],"jobs":[]}
        pending={**state("running"),"accounts":[],"grants":[]}
        snapshots=iter((initial,after_source,pending,terminal,terminal))
        channel=mock.Mock();channel.peer="fixture";channel.identity.return_value=channel.peer
        def read(method):
            if method == "system.health":
                return {**health,"account_count":1 if ambiguous or (not failed and channel.rpc.call_count == 2) else health["account_count"]}
            return handshake if method == "system.handshake" else next(snapshots)
        channel.read.side_effect=read
        channel.rpc.side_effect=[{"jsonrpc":"2.0","id":4,"result":{"status":"authorized","identity_admission":"verification_required","source_id":SOURCE}},
            {"jsonrpc":"2.0","id":6,"result":{"status":"verifying_identity","operation_id":"reconcile-"+SOURCE,"operation_generation":7,"admitted_revision":3}}]
        witness=mock.Mock();witness.owner.return_value="fixed-images-lock"
        peer=((1,2,stat.S_IFSOCK|0o600,os.getuid(),os.getgid()),10,20)
        caps={"memory.max":"268435456","memory.swap.max":"0","pids.max":"32","cpu.max":"10000 100000"}
        with ExitStack() as stack:
            for target,name,options in ((default.owned,"start_pins",{"return_value":value["existing_archive"]}),
                    (default.owned,"OwnedCustodyReopen",{"return_value":witness}),
                    (default.resident,"process_identity",{"return_value":(10,20,30,40)}),
                    (default.resident,"cgroup_observation",{"return_value":(caps,(1,2))}),
                    (default.guard,"socket_witness",{"return_value":peer}),(default.guard,"start_ticks",{"return_value":20}),
                    (default,"Channel",{"return_value":channel}),(default.time,"monotonic_ns",{"return_value":100*10**9}),
                    (default.time,"time",{"return_value":10}),(default.time,"sleep",{}),
                    (default.Path,"stat",{"side_effect":AssertionError("no host profile/proc stat")}),
                    (default.Path,"read_text",{"side_effect":AssertionError("no host profile/proc read")})):
                stack.enter_context(mock.patch.object(target,name,**options))
            try:
                result=default.execute(default.Path("/declared/systemctl"),value,{"HOME":"/home/jess","XDG_RUNTIME_DIR":"/fixture"},bounded,mock.Mock(),1300*10**9)
            finally:
                witness.close.assert_called_once();channel.close.assert_called_once()
                if locked or ambiguous: channel.rpc.assert_not_called()
            self.assertEqual(len(commands),4)
            self.assertEqual([call.args[0] for call in channel.rpc.call_args_list],["source.connect","enrollment.start"])
            self.assertNotIn("source_path",channel.rpc.call_args_list[0].args[1])
            self.assertNotIn("allow_reenrollment",channel.rpc.call_args_list[1].args[1])
            return result
    def test_complete_verified_one_source_and_external_renewal_without_service_transition(self):
        result=self.invoke()
        self.assertEqual(result["verified_source_identities"],1)
        self.assertEqual(result["authority"]["grant_handle"],GRANT)
        self.assertEqual(result["renewal_writer"],"external")
        self.assertFalse(result["controller_provider_requests"])
        self.assertTrue(result["daemon_identity_verification_authorized"])
        self.assertIsNone(result["daemon_provider_requests_observed"])
        self.assertIs(result["service_mutation_requested"],False)
        self.assertIs(result["profile_path_selected_by_controller"],False)
    def test_complete_failed_job_is_truthful_without_authority(self):
        result=self.invoke(failed=True)
        self.assertEqual(result["outcome"],"identity_verification_failed")
        self.assertIsNone(result["authority"]);self.assertIsNone(result["renewal_writer"])
    def test_complete_owner_drift_refuses_without_replaying_effect(self):
        with self.assertRaises(ValueError): self.invoke(drift=True)
    def test_locked_or_ambiguous_state_refuses_before_source_connection(self):
        for options in ({"locked":True},{"ambiguous":True}):
            with self.assertRaises(ValueError): self.invoke(**options)

if __name__ == "__main__": unittest.main()
