"""Finite offline predicates only; no installed daemon or vault access."""
import copy
import json
import unittest
from unittest import mock
import resident_custody_reopen as reopen

class ReopenContract(unittest.TestCase):
    def pair(self,loaded=False,count=None):
        health={"protocol_version":2,"status":"ready" if loaded else "vault_locked",
            "custody_available":loaded,"metadata_loaded":loaded,"account_count":count,
            "provider_access":False,"live_handoff_proven":False,
            "recovery_action":"unlock_platform_vault_then_reopen_custody"}
        handshake={"protocol_version":2,"service":"omuxd","channel":"control","custody_available":loaded,
            "capabilities":{"custody_reopen":True,"credential_free_control":True,"live_handoff_proven":False}}
        return health,handshake
    def response(self,count=0,reopened=True):
        return {"jsonrpc":"2.0","id":3,"result":{"reopened":reopened,"custody_available":True,
            "metadata_loaded":True,"account_count":count,"provider_request_initiated":False,"live_handoff_proven":False}}
    def test_cached_locked_count_is_unknown_and_capability_is_required(self):
        pair=self.pair()
        self.assertEqual(reopen.metadata(*pair),(False,None))
        for change in (0,False,"0"):
            bad=copy.deepcopy(pair)
            bad[0]["account_count"]=change
            with self.assertRaises(ValueError): reopen.metadata(*bad)
        for change in (False,None,"true"):
            bad=copy.deepcopy(pair)
            bad[1]["capabilities"]["custody_reopen"]=change
            with self.assertRaises(ValueError): reopen.metadata(*bad)
    def test_loaded_count_is_typed_and_both_views_must_agree(self):
        self.assertEqual(reopen.metadata(*self.pair(True,2)),(True,2))
        for count in (True,None,-1):
            with self.assertRaises(ValueError): reopen.metadata(*self.pair(True,count))
        bad=self.pair(True,0)
        bad[1]["custody_available"]=False
        with self.assertRaises(ValueError): reopen.metadata(*bad)
    def test_exact_ready_and_idempotent_classification(self):
        self.assertEqual(reopen.classify((False,None),(True,2),self.response(2)),("ready",None))
        self.assertEqual(reopen.classify((True,2),(True,2),self.response(2,False)),("ready",None))
        for key,value in (("provider_request_initiated",True),("live_handoff_proven",True),
                ("account_count",True),("reopened",False)):
            bad=self.response(2)
            bad["result"][key]=value
            with self.assertRaises(ValueError): reopen.classify((False,None),(True,2),bad)
        with self.assertRaises(ValueError): reopen.classify((False,None),(True,3),self.response(2))
    def test_safe_refusal_requires_authentic_error_and_unloaded_readback(self):
        response={"jsonrpc":"2.0","id":3,"error":{"code":-32000,"message":"Locked"}}
        self.assertEqual(reopen.classify((False,None),(False,None),response),("safe_refusal","Locked"))
        for before,after in (((False,None),(True,0)),((True,0),(False,None))):
            with self.assertRaises(ValueError): reopen.classify(before,after,response)
        for message in ("InvalidParams","arbitrary diagnostic"):
            bad=copy.deepcopy(response)
            bad["error"]["message"]=message
            with self.assertRaises(ValueError): reopen.classify((False,None),(False,None),bad)
    def channel(self,reply):
        channel=object.__new__(reopen.Channel)
        channel.serial=0
        channel.deadline=10**30
        channel.peer=("socket",42)
        channel.connection=mock.Mock()
        channel.connection.recv.return_value=reply
        channel.identity=mock.Mock(return_value=channel.peer)
        channel.timeout=mock.Mock(return_value=1)
        return channel
    def test_wire_empty_params_one_request_and_strict_frame(self):
        channel=self.channel(b'{"jsonrpc":"2.0","id":1,"result":{}}\n')
        channel.rpc("custody.reopen")
        raw=channel.connection.sendall.call_args.args[0]
        self.assertEqual(json.loads(raw),{"jsonrpc":"2.0","id":1,"method":"custody.reopen","params":{}})
        channel.connection.sendall.assert_called_once()
        for raw in (b'{"jsonrpc":"2.0","id":2,"result":{}}\n',
                b'{"jsonrpc":"2.0","id":1,"id":1,"result":{}}\n',
                b'{"jsonrpc":"2.0","id":1,"result":{}}\nextra'):
            with self.assertRaises(ValueError): self.channel(raw).rpc("custody.reopen")
    def test_fragmented_reply_cannot_renew_fifteen_second_call_cap(self):
        for final,expired in ((114,False),(115,True)):
            channel=self.channel(b"")
            channel.deadline=200*10**9
            channel.timeout=reopen.Channel.timeout.__get__(channel)
            channel.connection.recv.side_effect=[b'{"jsonrpc":"2.0","id":1,',b'"result":{}}\n']
            with mock.patch.object(reopen.time,"monotonic_ns",side_effect=[value*10**9 for value in (100,100,100,114,final)]):
                if expired:
                    with self.assertRaises(ValueError): channel.rpc("custody.reopen")
                else:
                    self.assertEqual(channel.rpc("custody.reopen")["result"],{})
            self.assertEqual([call.args[0] for call in channel.connection.settimeout.call_args_list],[15,15,1])
            channel.connection.sendall.assert_called_once()
            self.assertEqual(channel.connection.recv.call_count,2)
            self.assertEqual(channel.deadline,200*10**9)

    def test_peer_replacement_and_undeclared_method_refuse_before_send(self):
        for method in ("accounts.importNative","sources.connect","custody.unlock"):
            channel=self.channel(b"")
            with self.assertRaises(ValueError): channel.rpc(method)
            channel.connection.sendall.assert_not_called()
        channel=self.channel(b"")
        channel.identity.return_value=("replacement",42)
        with self.assertRaises(ValueError): channel.rpc("custody.reopen")
        channel.connection.sendall.assert_not_called()
    def test_original_deadline_is_not_renewed(self):
        channel=object.__new__(reopen.Channel)
        channel.deadline=100
        with mock.patch.object(reopen.time,"monotonic_ns",return_value=100):
            with self.assertRaises(ValueError): channel.timeout()
        with mock.patch.object(reopen.time,"monotonic_ns",return_value=99):
            self.assertEqual(channel.timeout(),1/10**9)


class AdmissionContract(unittest.TestCase):
    def test_exact_lifecycle_role_and_permissions(self):
        home=reopen.Path("/home/jess")
        value={"schema_version":1,"ownership":"omux-installation","action":"reopen-existing","instance":"default",
            **{key:str(path) for key,path in reopen.guard.fixed_paths(home).items()},
            "native_context":None,"permissions":{"connect_source":False,"activate_service":False,"restart_daemon":False},
            "start":{"archive_path":"/public/qualified-archive"}}
        with mock.patch.object(reopen.owned,"start_pins",return_value=value["start"]):
            reopen.guard.manifest_schema(value,home)
            for key in value["permissions"]:
                bad=copy.deepcopy(value)
                bad["permissions"][key]=True
                with self.assertRaises(ValueError): reopen.guard.manifest_schema(bad,home)
            for field,change in (("native_context",{}),("ownership","home-manager")):
                bad=copy.deepcopy(value)
                bad[field]=change
                with self.assertRaises(ValueError): reopen.guard.manifest_schema(bad,home)


class CompleteExecuteContract(unittest.TestCase):
    def invoke(self,*,refusal=False,drift=None,missing=None):
        from contextlib import ExitStack
        import os
        import stat
        home=reopen.Path("/home/jess")
        selection={"archive_path":"/public/qualified-archive","archive_sha256":"a"*64}
        manifest={"schema_version":1,"ownership":"omux-installation","action":"reopen-existing","instance":"default",
            **{key:str(path) for key,path in reopen.guard.fixed_paths(home).items()},
            "native_context":None,"permissions":{"connect_source":False,"activate_service":False,"restart_daemon":False},
            "start":selection}
        executable=str(reopen.Path(manifest["prefix"])/"bin/omuxd")
        group="/user.slice/user-"+str(os.getuid())+".slice/user@"+str(os.getuid())+".service/app.slice/ai.xoxd.omux.service"
        values={"LoadState":"loaded","ActiveState":"active","SubState":"running","MainPID":"10",
            "ControlGroup":group,"FragmentPath":manifest["service_path"],"UnitFileState":"enabled",
            "Slice":"app.slice","ExecStart":"{ path="+executable+" ; argv[]="+executable+" --state-dir "+manifest["runtime_state"]+" ; ignore_errors=no ; pid=10 ; status=0/0 }",
            "DropInPaths":"","NeedDaemonReload":"no","MemoryMax":"268435456","MemorySwapMax":"0",
            "TasksMax":"32","CPUQuotaPerSecUSec":"100ms","InvocationID":"b"*32,"NRestarts":"0"}
        observations=0
        commands=[]
        def bounded(command,environment):
            nonlocal observations
            commands.append(command)
            self.assertEqual(command[:4],["/declared/systemctl","--user","--quiet","show"])
            self.assertEqual(command[-1],"ai.xoxd.omux.service")
            self.assertEqual(command[4],"--property="+",".join(sorted(reopen.PROPERTIES)))
            observations+=1
            current=dict(values)
            if observations >= 3 and drift in ("InvocationID","NRestarts","MainPID"):
                current[drift]={"InvocationID":"c"*32,"NRestarts":"1","MainPID":"11"}[drift]
            return "\n".join(key+"="+value for key,value in current.items()).encode()
        peer=((1,2,stat.S_IFSOCK|0o600,os.getuid(),os.getgid()),10,20)
        def socket_peer(path):
            if drift == "socket" and observations >= 3:
                return ((1,3,stat.S_IFSOCK|0o600,os.getuid(),os.getgid()),10,20)
            return peer
        caps={"memory.max":"268435456","memory.swap.max":"0","pids.max":"32","cpu.max":"10000 100000"}
        witness=mock.Mock()
        witness.owner.side_effect=lambda pid,prefix: ("changed-lock" if drift == "writer" and observations >= 3 else "original-lock",(5,6))
        channel=mock.Mock()
        channel.peer="original-connected-peer"
        channel.identity.return_value=channel.peer
        helpers=ReopenContract()
        before=helpers.pair()
        if missing:
            before[0].pop(missing)
        after=helpers.pair() if refusal else helpers.pair(True,2)
        replies=iter((*before,*after))
        read_methods=[]
        def read(method):
            read_methods.append(method)
            return next(replies)
        channel.read.side_effect=read
        channel.rpc.return_value=({"jsonrpc":"2.0","id":3,"error":{"code":-32000,"message":"Locked"}}
            if refusal else helpers.response(2))
        remaining=mock.Mock()
        with ExitStack() as stack:
            for target,name,options in (
                (reopen.owned,"start_pins",{"return_value":selection}),
                (reopen.owned,"OwnedCustodyReopen",{"return_value":witness}),
                (reopen.resident,"process_identity",{"side_effect":lambda pid:(pid,20,30,40)}),
                (reopen.resident,"cgroup_observation",{"side_effect":lambda group,pid:(caps,(1,3 if drift == "cgroup" and observations >= 3 else 2))}),
                (reopen.guard,"socket_witness",{"side_effect":socket_peer}),
                (reopen,"Channel",{"return_value":channel}),
            ):
                stack.enter_context(mock.patch.object(target,name,**options))
            try:
                result=reopen.execute(reopen.Path("/declared/systemctl"),manifest,
                    {"HOME":str(home),"XDG_RUNTIME_DIR":"/omux-resident-inputs"},bounded,remaining,1300*10**9)
            finally:
                witness.close.assert_called_once()
                channel.close.assert_called_once()
                if missing:
                    channel.rpc.assert_not_called()
                if drift:
                    channel.rpc.assert_called_once_with("custody.reopen")
                    self.assertEqual(read_methods,["system.health","system.handshake"]*2)
            self.assertEqual(read_methods,["system.health","system.handshake"]*2)
            channel.rpc.assert_called_once_with("custody.reopen")
            self.assertEqual(len(commands),3)
            self.assertGreaterEqual(remaining.call_count,6)
            self.assertIs(result["service_mutation_requested"],False)
            self.assertIs(result["provider_request_requested_by_controller"],False)
            self.assertIs(result["enrollment_verified"],False)
            self.assertIs(result["same_process_handoff_proven"],False)
            return result
    def test_complete_success_and_safe_refusal_keep_process_and_truthful_counts(self):
        result=self.invoke()
        self.assertEqual((result["outcome"],result["metadata_loaded"],result["account_count"]),("ready",True,2))
        self.assertIsNone(result["account_count_before"])
        result=self.invoke(refusal=True)
        self.assertEqual((result["outcome"],result["refusal"],result["metadata_loaded"],result["account_count"]),
            ("safe_refusal","Locked",False,None))
    def test_full_execute_identity_changes_refuse_after_request(self):
        for drift in ("InvocationID","NRestarts","MainPID","cgroup","socket","writer"):
            with self.subTest(drift=drift), self.assertRaises(ValueError): self.invoke(drift=drift)
    def test_missing_typed_metadata_refuses_before_reopen(self):
        for missing in ("metadata_loaded","account_count"):
            with self.subTest(missing=missing), self.assertRaises(ValueError): self.invoke(missing=missing)
    def test_socket_call_cap_is_fifteen_seconds_and_uses_original_remaining(self):
        channel=object.__new__(reopen.Channel)
        channel.deadline=120*10**9
        with mock.patch.object(reopen.time,"monotonic_ns",return_value=100*10**9):
            self.assertEqual(channel.timeout(),15)
        with mock.patch.object(reopen.time,"monotonic_ns",return_value=119*10**9):
            self.assertEqual(channel.timeout(),1)
        with mock.patch.object(reopen.time,"monotonic_ns",return_value=114*10**9):
            self.assertEqual(channel.timeout(115*10**9),1)
        with mock.patch.object(reopen.time,"monotonic_ns",return_value=115*10**9):
            with self.assertRaises(ValueError): channel.timeout(115*10**9)
        self.assertEqual(channel.deadline,120*10**9)


class PortableImageContract(unittest.TestCase):
    def images(self):
        from types import SimpleNamespace
        import os
        loader=SimpleNamespace(path=reopen.Path("/owned/lib/omux/lib/ld-linux-x86-64.so.2"),identity=(os.makedev(8,1),100))
        backend=SimpleNamespace(path=reopen.Path("/owned/lib/omux/libexec/omuxd.bin"),identity=(os.makedev(8,1),101))
        maps=("1000-2000 r--p 00000000 08:01 100 "+str(loader.path)+"\n"
            "2000-3000 r-xp 00001000 08:01 100 "+str(loader.path)+"\n"
            "3000-4000 r--p 00000000 08:01 101 "+str(backend.path)+"\n"
            "4000-5000 r-xp 00001000 08:01 101 "+str(backend.path)+"\n").encode()
        return loader,backend,maps
    def test_exact_qualified_loader_and_backend_mapping(self):
        loader,backend,maps=self.images()
        self.assertEqual(reopen.owned.portable_process_images(str(loader.path),loader.identity,maps,loader,backend),
            (loader.identity,backend.identity))
    def test_loader_replacement_launcher_identity_and_basename_refuse(self):
        loader,backend,maps=self.images()
        for name,identity in ((str(loader.path),(loader.identity[0],999)),
                ("/owned/bin/omuxd",loader.identity),(loader.path.name,loader.identity),
                (str(loader.path)+" (deleted)",loader.identity)):
            with self.assertRaises(ValueError): reopen.owned.portable_process_images(name,identity,maps,loader,backend)
    def test_backend_replacement_missing_deleted_or_nonexecuting_mapping_refuse(self):
        loader,backend,maps=self.images()
        for bad in (maps.replace(b"08:01 101",b"08:01 999"),
                b"\n".join(row for row in maps.splitlines() if b"omuxd.bin" not in row),
                maps.replace(str(backend.path).encode(),(str(backend.path)+" (deleted)").encode()),
                maps.replace(b"4000-5000 r-xp",b"4000-5000 r--p"),
                maps.replace(str(backend.path).encode(),b"/other/libexec/omuxd.bin")):
            with self.assertRaises(ValueError): reopen.owned.portable_process_images(str(loader.path),loader.identity,bad,loader,backend)

if __name__ == "__main__": unittest.main()
