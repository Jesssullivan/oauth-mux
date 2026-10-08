"""Offline resident authority, wire parser, receipt and containment models."""
import copy
import json
import os
from pathlib import Path
import stat
import struct
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch
import guard_resident_continuity_profile as guard
import guard_resident_observation as resident

EPOCH = "11111111-1111-4111-8111-111111111111"
def context():
    return {"producer":guard.LABEL,"action_epoch":EPOCH,"producer_source_sha256":"1"*64,
        "observer_source_sha256":"2"*64,"runtime_selection_sha256":"3"*64,"model":"small-model",
        "application_version":"0.45.0","runtime_archive_sha256":"4"*64,"upstream_commit":"5"*40,
        "candidate_patch_sha256s":list(guard.PATCHES),"daemon_archive_sha256":"9"*64,
        "daemon_executable_sha256":"a"*64,"daemon_source_commit":"b"*40,"daemon_graph_sha256":"c"*64}
def native():
    c = context()
    return {**copy.deepcopy(guard.NATIVE_FIXED),**{key:c[key] for key in (
        "application_version","model","runtime_archive_sha256","upstream_commit","candidate_patch_sha256s")},
        "reasoning_effort":"minimal"}
def projection():
    c = context()
    return {"schema_version":1,**{k:c[k] for k in ("producer","action_epoch","producer_source_sha256",
        "observer_source_sha256","runtime_selection_sha256","model")},"native_result":native()}
def manifest(home=Path("/home/jess")):
    paths = resident.fixed_paths(home)
    return {"schema_version":1,"action_epoch":EPOCH,"model":"small-model",
        "allow_account_wide_drain":True,"proof_root":str(guard.proof_path(home,EPOCH)),
        "selected_accounts":[{"account_handle":"b"*64,"source_handle":"c"*64,"grant_handle":"d"*64,"grant_generation":1},
            {"account_handle":"e"*64,"source_handle":"f"*64,"grant_handle":"0"*64,"grant_generation":2}],
        "drain_account_handle":"b"*64,"resident":{"ownership":"omux-installation",
            **{k:str(v) for k,v in paths.items()},"archive_sha256":"9"*64,
            "executable_sha256":"a"*64,"executable_path":str(paths["prefix"]/"lib/omux/libexec/omuxd.bin"),
            "pid":123,"start_ticks":456,"installation":installation()}}
def installation():
    root="/home/jess/.local/state/omux-execution-20261005/"+EPOCH
    return {"archive":{"path":root+"/output-base/execroot/_main/bazel-out/k8-fastbuild/bin/delivery/default_instance_archive.tar.gz","sha256":"9"*64,"bytes":1},
        "manifest_sha256":"d"*64,"qualification":{"path":root+"/receipt.json","sha256":"e"*64,"bytes":1},
        "source_commit":"b"*40,"graph_sha256":"c"*64}
def snapshot():
    m = manifest()
    value = {"accounts":[],"sources":[],"grants":[]}
    for row in m["selected_accounts"]:
        value["accounts"].append({"id":row["account_handle"],"identity":{"provider":"codex","verified":True},
            "lifecycle":"active","source_ids":[row["source_handle"]]})
        value["sources"].append({"id":row["source_handle"],"provider":"codex","kind":"native_store",
            "status":"connected","authorized_at":100,"authorized_until":None})
        value["grants"].append({"id":row["grant_handle"],"account_id":row["account_handle"],
            "source_id":row["source_handle"],"generation":row["grant_generation"],
            "credential_kind":"oauth_access","ownership":"external","status":"ready",
            "audience":"https://chatgpt.com","purposes":["request"],
            "custody_expires_at":2000,"provider_expires_at":None})
    return value

class AdmissionModels(unittest.TestCase):
    def test_current_protocol_lineage_does_not_adopt_old_fresh_or_staged(self):
        package={'kind':guard.PACKAGE_KIND,'patch_sha256':list(guard.PATCHES)}
        guard.package_lineage(package)
        for wrong in ({**package,'kind':'omux-staged-native-package-selection-v1'},
            {**package,'patch_sha256':guard.PATCHES[:3]},
            {**package,'patch_sha256':['f'*64,*guard.PATCHES[1:]]}):
            with self.assertRaises(ValueError): guard.package_lineage(wrong)
        protocol={key:{} for key in ('protocol','schema','cli','artifact_envelopes','artifact_files')}
        value={'chain':{'patch_sha256':list(guard.PATCHES),'native_protocol_history':protocol}}
        guard.runtime_lineage(value)
        for wrong in ({'chain':{'patch_sha256':guard.PATCHES[:3],'native_protocol_history':protocol}},
            {'chain':{'patch_sha256':guard.PATCHES}},
            {'chain':{'patch_sha256':guard.PATCHES,'native_protocol_history':{**protocol,'extra':{}}}}):
            with self.assertRaises(ValueError): guard.runtime_lineage(wrong)

    def test_private_daemon_socket_rejects_permissive_mode_before_connection(self):
        selected=SimpleNamespace(stat=lambda **kwargs:SimpleNamespace(st_mode=stat.S_IFSOCK|0o666,st_uid=os.getuid(),st_gid=os.getgid()))
        with patch.object(guard.time,'monotonic_ns',return_value=1),patch.object(guard.socket,'socket') as opened:
            with self.assertRaises(ValueError): guard.socket_witness(selected,100,True)
            opened.assert_not_called()

    def test_exact_network_action_without_offline_profile_broadening(self):
        self.assertEqual(guard.finite(["run",guard.LABEL],"system","/private/input.json",False),
            {"PrivateNetwork":"no","ProtectSystem":"strict","PrivateTmp":"yes","PrivatePIDs":"no"})
        for args,manager,reuse,other in ((["test",guard.LABEL],"system",False,()),
            (["run","//delivery:resident_codex_enrollment"],"system",False,()),
            (["run",guard.LABEL,"--"],"system",False,()),(["run",guard.LABEL],"user",False,()),
            (["run",guard.LABEL],"system",True,()),(["run",guard.LABEL],"system",False,("foreign",))):
            with self.assertRaises(ValueError):
                guard.finite(args,manager,"/private/input.json",reuse,other)
        with self.assertRaises(ValueError):
            guard.finite(["run","//delivery:resident_codex_enrollment"],"system","/private/input.json",False)

    def test_exact_epoch_profile_two_handles_selected_A_and_owned_resident_only(self):
        guard.manifest_schema(manifest(),Path("/home/jess"),EPOCH)
        self.assertEqual(len(os.fsencode(guard.proof_path(Path("/home/jess"),EPOCH)/"c")),66)
        for mutate in (lambda v:v.update(extra=True),lambda v:v.update(proof_root="/private/foreign"),
            lambda v:v.update(drain_account_handle=v["selected_accounts"][1]["account_handle"]),
            lambda v:v["resident"].update(ownership="home-manager"),
            lambda v:v["resident"].update(executable_path="/private/foreign-executable"),
            lambda v:v["selected_accounts"][0].update(grant_generation=True),
            lambda v:v["selected_accounts"][1].update(source_handle=v["selected_accounts"][0]["source_handle"]),
            lambda v:v.update(allow_account_wide_drain=False)):
            value = manifest()
            mutate(value)
            with self.assertRaises(ValueError):
                guard.manifest_schema(value,Path("/home/jess"),EPOCH)
        with self.assertRaises(ValueError):
            guard.manifest_schema(manifest(),Path("/home/jess"),"22222222-2222-4222-8222-222222222222")

    def test_current_grant_qualified_identity_and_generation_are_actual_predicates(self):
        rows = manifest()["selected_accounts"]
        with patch.object(guard.time,"time",return_value=1000):
            guard.current_domain(snapshot(),rows)
            for mutate in (lambda v:v["accounts"][0]["identity"].pop("verified"),
                lambda v:v["accounts"][0]["identity"].update(verified=False),
                lambda v:v["grants"][0].update(generation=2),
                lambda v:v["grants"][0].update(custody_expires_at=None),
                lambda v:v["grants"][0].update(custody_expires_at=True),
                lambda v:v["grants"][0].update(custody_expires_at=999),
                lambda v:v["sources"][0].update(status="disconnected"),
                lambda v:v["accounts"][0].update(lifecycle="draining"),
                lambda v:v["grants"].append(copy.deepcopy(v["grants"][0]))):
                value = snapshot()
                mutate(value)
                with self.assertRaises(ValueError):
                    guard.current_domain(value,rows)
            after = snapshot()
            after["accounts"][0]["lifecycle"] = "draining"
            guard.current_domain(after,rows,rows[0]["account_handle"])

    def test_original_deadline_is_not_renewed_and_has_owned_cleanup_reserve(self):
        context_instance = guard.ControllerContext.__new__(guard.ControllerContext)
        context_instance.deadline = 100*10**9
        with patch.object(guard.time,"monotonic_ns",return_value=20*10**9):
            self.assertEqual(context_instance.remaining(),50)
        with patch.object(guard.time,"monotonic_ns",return_value=70*10**9):
            with self.assertRaises(ValueError):
                context_instance.remaining()

    def test_capability_reader_is_O_PATH_only_and_never_reads_content(self):
        with tempfile.TemporaryDirectory(dir=Path.home()) as temporary:
            path = Path(temporary)/"capability"
            path.write_bytes(b"x"*64)
            path.chmod(0o600)
            with patch.object(guard.os,"pread",side_effect=AssertionError("capability read")):
                held = guard.PublicFile(path,64,0o600,metadata_only=True)
                try:
                    self.assertIsNone(held.raw)
                    held.recheck()
                finally:
                    held.close()

    def test_pinned_readback_preserves_directory_and_leaf_modes_and_denies_extra_writes(self):
        admission = guard.Admission.__new__(guard.Admission)
        admission.bindings = lambda:["/private/input:"+guard.DESTINATION,
            "/private/runtime:/run/user/1000","/run/user/1000/bus:/run/user/1000/bus:norbind"]
        admission.writable_binding = lambda:"/private/proof:/private/proof"
        run = Path("/private/action")
        actual = {"BindReadOnlyPaths":"/private/input:"+guard.DESTINATION+":rbind /private/runtime:/run/user/1000:rbind /run/user/1000/bus:/run/user/1000/bus",
            "BindPaths":"/private/proof:/private/proof:rbind /private/action:/private/action:rbind"}
        admission.verify_bindings(actual,run)
        for field,value in (("BindReadOnlyPaths",actual["BindReadOnlyPaths"]+":rbind"),
            ("BindReadOnlyPaths",actual["BindReadOnlyPaths"].replace("/run/user/1000:rbind","/run/user/1000")),
            ("BindPaths",actual["BindPaths"]+" /home/jess:/home/jess:rbind")):
            with self.assertRaises(ValueError):
                admission.verify_bindings({**actual,field:value},run)


    def test_actual_binding_constructor_uses_private_run_shadow_and_exact_owned_endpoints(self):
        admission = guard.Admission.__new__(guard.Admission)
        admission.root = Path("/private/input")
        admission.observer = SimpleNamespace(runtime=Path("/run/user/1000/omux-"+"a"*32),
            bus=Path("/run/user/1000/bus"))
        admission.integration_root = Path("/home/jess/.local/state/omux/integrations")
        admission.proof_root = Path("/home/jess/.local/state/omux-rp/"+"b"*32)
        admission.fresh = SimpleNamespace(root=Path("/private/qualified/backend"),
            archive=Path("/private/qualified/archive"),manifest=Path("/private/qualified/manifest"),
            receipt=Path("/private/qualified/receipt"))
        bindings = admission.bindings()
        self.assertIn("/private/input/run:/run",bindings)
        self.assertNotIn("/run:/run",bindings)
        self.assertNotIn("/run/user/1000:/run/user/1000",bindings)
        self.assertIn("/run/user/1000/bus:/run/user/1000/bus:norbind",bindings)
        run = Path("/private/action")
        serialized = lambda rows:" ".join(row.removesuffix(":norbind") if row.endswith(":norbind")
            else row+":rbind" for row in rows)
        actual = {"BindReadOnlyPaths":serialized(bindings),
            "BindPaths":serialized([admission.writable_binding(),str(run)+":"+str(run)])}
        admission.verify_bindings(actual,run)
        changed = actual["BindReadOnlyPaths"].replace("/private/input/run:/run:rbind","/run:/run:rbind")
        with self.assertRaises(ValueError):
            admission.verify_bindings({**actual,"BindReadOnlyPaths":changed},run)


class ReceiptModels(unittest.TestCase):
    def test_actual_closed_native_serializer_accepts_fresh_projection(self):
        self.assertEqual(guard.handoff(json.loads(guard.encoded(projection())),context()),native())
        for key,value in (("producer","//delivery:installed_codex_live_continuity_test"),
            ("action_epoch","22222222-2222-4222-8222-222222222222"),
            ("runtime_selection_sha256","0"*64),("model","other-model"),
            ("producer_source_sha256","f"*64),("observer_source_sha256","f"*64)):
            item = projection()
            item[key] = value
            with self.assertRaises(ValueError):
                guard.handoff(item,context())
        for mutate in (lambda v:v.update(private_handles=["opaque"]),
            lambda v:v["native_result"].update(runtime_kind="retained"),
            lambda v:v["native_result"].update(tool_calls=1),
            lambda v:v["native_result"].update(same_process=1),
            lambda v:v["native_result"].update(model="other-model"),
            lambda v:v["native_result"].update(candidate_patch_sha256s=["f"*64]*3)):
            item = projection()
            mutate(item)
            with self.assertRaises(ValueError):
                guard.handoff(item,context())

    def test_observer_projection_cannot_be_missing_failed_or_controller_selfassertion(self):
        observation = {"resident_daemon_same_process":True,"resident_installation_preserved":True,
            "resident_service_active_after_controller":True,"resident_lifecycle_changed":False,
            "resident_vault_owner_preserved":True}
        result = guard.final_receipt(native(),observation,context())
        self.assertEqual(result["scope"],guard.SCOPE)
        for value in ({},{**observation,"resident_service_active_after_controller":False},
            {**observation,"resident_daemon_same_process":1},{**observation,"controller_says_success":True}):
            with self.assertRaises(ValueError):
                guard.final_receipt(native(),value,context())
        self.assertFalse(any(key in result for key in ("pid","proof_root","capability","grant_handle")))

    def test_exclusive_owned_output_refuses_reuse_symlink_and_arbitrary_basename(self):
        with tempfile.TemporaryDirectory(dir=Path.home()) as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            fd = resident.open_directory(root,True)
            try:
                guard.create_file(fd,guard.HANDOFF,projection())
                self.assertEqual(stat.S_IMODE((root/guard.HANDOFF).stat().st_mode),0o600)
                with self.assertRaises(FileExistsError):
                    guard.create_file(fd,guard.HANDOFF,projection())
                with self.assertRaises(ValueError):
                    guard.create_file(fd,"foreign-output.json",projection())
                (root/guard.OUTPUT).symlink_to(root/guard.HANDOFF)
                with self.assertRaises(FileExistsError):
                    guard.create_file(fd,guard.OUTPUT,{})
            finally:
                os.close(fd)

    def test_projection_alone_never_satisfies_successful_outer_guard_join(self):
        observation = {"resident_daemon_same_process":True,"resident_installation_preserved":True,
            "resident_service_active_after_controller":True,"resident_lifecycle_changed":False,
            "resident_vault_owner_preserved":True}
        result = guard.final_receipt(native(),observation,context())
        result.update(guard_graph_sha256="b"*64,requires_successful_guard_receipt=True)
        outer = {"id":EPOCH,"profile":guard.PROFILE,"verb":"run","targets":[guard.LABEL],"exit":0,
            "workload_exit":0,"descendants_empty":True,"cleanup":{"state":"empty"},"controller_failure":None,
            "graph_sha256":"b"*64,"resident_continuity":{"verified_after_cleanup":True,"output":{
                "sha256":"c"*64,"basename":guard.OUTPUT,"verified_after_controller_exit":True}}}
        guard.validate_guard_join(result,outer,"c"*64)
        for key,value in (("exit",125),("workload_exit",1),("descendants_empty",False),
            ("profile","resident-enrollment"),("graph_sha256","d"*64),("controller_failure",{"phase":"failed"})):
            with self.assertRaises(ValueError):
                guard.validate_guard_join(result,{**outer,key:value},"c"*64)

class ObserverModels(unittest.TestCase):
    def test_wrong_control_peer_refuses_before_send_and_no_secret_output(self):
        observer = SimpleNamespace(quick=lambda:None,deadline=100*10**9,
            control_socket=Path("/private/control.sock"),value={"pid":123})
        class Peer:
            def settimeout(self,value): pass
            def connect(self,value): pass
            def getsockopt(self,*args): return struct.pack("3i",999,os.getuid(),os.getgid())
            def sendall(self,value): raise AssertionError("request sent to foreign peer")
            def __enter__(self): return self
            def __exit__(self,*args): pass
        with patch.object(guard.time,"monotonic_ns",return_value=1),patch.object(guard.socket,"socket",return_value=Peer()):
            with self.assertRaisesRegex(ValueError,"^resident-continuity-refused$"):
                guard.control_request(observer,"system.health",{})

    def test_account_drain_is_exact_A_once_and_lost_ack_cannot_reissue(self):
        instance = guard.ControllerContext.__new__(guard.ControllerContext)
        instance.drain_account_handle = "b"*64
        instance.mutations = set()
        instance.recheck = lambda:None
        instance.observer = object()
        params = {"account_id":"b"*64,"operation_id":"c"*64,"expected_revision":1}
        with patch.object(guard,"control_request",side_effect=OSError("closed transport failure")):
            with self.assertRaises(OSError):
                instance.control("account.drain",params)
        with self.assertRaises(ValueError):
            instance.control("account.drain",{**params,"operation_id":"d"*64})
        fresh = guard.ControllerContext.__new__(guard.ControllerContext)
        fresh.drain_account_handle = "b"*64
        fresh.mutations = set()
        with self.assertRaises(ValueError):
            fresh.control("account.drain",{**params,"account_id":"e"*64})
        with self.assertRaises(ValueError):
            instance.control("source.connect",{})



    def test_control_receive_timeouts_shrink_to_original_request_deadline_for_every_chunk(self):
        observer = SimpleNamespace(quick=lambda:None,deadline=100*10**9,
            control_socket=Path("/private/control.sock"),value={"pid":123})
        reply = guard.encoded({"jsonrpc":"2.0","id":1,"result":{}})
        moments = iter([0,0,0,0,0,10*10**9,10*10**9,69*10**9,69*10**9,69*10**9])
        class Peer:
            def __init__(self): self.timeouts,self.reads = [],0
            def settimeout(self,value): self.timeouts.append(value)
            def connect(self,value): pass
            def getsockopt(self,*args): return struct.pack("3i",123,os.getuid(),os.getgid())
            def sendall(self,value): pass
            def recv(self,n):
                self.reads += 1
                return reply[:1] if self.reads == 1 else reply[1:]
            def __enter__(self): return self
            def __exit__(self,*args): pass
        peer = Peer()
        with patch.object(guard.time,"monotonic_ns",side_effect=lambda:next(moments)), \
                patch.object(guard.socket,"socket",return_value=peer):
            guard.control_request(observer,"system.health",{},deadline=70*10**9)
        self.assertEqual(peer.timeouts[-1],1)
        self.assertLess(peer.timeouts[-1],peer.timeouts[-2])


class BusWireModels(unittest.TestCase):
    def reply(self,signature="b",body=struct.pack("<I",1),reply_serial=1,kind=2):
        header = bytearray()
        for code,typ,value in ((5,"u",reply_serial),(8,"g",signature),(7,"s","org.freedesktop.DBus")):
            header.extend(b"\0"*((-len(header))%8))
            header.extend(bytes((code,1))+typ.encode()+b"\0")
            if typ == "u":
                header.extend(struct.pack("<I",value))
            elif typ == "g":
                header.extend(bytes((len(value),))+value.encode()+b"\0")
            else:
                header.extend(guard.BusMetadata.string(value.encode()))
        packet = bytes((ord("l"),kind,0,1))+struct.pack("<III",len(body),13,len(header))+header
        return packet+b"\0"*((-len(packet))%8)+body

    def bus(self,reply):
        class Channel:
            def __init__(self,data):
                self.data,self.sent = data,[]
            def recv(self,n):
                value,self.data = self.data[:n],self.data[n:]
                return value
            def sendall(self,raw): self.sent.append(raw)
            def settimeout(self,value): self.timeout = value
        bus = guard.BusMetadata.__new__(guard.BusMetadata)
        bus.channel = Channel(reply)
        bus.serial,bus.deadline = 0,100*10**9
        return bus

    def test_actual_wire_decoder_and_encoder_require_matching_reply_and_no_autostart(self):
        with patch.object(guard.time,"monotonic_ns",return_value=1):
            bus = self.bus(self.reply())
            self.assertEqual(bus.call("NameHasOwner","org.freedesktop.secrets","b"),1)
            self.assertEqual(bus.channel.sent[0][:4],b"l\1\2\1")
            self.assertIn(b"NameHasOwner",bus.channel.sent[0])
            self.assertNotIn(b"StartServiceByName",bus.channel.sent[0])
            for raw in (self.reply(reply_serial=2),self.reply(signature="u"),
                self.reply(body=struct.pack("<I",2)),self.reply(kind=3),self.reply()[:-1]):
                failed = self.bus(raw)
                with self.assertRaises(ValueError):
                    failed.call("NameHasOwner","org.freedesktop.secrets","b")

    def test_proven_absence_does_not_activate_or_accept_missing_vault(self):
        bus = guard.BusMetadata.__new__(guard.BusMetadata)
        bus.peer = (100,os.getuid(),os.getgid())
        calls = []
        def call(member,argument,signature):
            calls.append((member,argument,signature))
            return 0
        bus.call = call
        with patch.object(resident,"start_ticks",return_value=10):
            with self.assertRaises(ValueError):
                bus.owners()
        self.assertEqual(calls,[("NameHasOwner","org.freedesktop.systemd1","b")])

    def test_owner_change_or_foreign_uid_is_refused_using_measured_metadata(self):
        for change in ("owner","uid"):
            bus = guard.BusMetadata.__new__(guard.BusMetadata)
            bus.peer = (100,os.getuid(),os.getgid())
            lookups = 0
            def call(member,argument,signature):
                nonlocal lookups
                if member == "NameHasOwner": return 1
                if member == "GetNameOwner":
                    lookups += 1
                    return ":1.2" if change != "owner" or lookups == 1 else ":1.3"
                if member == "GetConnectionUnixUser":
                    return os.getuid()+1 if change == "uid" else os.getuid()
                return 101
            bus.call = call
            with patch.object(resident,"start_ticks",return_value=10):
                with self.assertRaises(ValueError):
                    bus.owners()


    def test_each_bus_receive_chunk_refreshes_original_absolute_remaining_timeout(self):
        moments = iter([0,0,0,69*10**9,69*10**9])
        class Channel:
            def __init__(self): self.data,self.timeouts = b"abcdefgh",[]
            def settimeout(self,value): self.timeouts.append(value)
            def recv(self,n):
                count = min(4,n)
                raw,self.data = self.data[:count],self.data[count:]
                return raw
        bus = guard.BusMetadata.__new__(guard.BusMetadata)
        bus.deadline,bus.channel = 70*10**9,Channel()
        with patch.object(guard.time,"monotonic_ns",side_effect=lambda:next(moments)):
            self.assertEqual(bus.exact(8),b"abcdefgh")
        self.assertEqual(bus.channel.timeouts,[5,1])


class PostExitModels(unittest.TestCase):
    def test_collector_checks_exit_cleanup_then_observer_and_writes_exclusive_closed_receipt(self):
        with tempfile.TemporaryDirectory(dir=Path.home()) as temporary:
            run = Path(temporary)
            run.chmod(0o700)
            output = run/"resident-handoff"
            output.mkdir(mode=0o700)
            run_fd,output_fd = resident.open_directory(run,True),resident.open_directory(output,True)
            try:
                guard.create_file(output_fd,guard.HANDOFF,projection())
                calls = []
                observation = {"resident_daemon_same_process":True,"resident_installation_preserved":True,
                    "resident_service_active_after_controller":True,"resident_lifecycle_changed":False,
                    "resident_vault_owner_preserved":True}
                admission = guard.Admission.__new__(guard.Admission)
                admission.context,admission.action_epoch = context(),EPOCH
                admission.deadline_ns,admission.resources = 100*10**9,[]
                admission.fresh = SimpleNamespace(deadline=70)
                admission.selected = manifest()
                admission.run,admission.run_fd,admission.output,admission.output_fd = run,run_fd,output,output_fd
                admission.recheck = lambda:calls.append("metadata-recheck")
                admission.observer = SimpleNamespace(observe=lambda full=False:(calls.append(("observer",full)) or observation))
                after = snapshot()
                after["accounts"][0]["lifecycle"] = "draining"
                def control(observer,method,params):
                    calls.append(method)
                    return {"custody_available":True} if method == "system.health" else after
                with patch.object(guard.time,"time",return_value=1000),patch.object(guard,"control_request",side_effect=control), \
                     patch.object(resident,"collection_deadline") as collect:
                    for status,cleaned in ((1,True),(0,False)):
                        with self.assertRaises(ValueError):
                            admission.completed(status,cleaned,EPOCH,"1"*64,"b"*64)
                    self.assertEqual(calls,[])
                    collect.assert_not_called()
                    result = admission.completed(0,True,EPOCH,"1"*64,"b"*64)
                    collect.assert_called_once_with(admission.observer,[],100*10**9)
                self.assertEqual(result["basename"],guard.OUTPUT)
                self.assertIn(("observer",True),calls)
                final = json.loads((run/guard.OUTPUT).read_bytes())
                self.assertEqual(final["scope"],guard.SCOPE)
                self.assertTrue(final["requires_successful_guard_receipt"])
                self.assertEqual(stat.S_IMODE((run/guard.OUTPUT).stat().st_mode),0o600)
            finally:
                os.close(output_fd)
                os.close(run_fd)

if __name__ == "__main__":
    unittest.main()
